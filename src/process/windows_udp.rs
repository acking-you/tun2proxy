//! Windows exposes a PID and bind timestamp, not a unique socket identifier.
//! Fast rebinds can share a timestamp. Treat this as a best-effort ownership
//! fingerprint; neither timestamp uniqueness nor chronological order is promised.

use super::{IpProtocol, SocketEntry};
use std::{
    io, mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
    NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDP6ROW_OWNER_MODULE, MIB_UDP6TABLE_OWNER_MODULE, MIB_UDPROW_OWNER_MODULE, MIB_UDPTABLE_OWNER_MODULE,
        UDP_TABLE_OWNER_MODULE,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SocketOwner {
    pub(crate) pid: u32,
    pub(crate) bound_at: i64,
}

fn table(family: u32) -> io::Result<(Vec<u64>, usize)> {
    const MAX_BYTES: usize = 32 * 1024 * 1024;
    // u64 storage supplies the alignment required by the OWNER_MODULE rows.
    let mut buffer = Vec::<u64>::new();
    let mut size = 0;
    for _ in 0..4 {
        let pointer = if buffer.is_empty() {
            std::ptr::null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        };
        // SAFETY: size is the allocated byte capacity (or zero for the probe).
        // The API returns the required size when the table grows concurrently.
        let result = unsafe { GetExtendedUdpTable(pointer, &mut size, 0, family, UDP_TABLE_OWNER_MODULE, 0) };
        if result == NO_ERROR {
            return Ok((buffer, size as usize));
        }
        if result != ERROR_INSUFFICIENT_BUFFER {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        if size as usize > MAX_BYTES {
            return Err(io::Error::other("UDP owner table exceeds size limit"));
        }
        // Leave room for concurrent binds rather than chasing exact table sizes.
        let capacity = (size as usize + (size as usize / 2).max(4096)).min(MAX_BYTES);
        buffer.resize(capacity.div_ceil(mem::size_of::<u64>()), 0);
        size = (buffer.len() * mem::size_of::<u64>()) as u32;
    }
    Err(io::Error::other("UDP owner table kept changing"))
}

// SAFETY: T must be the Windows POD row matching the queried family, and
// offset must be offset_of!(the corresponding table type, table).
unsafe fn rows<T: Copy>(buffer: &[u64], size: usize, offset: usize) -> io::Result<Vec<T>> {
    if size < offset || size > mem::size_of_val(buffer) || offset < mem::size_of::<u32>() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // SAFETY: the bounds above include the DWORD count; u64 storage is aligned.
    let count = unsafe { buffer.as_ptr().cast::<u32>().read() } as usize;
    if count > (size - offset) / mem::size_of::<T>() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // SAFETY: validated count/offset fit the initialized buffer. read_unaligned
    // handles the SDK's padding without depending on Vec's element layout.
    Ok((0..count)
        .map(|index| unsafe {
            buffer
                .as_ptr()
                .cast::<u8>()
                .add(offset + index * mem::size_of::<T>())
                .cast::<T>()
                .read_unaligned()
        })
        .collect())
}

pub(super) fn snapshot() -> io::Result<Vec<SocketEntry>> {
    let mut entries = Vec::new();
    let (buffer, size) = table(u32::from(AF_INET))?;
    // SAFETY: IPv4 OWNER_MODULE table and its SDK row/offset are paired.
    let ipv4 = unsafe { rows::<MIB_UDPROW_OWNER_MODULE>(&buffer, size, mem::offset_of!(MIB_UDPTABLE_OWNER_MODULE, table))? };
    for row in ipv4 {
        entries.push(entry(
            SocketAddr::from((Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()), u16::from_be(row.dwLocalPort as u16))),
            row.dwOwningPid,
            row.liCreateTimestamp,
        ));
    }
    let (buffer, size) = table(u32::from(AF_INET6))?;
    // SAFETY: IPv6 OWNER_MODULE table and its SDK row/offset are paired.
    let ipv6 = unsafe { rows::<MIB_UDP6ROW_OWNER_MODULE>(&buffer, size, mem::offset_of!(MIB_UDP6TABLE_OWNER_MODULE, table))? };
    for row in ipv6 {
        entries.push(entry(
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(row.ucLocalAddr),
                u16::from_be(row.dwLocalPort as u16),
                0,
                row.dwLocalScopeId,
            )),
            row.dwOwningPid,
            row.liCreateTimestamp,
        ));
    }
    Ok(entries)
}

fn entry(local: SocketAddr, pid: u32, bound_at: i64) -> SocketEntry {
    SocketEntry {
        protocol: IpProtocol::Udp,
        local,
        remote: None,
        pids: vec![pid],
        udp_owner: (pid != 0 && bound_at > 0).then_some(SocketOwner { pid, bound_at }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::udp_owner;

    #[test]
    fn udp_snapshot_reports_live_bindings_and_removal() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let socket = std::net::UdpSocket::bind(address).unwrap();
            let source = socket.local_addr().unwrap();
            let owner = udp_owner(&snapshot().unwrap(), source).unwrap();
            assert_eq!(owner.pid, std::process::id());
            assert_eq!(udp_owner(&snapshot().unwrap(), source), Some(owner));
            drop(socket);
            assert_eq!(udp_owner(&snapshot().unwrap(), source), None);
            let _replacement = std::net::UdpSocket::bind(source).unwrap();
            // Windows can reuse the timestamp within a clock tick. The table
            // still reports the replacement, but cannot prove a new generation.
            let replacement = udp_owner(&snapshot().unwrap(), source).unwrap();
            assert_eq!(replacement.pid, std::process::id());
            assert_eq!(udp_owner(&snapshot().unwrap(), source), Some(replacement));
        }
    }

    #[test]
    fn ambiguous_and_other_family_owners_are_not_shared() {
        let source = "10.0.0.2:12345".parse().unwrap();
        let first = entry("0.0.0.0:12345".parse().unwrap(), 7, 10);
        let second = entry("0.0.0.0:12345".parse().unwrap(), 7, 11);
        let ipv6 = entry("[::]:12345".parse().unwrap(), 8, 12);
        assert_eq!(udp_owner(std::slice::from_ref(&ipv6), source), None);
        assert_eq!(udp_owner(std::slice::from_ref(&first), source), first.udp_owner);
        assert_eq!(udp_owner(&[first.clone(), ipv6], source), None);
        let concrete = entry(source, 9, 13);
        assert_eq!(udp_owner(&[first.clone(), concrete], source), None);
        assert_eq!(udp_owner(&[first, second], source), None);
        let v4 = entry("0.0.0.0:12345".parse().unwrap(), 7, 10);
        let v6 = entry("[::]:12345".parse().unwrap(), 8, 12);
        assert_eq!(udp_owner(&[v4, v6.clone()], "[fd00::2]:12345".parse().unwrap()), v6.udp_owner);
    }
}
