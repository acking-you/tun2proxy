//! Bounded ICMP Echo forwarding through proxy-everything's local SOCKS5 extension.
//! No reply is injected until the remote endpoint reports an actual echo reply.

use crate::{ArgProxy, Args};
use ipstack::IpStackUnknownTransport;
use std::{
    collections::HashMap,
    io::{self, IoSlice},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
    task::JoinSet,
};

/// Private, loopback-only SOCKS5 command. DST.PORT is 4 or 6 for the IP family.
pub const SOCKS5_ECHO: u8 = 0xe0;
/// Maximum raw Echo packet carried by either side of the local extension.
pub const MAX_ECHO_PACKET: usize = u16::MAX as usize;
const MAX_FLOWS: usize = 64;
const QUEUE_DEPTH: usize = 4;
const ECHO_TIMEOUT: Duration = Duration::from_secs(4);
const IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// Read one local Echo packet. Cancellation requires dropping the connection.
pub async fn read_packet<'a, R: AsyncRead + Unpin>(reader: &mut R, buffer: &'a mut Vec<u8>) -> io::Result<&'a [u8]> {
    let length = reader.read_u16().await? as usize;
    if length < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid ICMP Echo packet length"));
    }
    buffer.resize(length, 0);
    reader.read_exact(buffer).await?;
    Ok(buffer)
}

/// Write the prefix and borrowed packet together, without a packet-sized copy.
pub async fn write_packet<W: AsyncWrite + Unpin>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    if !(8..=MAX_ECHO_PACKET).contains(&packet.len()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid ICMP Echo packet length"));
    }
    let prefix = (packet.len() as u16).to_be_bytes();
    let mut slices = [IoSlice::new(&prefix), IoSlice::new(packet)];
    let mut pending = &mut slices[..];
    while !pending.is_empty() {
        let n = writer.write_vectored(pending).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        IoSlice::advance_slices(&mut pending, n);
    }
    writer.flush().await
}

pub(crate) fn validate_options(args: &Args) -> io::Result<()> {
    if args.icmp_echo
        && (args.proxy.proxy_type != crate::args::ProxyType::Socks5
            || !args.proxy.addr.ip().is_loopback()
            || args.proxy.credentials.is_some())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ICMP Echo requires proxy-everything's loopback SOCKS5 endpoint without authentication",
        ));
    }
    Ok(())
}

#[derive(Hash, PartialEq, Eq)]
struct FlowKey {
    source: IpAddr,
    destination: IpAddr,
    identifier: [u8; 2],
}

struct EchoRequest {
    packet: IpStackUnknownTransport,
    deadline: tokio::time::Instant,
}

pub(crate) struct EchoFlows {
    flows: HashMap<FlowKey, mpsc::Sender<EchoRequest>>,
    proxy: ArgProxy,
    mtu: usize,
}

impl EchoFlows {
    pub(crate) fn new(args: &Args, mtu: u16) -> io::Result<Option<Self>> {
        validate_options(args)?;
        Ok(args.icmp_echo.then(|| Self {
            flows: HashMap::new(),
            proxy: args.proxy.clone(),
            mtu: mtu as usize,
        }))
    }

    pub(crate) fn is_echo(&self, packet: &IpStackUnknownTransport) -> bool {
        matches!(
            (packet.ip_protocol().0, packet.payload().get(..2)),
            (1, Some([8, 0])) | (58, Some([128, 0]))
        )
    }

    pub(crate) fn dispatch(&mut self, packet: IpStackUnknownTransport, domain: Option<Arc<str>>, tasks: &mut JoinSet<()>) {
        let data = packet.payload();
        let header_len = if packet.src_addr().is_ipv4() { 20 } else { 40 };
        if data.len() < 8
            || data.len() > self.mtu.saturating_sub(header_len)
            || packet_checksum(data, packet.src_addr(), packet.dst_addr()) != 0
        {
            log::debug!("Discarding malformed or oversized ICMP Echo request");
            return;
        }
        self.flows.retain(|_, sender| !sender.is_closed());
        let key = FlowKey {
            source: packet.src_addr(),
            destination: packet.dst_addr(),
            identifier: [data[4], data[5]],
        };
        if self.flows.len() >= MAX_FLOWS && !self.flows.contains_key(&key) {
            log::debug!("ICMP Echo flow limit reached; dropping request");
            return;
        }
        let sender = match self.flows.entry(key) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                // JoinSet also owns the worker; no detached flow can outlive TUN.
                let (sender, receiver) = mpsc::channel(QUEUE_DEPTH);
                let proxy = self.proxy.clone();
                let target = domain.unwrap_or_else(|| Arc::from(packet.dst_addr().to_string()));
                let ipv6 = packet.dst_addr().is_ipv6();
                tasks.spawn(async move {
                    if let Err(error) = run_flow(proxy, target, ipv6, receiver).await {
                        log::debug!("ICMP Echo tunnel ended: {error}");
                    }
                });
                entry.insert(sender)
            }
        };
        // A full queue is packet loss, not permission to stall TCP/UDP forwarding.
        let _ = sender.try_send(EchoRequest {
            packet,
            deadline: tokio::time::Instant::now() + ECHO_TIMEOUT,
        });
    }
}

async fn connect(proxy: &ArgProxy, target: &str, ipv6: bool) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy.addr).await?;
    stream.set_nodelay(true)?;
    let mut request = vec![5, 1, 0, 5, SOCKS5_ECHO, 0];
    match target.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let length =
                u8::try_from(target.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Echo hostname is too long"))?;
            request.extend_from_slice(&[3, length]);
            request.extend_from_slice(target.as_bytes());
        }
    }
    request.extend_from_slice(&(if ipv6 { 6u16 } else { 4u16 }).to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0; 12];
    stream.read_exact(&mut reply).await?;
    if reply[..6] != [5, 0, 5, 0, 0, 1] {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local proxy rejected ICMP Echo; upgrade the proxy and use its native upstream",
        ));
    }
    Ok(stream)
}

async fn run_flow(proxy: ArgProxy, target: Arc<str>, ipv6: bool, mut requests: mpsc::Receiver<EchoRequest>) -> io::Result<()> {
    let mut stream = tokio::time::timeout(ECHO_TIMEOUT, connect(&proxy, &target, ipv6)).await??;
    let mut response = Vec::new();
    while let Ok(Some(EchoRequest { packet, deadline })) = tokio::time::timeout(IDLE_TIMEOUT, requests.recv()).await {
        if deadline <= tokio::time::Instant::now() {
            continue;
        }
        tokio::time::timeout_at(deadline, async {
            write_packet(&mut stream, packet.payload()).await?;
            read_packet(&mut stream, &mut response).await?;
            let request = packet.payload();
            if response.len() != request.len()
                || response[0] != if ipv6 { 129 } else { 0 }
                || response[1] != 0
                || response[4..] != request[4..]
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "remote ICMP reply does not match the request",
                ));
            }
            response[2..4].fill(0);
            let checksum = packet_checksum(&response, packet.dst_addr(), packet.src_addr());
            response[2..4].copy_from_slice(&checksum.to_be_bytes());
            packet.send(std::mem::take(&mut response))
        })
        .await??;
    }
    Ok(())
}

fn packet_checksum(packet: &[u8], source: IpAddr, destination: IpAddr) -> u16 {
    let mut checksum = internet_checksum::Checksum::new();
    if let (IpAddr::V6(source), IpAddr::V6(destination)) = (source, destination) {
        checksum.add_bytes(&source.octets());
        checksum.add_bytes(&destination.octets());
        checksum.add_bytes(&(packet.len() as u32).to_be_bytes());
        checksum.add_bytes(&[0, 0, 0, 58]);
    }
    checksum.add_bytes(packet);
    u16::from_be_bytes(checksum.checksum())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn packet_framing_survives_fragmented_io_and_rejects_short_packets() {
        let (mut writer, mut reader) = tokio::io::duplex(3);
        let sender = tokio::spawn(async move {
            write_packet(&mut writer, &[8, 0, 0, 0, 1, 2, 3, 4, 5]).await.unwrap();
            write_packet(&mut writer, &[128, 0, 0, 0, 4, 3, 2, 1]).await.unwrap();
            writer.write_u16(7).await.unwrap();
        });
        let mut buffer = Vec::new();
        assert_eq!(read_packet(&mut reader, &mut buffer).await.unwrap(), &[8, 0, 0, 0, 1, 2, 3, 4, 5]);
        assert_eq!(read_packet(&mut reader, &mut buffer).await.unwrap(), &[128, 0, 0, 0, 4, 3, 2, 1]);
        assert_eq!(
            read_packet(&mut reader, &mut buffer).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        sender.await.unwrap();
    }

    #[test]
    fn echo_is_opt_in_and_rejects_remote_or_non_socks_endpoints() {
        let mut args = Args::default();
        assert!(!args.icmp_echo);
        args.icmp_echo = true;
        args.proxy = ArgProxy::try_from("socks5://127.0.0.1:1080").unwrap();
        validate_options(&args).unwrap();
        for proxy in [
            "http://127.0.0.1:1080",
            "socks5://192.0.2.1:1080",
            "socks5://user:pass@127.0.0.1:1080",
        ] {
            args.proxy = ArgProxy::try_from(proxy).unwrap();
            assert!(validate_options(&args).is_err());
        }
    }
}
