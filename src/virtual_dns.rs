use crate::error::Result;
use hashlink::{LruCache, linked_hash_map::RawEntryMut};
use std::{
    collections::HashMap,
    convert::TryInto,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tproxy_config::IpCidr;

const MAPPING_TIMEOUT: u64 = 60; // Mapping timeout in seconds

struct NameCacheEntry {
    name: String,
    expiry: Instant,
}

/// A virtual DNS server which allocates IP addresses to clients.
/// The IP addresses are in the range of private IP addresses.
/// The DNS server is implemented as a LRU cache.
pub struct VirtualDns {
    trailing_dot: bool,
    lru_cache: LruCache<IpAddr, NameCacheEntry>,
    name_to_ip: HashMap<String, IpAddr>,
    network_addr: IpAddr,
    broadcast_addr: IpAddr,
    next_addr: IpAddr,
}

/// Share fake-IP allocations across restarts of the same embedded TUN session.
///
/// Operating systems and applications may retain DNS answers after routes are
/// recreated. Keeping this state at the embedding handle level ensures those
/// cached addresses still resolve to the same domain after a node hot switch.
#[derive(Clone)]
pub struct VirtualDnsState(Arc<Mutex<VirtualDns>>);

impl VirtualDnsState {
    pub fn new(ip_pool: IpCidr) -> Self {
        Self(Arc::new(Mutex::new(VirtualDns::new(ip_pool))))
    }

    pub(crate) fn resolver(&self) -> Arc<Mutex<VirtualDns>> {
        Arc::clone(&self.0)
    }
}

impl Default for VirtualDnsState {
    fn default() -> Self {
        Self::new(crate::Args::default().virtual_dns_pool)
    }
}

impl fmt::Debug for VirtualDnsState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("VirtualDnsState").finish_non_exhaustive()
    }
}

impl VirtualDns {
    pub fn new(ip_pool: IpCidr) -> Self {
        Self {
            trailing_dot: false,
            next_addr: ip_pool.first_address(),
            name_to_ip: HashMap::default(),
            network_addr: ip_pool.first_address(),
            broadcast_addr: ip_pool.last_address(),
            lru_cache: LruCache::new_unbounded(),
        }
    }

    /// Returns the DNS response to send back to the client.
    pub fn generate_query(&mut self, data: &[u8]) -> Result<(Vec<u8>, String, IpAddr)> {
        use crate::dns;
        let message = dns::parse_data_to_dns_message(data, false)?;
        let qname = dns::extract_domain_from_dns_message(&message)?;
        let ip = self.find_or_allocate_ip(qname.clone())?;
        let message = dns::build_dns_response(message, &qname, ip, 5)?;
        Ok((message.to_vec()?, qname, ip))
    }

    fn increment_ip(addr: IpAddr) -> Result<IpAddr> {
        let mut ip_bytes = match addr as IpAddr {
            IpAddr::V4(ip) => Vec::<u8>::from(ip.octets()),
            IpAddr::V6(ip) => Vec::<u8>::from(ip.octets()),
        };

        // Traverse bytes from right to left and stop when we can add one.
        for j in 0..ip_bytes.len() {
            let i = ip_bytes.len() - 1 - j;
            if ip_bytes[i] != 255 {
                // We can add 1 without carry and are done.
                ip_bytes[i] += 1;
                break;
            } else {
                // Zero this byte and carry over to the next one.
                ip_bytes[i] = 0;
            }
        }
        let addr = if addr.is_ipv4() {
            let bytes: [u8; 4] = ip_bytes.as_slice().try_into()?;
            IpAddr::V4(Ipv4Addr::from(bytes))
        } else {
            let bytes: [u8; 16] = ip_bytes.as_slice().try_into()?;
            IpAddr::V6(Ipv6Addr::from(bytes))
        };
        Ok(addr)
    }

    // This is to be called whenever we receive or send a packet on the socket
    // which connects the tun interface to the client, so existing IP address to name
    // mappings to not expire as long as the connection is active.
    pub fn touch_ip(&mut self, addr: &IpAddr) {
        _ = self.lru_cache.get_mut(addr).map(|entry| {
            entry.expiry = Instant::now() + Duration::from_secs(MAPPING_TIMEOUT);
        });
    }

    pub fn resolve_ip(&mut self, addr: &IpAddr) -> Option<&String> {
        self.lru_cache.get(addr).map(|entry| &entry.name)
    }

    fn find_or_allocate_ip(&mut self, name: String) -> Result<IpAddr> {
        // This function is a search and creation function.
        // Thus, it is sufficient to canonicalize the name here.
        let insert_name = if name.ends_with('.') && !self.trailing_dot {
            String::from(name.trim_end_matches('.'))
        } else {
            name
        };

        let now = Instant::now();

        // Iterate through all entries of the LRU cache and remove those that have expired.
        loop {
            let (ip, entry) = match self.lru_cache.iter().next() {
                None => break,
                Some((ip, entry)) => (ip, entry),
            };

            // The entry has expired.
            if now > entry.expiry {
                let name = entry.name.clone();
                self.lru_cache.remove(&ip.clone());
                self.name_to_ip.remove(&name);
                continue; // There might be another expired entry after this one.
            }

            break; // The entry has not expired and all following entries are newer.
        }

        // Return the IP if it is stored inside our LRU cache.
        if let Some(ip) = self.name_to_ip.get(&insert_name) {
            let ip = *ip;
            self.touch_ip(&ip);
            return Ok(ip);
        }

        // Otherwise, store name and IP pair inside the LRU cache.
        let started_at = self.next_addr;

        loop {
            if let RawEntryMut::Vacant(vacant) = self.lru_cache.raw_entry_mut().from_key(&self.next_addr) {
                let expiry = Instant::now() + Duration::from_secs(MAPPING_TIMEOUT);
                let name0 = insert_name.clone();
                vacant.insert(self.next_addr, NameCacheEntry { name: insert_name, expiry });
                self.name_to_ip.insert(name0, self.next_addr);
                return Ok(self.next_addr);
            }
            self.next_addr = Self::increment_ip(self.next_addr)?;
            if self.next_addr == self.broadcast_addr {
                // Wrap around.
                self.next_addr = self.network_addr;
            }
            if self.next_addr == started_at {
                return Err("Virtual IP space for DNS exhausted".into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cloned_state_preserves_fake_ip_mapping() {
        let state = VirtualDnsState::default();
        let resolver = state.resolver();
        let address = resolver.lock().await.find_or_allocate_ip("cached.example".to_string()).unwrap();

        let restarted_resolver = state.clone().resolver();
        assert!(Arc::ptr_eq(&resolver, &restarted_resolver));
        assert_eq!(
            restarted_resolver.lock().await.resolve_ip(&address),
            Some(&"cached.example".to_string())
        );
    }
}
