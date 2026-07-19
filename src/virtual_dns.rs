use crate::error::Result;
use hashlink::{LruCache, linked_hash_map::RawEntryMut};
use std::{
    collections::HashMap,
    convert::TryInto,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::sync::Mutex;
use tproxy_config::IpCidr;

struct NameCacheEntry {
    name: String,
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

    // Mark the mapping as recently used. Mappings intentionally have no time-based
    // expiry: applications can retain DNS answers beyond their advertised TTL, so
    // recycling a fake IP can break or misroute a later connection from that cache.
    pub fn touch_ip(&mut self, addr: &IpAddr) {
        _ = self.lru_cache.get_mut(addr);
    }

    pub fn resolve_ip(&mut self, addr: &IpAddr) -> Option<&String> {
        self.lru_cache.get(addr).map(|entry| &entry.name)
    }

    fn find_or_allocate_ip(&mut self, name: String) -> Result<IpAddr> {
        // This function is a search and creation function, so canonicalizing
        // once here keeps the forward and reverse maps consistent. DNS names
        // are ASCII case-insensitive and a terminal root dot is equivalent.
        let insert_name = if name.ends_with('.') && !self.trailing_dot {
            String::from(name.trim_end_matches('.'))
        } else {
            name
        }
        .to_ascii_lowercase();

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
                let name0 = insert_name.clone();
                vacant.insert(self.next_addr, NameCacheEntry { name: insert_name });
                self.name_to_ip.insert(name0, self.next_addr);
                return Ok(self.next_addr);
            }
            // Wrap before incrementing the final address. Comparing the
            // current address is essential for a one-address /32 or /128
            // pool: incrementing first would escape the configured CIDR and
            // could scan the entire address space before exhaustion is seen.
            self.next_addr = if self.next_addr == self.broadcast_addr {
                self.network_addr
            } else {
                Self::increment_ip(self.next_addr)?
            };
            if self.next_addr == started_at {
                // Every address is allocated. Recycle only now, and choose the
                // least recently used mapping. DNS lookups and intercepted
                // sessions both touch their mapping before a new allocation can
                // acquire the resolver lock, so active cached addresses remain
                // at the MRU end of the cache.
                let (ip, entry) = self.lru_cache.remove_lru().ok_or("Virtual IP space for DNS exhausted")?;
                self.name_to_ip.remove(&entry.name);
                self.lru_cache.insert(ip, NameCacheEntry { name: insert_name.clone() });
                self.name_to_ip.insert(insert_name, ip);
                return Ok(ip);
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

    #[test]
    fn increment_ip_carries_for_ipv4_and_ipv6() {
        assert_eq!(
            VirtualDns::increment_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 255))).unwrap(),
            IpAddr::V4(Ipv4Addr::new(198, 18, 1, 0))
        );
        assert_eq!(
            VirtualDns::increment_ip("2001:db8::ffff".parse().unwrap()).unwrap(),
            "2001:db8::1:0".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn canonical_name_reuses_mapping_and_reverse_lookup() {
        let mut dns = VirtualDns::new("198.18.0.0/15".parse::<IpCidr>().unwrap());

        let first = dns.find_or_allocate_ip("example.com.".to_string()).unwrap();
        let same = dns.find_or_allocate_ip("EXAMPLE.COM".to_string()).unwrap();
        let other = dns.find_or_allocate_ip("www.example.com".to_string()).unwrap();

        assert_eq!(first, same);
        assert_ne!(first, other);
        assert_eq!(dns.resolve_ip(&first).map(String::as_str), Some("example.com"));
        assert_eq!(dns.resolve_ip(&other).map(String::as_str), Some("www.example.com"));
    }

    #[test]
    fn single_address_pools_recycle_only_address_without_leaving_the_cidr() {
        for cidr in ["198.18.0.1/32", "2001:db8::1/128"] {
            let mut dns = VirtualDns::new(cidr.parse::<IpCidr>().unwrap());
            let first = dns.find_or_allocate_ip("first.example".to_string()).unwrap();
            let second = dns.find_or_allocate_ip("second.example".to_string()).unwrap();

            assert_eq!(first, second);
            assert_eq!(dns.resolve_ip(&second).map(String::as_str), Some("second.example"));
        }
    }

    #[test]
    fn full_pool_recycles_the_least_recently_used_mapping() {
        let mut dns = VirtualDns::new("198.18.0.0/31".parse::<IpCidr>().unwrap());
        let first = dns.find_or_allocate_ip("first.example".to_string()).unwrap();
        let second = dns.find_or_allocate_ip("second.example".to_string()).unwrap();
        assert_eq!(dns.resolve_ip(&first).map(String::as_str), Some("first.example"));

        let third = dns.find_or_allocate_ip("third.example".to_string()).unwrap();

        assert_eq!(first, "198.18.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(second, "198.18.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(third, second);
        assert_eq!(dns.resolve_ip(&first).map(String::as_str), Some("first.example"));
        assert_eq!(dns.resolve_ip(&third).map(String::as_str), Some("third.example"));
        assert!(!dns.name_to_ip.contains_key("second.example"));
    }
}
