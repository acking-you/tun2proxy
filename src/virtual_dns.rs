use crate::error::Result;
use hashbrown::HashMap;
use hashlink::{LruCache, linked_hash_map::RawEntryMut};
use std::{
    convert::TryInto,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::Mutex;
use tproxy_config::IpCidr;

mod persistence;

use persistence::{LoadResult, PersistentCache};

const CACHE_FILE_NAME: &str = "tun-virtual-dns-v1.jsonl";

/// A virtual DNS server which allocates IP addresses to clients.
/// The IP addresses are in the range of private IP addresses.
/// The DNS server is implemented as a LRU cache.
pub struct VirtualDns {
    trailing_dot: bool,
    lru_cache: LruCache<IpAddr, Arc<str>>,
    name_to_ip: HashMap<Arc<str>, IpAddr>,
    network_addr: IpAddr,
    broadcast_addr: IpAddr,
    next_addr: IpAddr,
    persistence: Option<PersistentCache>,
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

    /// Persist fake-IP mappings so application DNS caches survive a proxy
    /// process restart or an in-place application upgrade.
    pub async fn enable_persistence_in(&self, directory: impl Into<PathBuf>) -> Result<usize> {
        self.0.lock().await.enable_persistence(directory.into().join(CACHE_FILE_NAME))
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
            persistence: None,
        }
    }

    fn enable_persistence(&mut self, path: PathBuf) -> Result<usize> {
        let mut persistence = PersistentCache::new(path);
        match persistence.load(self.network_addr, self.broadcast_addr)? {
            LoadResult::Missing => {
                // Older releases always allocated from the first address. Start
                // the first persistent generation in the upper half so cached
                // addresses from a pre-persistence process are not silently
                // reassigned to an unrelated hostname during migration.
                if self.lru_cache.is_empty() {
                    self.next_addr = upper_half_start(self.network_addr, self.broadcast_addr);
                }
                self.persistence = Some(persistence);
                self.rewrite_persistence()?;
            }
            LoadResult::Incompatible => {
                log::warn!("Ignoring incompatible virtual DNS cache at {}", persistence.path().display());
                self.clear_mappings();
                self.next_addr = upper_half_start(self.network_addr, self.broadcast_addr);
                self.persistence = Some(persistence);
                self.rewrite_persistence()?;
            }
            LoadResult::Loaded {
                allocation_cursor,
                mappings,
                mut repair_needed,
            } => {
                self.clear_mappings();
                self.next_addr = allocation_cursor;
                for (ip, name) in mappings {
                    if !self.restore_mapping(ip, name) {
                        repair_needed = true;
                    }
                }
                self.persistence = Some(persistence);
                if repair_needed {
                    if let Some(cache) = &self.persistence {
                        log::warn!("Repaired incomplete virtual DNS cache at {}", cache.path().display());
                    }
                    self.rewrite_persistence()?;
                }
            }
        }
        Ok(self.lru_cache.len())
    }

    fn clear_mappings(&mut self) {
        self.lru_cache.clear();
        self.name_to_ip.clear();
        self.next_addr = self.network_addr;
    }

    fn canonical_name(&self, name: String) -> String {
        if name.ends_with('.') && !self.trailing_dot {
            String::from(name.trim_end_matches('.'))
        } else {
            name
        }
        .to_ascii_lowercase()
    }

    fn address_in_pool(&self, ip: IpAddr) -> bool {
        ip.is_ipv4() == self.network_addr.is_ipv4() && ip >= self.network_addr && ip <= self.broadcast_addr
    }

    fn restore_mapping(&mut self, ip: IpAddr, name: String) -> bool {
        let name: Arc<str> = self.canonical_name(name).into();
        if name.is_empty() || name.len() > 253 || !self.address_in_pool(ip) {
            return false;
        }
        if let Some(old_ip) = self.name_to_ip.remove(name.as_ref()) {
            self.lru_cache.remove(&old_ip);
        }
        if let Some(old_name) = self.lru_cache.remove(&ip) {
            self.name_to_ip.remove(old_name.as_ref());
        }
        self.lru_cache.insert(ip, Arc::clone(&name));
        self.name_to_ip.insert(name, ip);
        true
    }

    fn persist_mapping(&mut self, ip: IpAddr, name: &str) {
        let needs_rewrite = match &self.persistence {
            Some(persistence) => persistence.needs_rewrite(),
            None => return,
        };
        let result = match needs_rewrite {
            Ok(true) => self.rewrite_persistence(),
            Ok(false) => {
                let should_compact = match self.persistence.as_mut() {
                    Some(persistence) => persistence
                        .append_mapping(ip, name)
                        .map(|()| persistence.should_compact(self.lru_cache.len())),
                    None => return,
                };
                match should_compact {
                    Ok(true) => self.rewrite_persistence(),
                    Ok(false) => Ok(()),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            if let Some(persistence) = &mut self.persistence {
                persistence.mark_dirty();
                log::warn!("Failed to persist virtual DNS cache at {}: {error}", persistence.path().display());
            }
            // An append can fail after leaving a partial final record. Repair
            // immediately while the new mapping is still available in memory;
            // deferring until another DNS query could lose it on process exit.
            if let Err(repair_error) = self.rewrite_persistence()
                && let Some(persistence) = &self.persistence
            {
                log::warn!(
                    "Failed to repair virtual DNS cache at {}: {repair_error}",
                    persistence.path().display()
                );
            }
        }
    }

    fn retry_dirty_persistence(&mut self) {
        if self.persistence.as_ref().is_some_and(PersistentCache::is_dirty)
            && let Err(error) = self.rewrite_persistence()
        {
            if let Some(persistence) = &self.persistence {
                log::warn!("Failed to repair virtual DNS cache at {}: {error}", persistence.path().display());
            }
        }
    }

    fn rewrite_persistence(&mut self) -> Result<()> {
        let Some(persistence) = &mut self.persistence else {
            return Ok(());
        };
        persistence.rewrite(
            self.network_addr,
            self.broadcast_addr,
            self.next_addr,
            self.lru_cache.iter().map(|(ip, name)| (*ip, name.as_ref())),
        )
    }

    /// Returns the DNS response to send back to the client.
    pub fn generate_query(&mut self, data: &[u8]) -> Result<(Vec<u8>, String, Option<IpAddr>)> {
        use crate::dns;
        let message = dns::parse_data_to_dns_message(data, false)?;
        let query_type = dns::validate_dns_query(&message)?.query_type();
        let qname = dns::extract_domain_from_dns_message(&message)?;
        let ip = match (query_type, self.network_addr) {
            (hickory_proto::rr::RecordType::A, IpAddr::V4(_)) | (hickory_proto::rr::RecordType::AAAA, IpAddr::V6(_)) => {
                Some(self.find_or_allocate_ip(qname.clone())?)
            }
            _ => None,
        };
        let message = dns::build_dns_response(message, ip, 5)?;
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

    pub fn resolve_ip(&mut self, addr: &IpAddr) -> Option<Arc<str>> {
        self.lru_cache.get(addr).cloned()
    }

    pub fn contains_address(&self, addr: IpAddr) -> bool {
        self.address_in_pool(addr)
    }

    fn find_or_allocate_ip(&mut self, name: String) -> Result<IpAddr> {
        // This function is a search and creation function, so canonicalizing
        // once here keeps the forward and reverse maps consistent. DNS names
        // are ASCII case-insensitive and a terminal root dot is equivalent.
        let insert_name: Arc<str> = self.canonical_name(name).into();

        // Return the IP if it is stored inside our LRU cache.
        if let Some(ip) = self.name_to_ip.get(insert_name.as_ref()) {
            let ip = *ip;
            self.touch_ip(&ip);
            self.retry_dirty_persistence();
            return Ok(ip);
        }

        // Otherwise, store name and IP pair inside the LRU cache.
        let started_at = self.next_addr;

        loop {
            if let RawEntryMut::Vacant(vacant) = self.lru_cache.raw_entry_mut().from_key(&self.next_addr) {
                vacant.insert(self.next_addr, Arc::clone(&insert_name));
                self.name_to_ip.insert(Arc::clone(&insert_name), self.next_addr);
                self.persist_mapping(self.next_addr, insert_name.as_ref());
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
                let (ip, old_name) = self.lru_cache.remove_lru().ok_or("Virtual IP space for DNS exhausted")?;
                self.name_to_ip.remove(old_name.as_ref());
                self.lru_cache.insert(ip, Arc::clone(&insert_name));
                self.name_to_ip.insert(Arc::clone(&insert_name), ip);
                self.persist_mapping(ip, insert_name.as_ref());
                return Ok(ip);
            }
        }
    }
}

fn upper_half_start(network_addr: IpAddr, broadcast_addr: IpAddr) -> IpAddr {
    match (network_addr, broadcast_addr) {
        (IpAddr::V4(network), IpAddr::V4(broadcast)) => {
            let network = u32::from(network);
            let distance = u32::from(broadcast) - network;
            IpAddr::V4(Ipv4Addr::from(network + distance / 2 + distance % 2))
        }
        (IpAddr::V6(network), IpAddr::V6(broadcast)) => {
            let network = u128::from(network);
            let distance = u128::from(broadcast) - network;
            IpAddr::V6(Ipv6Addr::from(network + distance / 2 + distance % 2))
        }
        _ => network_addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RecordType},
    };
    use std::{
        fs::{self, File, OpenOptions},
        io::{BufRead, BufReader, Write},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_CACHE_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn non_address_queries_do_not_consume_fake_ips() {
        let mut dns = VirtualDns::new(crate::Args::default().virtual_dns_pool);
        let mut query = Message::new(7, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_ascii("example.com").unwrap(), RecordType::HTTPS));

        let (response, name, ip) = dns.generate_query(&query.to_vec().unwrap()).unwrap();
        let response = Message::from_vec(&response).unwrap();

        assert_eq!(name, "example.com.");
        assert_eq!(ip, None);
        assert!(response.answers().is_empty());
        assert!(response.recursion_available());
        assert!(dns.lru_cache.is_empty());
        assert!(dns.name_to_ip.is_empty());
    }

    struct TestCache {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TestCache {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "tun2proxy-virtual-dns-{}-{}",
                std::process::id(),
                NEXT_CACHE_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&directory).unwrap();
            let path = directory.join(CACHE_FILE_NAME);
            Self { directory, path }
        }
    }

    impl Drop for TestCache {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[tokio::test]
    async fn cloned_state_preserves_fake_ip_mapping() {
        let state = VirtualDnsState::default();
        let resolver = state.resolver();
        let address = resolver.lock().await.find_or_allocate_ip("cached.example".to_string()).unwrap();

        let restarted_resolver = state.clone().resolver();
        assert!(Arc::ptr_eq(&resolver, &restarted_resolver));
        assert_eq!(
            restarted_resolver.lock().await.resolve_ip(&address).as_deref(),
            Some("cached.example")
        );
    }

    #[tokio::test]
    async fn persistent_state_preserves_mapping_across_process_recreation() {
        let cache = TestCache::new();
        let original = VirtualDnsState::default();
        original.enable_persistence_in(&cache.directory).await.unwrap();
        let address = original
            .resolver()
            .lock()
            .await
            .find_or_allocate_ip("play.googleapis.com".to_string())
            .unwrap();
        assert_eq!(address, "198.19.0.0".parse::<IpAddr>().unwrap());

        let recreated = VirtualDnsState::default();
        assert_eq!(recreated.enable_persistence_in(&cache.directory).await.unwrap(), 1);
        let resolver = recreated.resolver();
        let mut resolver = resolver.lock().await;
        assert_eq!(resolver.find_or_allocate_ip("PLAY.GOOGLEAPIS.COM.".to_string()).unwrap(), address);
        assert_eq!(resolver.resolve_ip(&address).as_deref(), Some("play.googleapis.com"));
    }

    #[tokio::test]
    async fn persistent_state_repairs_a_truncated_journal_tail() {
        let cache = TestCache::new();
        let original = VirtualDnsState::default();
        original.enable_persistence_in(&cache.directory).await.unwrap();
        let address = original
            .resolver()
            .lock()
            .await
            .find_or_allocate_ip("cached.example".to_string())
            .unwrap();
        OpenOptions::new().append(true).open(&cache.path).unwrap().write_all(b"{").unwrap();

        let recreated = VirtualDnsState::default();
        assert_eq!(recreated.enable_persistence_in(&cache.directory).await.unwrap(), 1);
        assert_eq!(
            recreated.resolver().lock().await.resolve_ip(&address).as_deref(),
            Some("cached.example")
        );
        for line in BufReader::new(File::open(&cache.path).unwrap()).lines() {
            serde_json::from_str::<serde_json::Value>(&line.unwrap()).unwrap();
        }
    }

    #[tokio::test]
    async fn persistent_state_rebuilds_a_deleted_journal_from_live_mappings() {
        let cache = TestCache::new();
        let original = VirtualDnsState::default();
        original.enable_persistence_in(&cache.directory).await.unwrap();
        let resolver = original.resolver();
        resolver.lock().await.find_or_allocate_ip("first.example".to_string()).unwrap();
        fs::remove_file(&cache.path).unwrap();
        resolver.lock().await.find_or_allocate_ip("second.example".to_string()).unwrap();

        let recreated = VirtualDnsState::default();
        assert_eq!(recreated.enable_persistence_in(&cache.directory).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn persistent_state_rejects_a_different_fake_ip_pool() {
        let cache = TestCache::new();
        let original = VirtualDnsState::default();
        original.enable_persistence_in(&cache.directory).await.unwrap();
        original
            .resolver()
            .lock()
            .await
            .find_or_allocate_ip("cached.example".to_string())
            .unwrap();

        let replacement = VirtualDnsState::new("198.19.0.0/31".parse().unwrap());
        assert_eq!(replacement.enable_persistence_in(&cache.directory).await.unwrap(), 0);
        assert_eq!(replacement.resolver().lock().await.lru_cache.len(), 0);
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
        assert_eq!(dns.resolve_ip(&first).as_deref(), Some("example.com"));
        assert_eq!(dns.resolve_ip(&other).as_deref(), Some("www.example.com"));
    }

    #[test]
    fn single_address_pools_recycle_only_address_without_leaving_the_cidr() {
        for cidr in ["198.18.0.1/32", "2001:db8::1/128"] {
            let mut dns = VirtualDns::new(cidr.parse::<IpCidr>().unwrap());
            let first = dns.find_or_allocate_ip("first.example".to_string()).unwrap();
            let second = dns.find_or_allocate_ip("second.example".to_string()).unwrap();

            assert_eq!(first, second);
            assert_eq!(dns.resolve_ip(&second).as_deref(), Some("second.example"));
        }
    }

    #[test]
    fn full_pool_recycles_the_least_recently_used_mapping() {
        let mut dns = VirtualDns::new("198.18.0.0/31".parse::<IpCidr>().unwrap());
        let first = dns.find_or_allocate_ip("first.example".to_string()).unwrap();
        let second = dns.find_or_allocate_ip("second.example".to_string()).unwrap();
        assert_eq!(dns.resolve_ip(&first).as_deref(), Some("first.example"));

        let third = dns.find_or_allocate_ip("third.example".to_string()).unwrap();

        assert_eq!(first, "198.18.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(second, "198.18.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(third, second);
        assert_eq!(dns.resolve_ip(&first).as_deref(), Some("first.example"));
        assert_eq!(dns.resolve_ip(&third).as_deref(), Some("third.example"));
        assert!(!dns.name_to_ip.contains_key("second.example"));
    }
}
