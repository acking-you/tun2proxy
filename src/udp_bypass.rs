//! Windows process bypass keeps a physical UDP socket per application socket,
//! not per destination. Flow-specific writers still restore the original (even
//! Fake-IP) peer, and only explicitly contacted peers can deliver replies.

use crate::{
    direct::{self, BindInterface},
    process::{SessionPolicy, SocketOwner, UdpOwners},
};
use ipstack::IpStackUdpStream;
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    os::windows::io::AsRawSocket,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::JoinSet,
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use windows_sys::Win32::Networking::WinSock::{SIO_UDP_CONNRESET, SIO_UDP_NETRESET, SOCKET_ERROR, WSAGetLastError, WSAIoctl};

const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const OWNER_FAILURE_GRACE: Duration = Duration::from_secs(6);
const QUEUED_BYTES: usize = 8 * 1024 * 1024;
const PEER_QUEUE: usize = 16;

fn bind_shared_udp(ipv6: bool, interface: &BindInterface) -> io::Result<UdpSocket> {
    let socket = direct::bind_udp_unconnected(ipv6, interface)?;
    // ICMP errors cannot be attributed to one peer on a shared socket. Suppress
    // both port-unreachable and TTL-expired notifications, per Winsock IOCTLs.
    for control in [SIO_UDP_CONNRESET, SIO_UDP_NETRESET] {
        let disabled = 0u32;
        let mut returned = 0;
        // SAFETY: the socket is live; both buffers are correctly sized and the
        // call is synchronous, with no overlapped operation or retained pointers.
        let result = unsafe {
            WSAIoctl(
                socket.as_raw_socket() as _,
                control,
                (&disabled as *const u32).cast(),
                size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
                None,
            )
        };
        if result == SOCKET_ERROR {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
    }
    Ok(socket)
}

struct Datagram {
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

struct State {
    routes: HashMap<SocketAddr, mpsc::Sender<Datagram>>,
    last_activity: Instant,
}

struct Endpoint {
    owner: SocketOwner,
    interface: Arc<BindInterface>,
    socket: Arc<UdpSocket>,
    state: Mutex<State>,
    closed: CancellationToken,
}

impl Endpoint {
    fn uses_interface(&self, source: SocketAddr, interface: &BindInterface) -> bool {
        // A unicast binding uses only the interface index of its address family.
        if source.is_ipv6() {
            self.interface.ipv6_index == interface.ipv6_index
        } else {
            self.interface.ipv4_index == interface.ipv4_index
        }
    }

    fn close(&self) {
        let mut state = self.state.lock().unwrap();
        self.closed.cancel();
        state.routes.clear();
    }

    fn expired(&self) -> bool {
        let state = self.state.lock().unwrap();
        self.closed.is_cancelled() || (state.routes.is_empty() && state.last_activity.elapsed() >= IDLE_TIMEOUT)
    }

    async fn receive(self: Arc<Self>, budget: Arc<Semaphore>, policy_changed: impl Future<Output = ()>) {
        let _cancel_on_exit = self.closed.clone().drop_guard();
        tokio::pin!(policy_changed);
        let mut buffer = vec![0; u16::MAX as usize];
        loop {
            let result = tokio::select! {
                biased;
                _ = self.closed.cancelled() => break,
                _ = &mut policy_changed => break,
                result = self.socket.recv_from(&mut buffer) => result,
            };
            let (length, peer) = match result {
                Ok(packet) => packet,
                // Windows reports an earlier ICMP error on a later UDP receive.
                // One unreachable peer must not terminate other peers' traffic.
                Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused) => continue,
                Err(error) => {
                    log::debug!("UDP bypass receive failed: {error}");
                    break;
                }
            };
            let mut state = self.state.lock().unwrap();
            let Some(route) = state.routes.get(&peer) else { continue };
            let Ok(permit) = budget.clone().try_acquire_many_owned(length.max(1) as u32) else {
                continue;
            };
            if route
                .try_send(Datagram {
                    bytes: buffer[..length].to_vec(),
                    _permit: permit,
                })
                .is_ok()
            {
                state.last_activity = Instant::now();
            }
        }
        self.close();
    }
}

struct PoolState {
    endpoints: HashMap<SocketAddr, Arc<Endpoint>>,
    tasks: JoinSet<()>,
    owner_failure_since: Option<Instant>,
}

impl PoolState {
    fn reap(&mut self) {
        while let Some(result) = self.tasks.try_join_next() {
            if let Err(error) = result
                && !error.is_cancelled()
            {
                log::warn!("UDP bypass receiver task failed: {error}");
            }
        }
    }
}

pub(crate) struct Pool {
    state: Mutex<PoolState>,
    budget: Arc<Semaphore>,
    owner_lookup: Arc<Semaphore>,
    egress: Option<watch::Receiver<Arc<BindInterface>>>,
    limit: usize,
}

impl Pool {
    pub(crate) fn new(limit: usize, egress: Option<watch::Receiver<Arc<BindInterface>>>) -> Self {
        Self {
            state: Mutex::new(PoolState {
                endpoints: HashMap::new(),
                tasks: JoinSet::new(),
                owner_failure_since: None,
            }),
            budget: Arc::new(Semaphore::new(QUEUED_BYTES)),
            owner_lookup: Arc::new(Semaphore::new(1)),
            egress,
            limit: limit.min(1024),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.state.lock().unwrap().endpoints.is_empty()
    }

    async fn snapshot(&self) -> (Arc<OwnedSemaphorePermit>, io::Result<UdpOwners>) {
        // Serialize the OS read AND its application across opens and maintenance.
        // Retain the permit in a cancelled caller's blocking job too.
        let permit = Arc::new(
            self.owner_lookup
                .clone()
                .acquire_owned()
                .await
                .expect("owner lookup is never closed"),
        );
        let worker_permit = permit.clone();
        let owners = tokio::task::spawn_blocking(move || {
            let _permit = worker_permit;
            UdpOwners::snapshot()
        })
        .await
        .map_err(io::Error::other)
        .and_then(std::convert::identity);
        (permit, owners)
    }

    pub(crate) fn interface(&self) -> Option<Arc<BindInterface>> {
        self.egress.as_ref().map(|egress| Arc::clone(&egress.borrow()))
    }

    pub(crate) async fn open(&self, source: SocketAddr, peer: SocketAddr, policy: SessionPolicy) -> io::Result<Option<Flow>> {
        let (_permit, owners) = self.snapshot().await;
        // Read the current interface after DNS/OS lookup, and keep the watch
        // borrow through registration so a delayed flow cannot restore an old bind.
        let interface = self.egress.as_ref().map(watch::Receiver::borrow);
        self.maintain_with(owners.as_ref().ok(), interface.as_deref().map(Arc::as_ref));
        let owners = owners?;
        let owner = policy.udp_owner.ok_or(io::ErrorKind::PermissionDenied)?;
        if owners.get(source) != Some(owner) || !policy.bypass() || !policy.is_current() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "UDP bypass owner or policy changed during setup",
            ));
        }
        let interface = interface
            .as_deref()
            .cloned()
            .ok_or_else(|| io::Error::other("UDP bypass physical interface unavailable"))?;
        self.open_with(source, peer, owner, interface, policy.wait_for_routing_change(), bind_shared_udp)
    }

    fn open_with(
        &self,
        source: SocketAddr,
        peer: SocketAddr,
        owner: SocketOwner,
        interface: Arc<BindInterface>,
        policy_changed: impl Future<Output = ()> + Send + 'static,
        bind: impl FnOnce(bool, &BindInterface) -> io::Result<UdpSocket>,
    ) -> io::Result<Option<Flow>> {
        if source.is_ipv4() != peer.is_ipv4() || peer.ip().is_multicast() || peer.ip().is_unspecified() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut pool = self.state.lock().unwrap();
        pool.reap();
        pool.endpoints.retain(|_, endpoint| {
            if endpoint.expired() {
                endpoint.close();
                false
            } else {
                true
            }
        });
        if let Some(endpoint) = pool.endpoints.get(&source)
            && (endpoint.owner != owner || !endpoint.uses_interface(source, &interface))
        {
            endpoint.close();
            pool.endpoints.remove(&source);
        }
        if !pool.endpoints.contains_key(&source) {
            if pool.endpoints.len() >= self.limit {
                // Idle mappings can be reclaimed under pressure; active flows
                // must never silently move to a different physical source port.
                let oldest = pool
                    .endpoints
                    .iter()
                    .filter_map(|(source, endpoint)| {
                        let state = endpoint.state.lock().unwrap();
                        state.routes.is_empty().then_some((*source, state.last_activity))
                    })
                    .min_by_key(|(_, activity)| *activity);
                if let Some((source, _)) = oldest {
                    pool.endpoints.remove(&source).unwrap().close();
                } else {
                    return Ok(None);
                }
            }
            let socket = Arc::new(bind(source.is_ipv6(), &interface)?);
            log::info!(
                "Opening UDP bypass endpoint: source={source}, local={:?}, pid={}, interface={interface}",
                socket.local_addr().ok(),
                owner.pid
            );
            let endpoint = Arc::new(Endpoint {
                owner,
                interface,
                socket,
                state: Mutex::new(State {
                    routes: HashMap::new(),
                    last_activity: Instant::now(),
                }),
                closed: CancellationToken::new(),
            });
            pool.tasks.spawn(endpoint.clone().receive(self.budget.clone(), policy_changed));
            pool.endpoints.insert(source, endpoint);
        }
        let endpoint = pool.endpoints[&source].clone();
        let mut state = endpoint.state.lock().unwrap();
        if endpoint.closed.is_cancelled() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        // Two virtual destinations can resolve to the same real peer. Their
        // replies cannot be disambiguated, so never steal an existing route.
        if state.routes.contains_key(&peer) {
            return Ok(None);
        }
        // Each route already owns a global session permit. A second arbitrary
        // per-source limit would break high-fanout DHT and game traffic.
        let (sender, receiver) = mpsc::channel(PEER_QUEUE);
        state.routes.insert(peer, sender);
        state.last_activity = Instant::now();
        drop(state);
        Ok(Some(Flow { endpoint, peer, receiver }))
    }

    pub(crate) async fn maintain(&self) {
        let (_permit, owners) = self.snapshot().await;
        if let Err(error) = &owners {
            log::debug!("Cannot validate UDP bypass owners: {error}");
        }
        let interface = self.egress.as_ref().map(watch::Receiver::borrow);
        self.maintain_with(owners.as_ref().ok(), interface.as_deref().map(Arc::as_ref));
    }

    fn maintain_with(&self, owners: Option<&UdpOwners>, interface: Option<&BindInterface>) {
        let mut pool = self.state.lock().unwrap();
        let ownership_unknown = if owners.is_some() {
            pool.owner_failure_since = None;
            false
        } else {
            pool.owner_failure_since.get_or_insert_with(Instant::now).elapsed() < OWNER_FAILURE_GRACE
        };
        if owners.is_none() && !ownership_unknown && !pool.endpoints.is_empty() {
            log::warn!(
                "UDP ownership verification unavailable for {OWNER_FAILURE_GRACE:?}; retiring {} endpoints",
                pool.endpoints.len()
            );
        }
        pool.endpoints.retain(|source, endpoint| {
            let keep = (ownership_unknown || owners.and_then(|owners| owners.get(*source)) == Some(endpoint.owner))
                && interface.is_some_and(|interface| endpoint.uses_interface(*source, interface))
                && !endpoint.expired();
            if !keep {
                endpoint.close();
            }
            keep
        });
        pool.reap();
    }

    pub(crate) async fn shutdown(&self) {
        let mut tasks = {
            let mut pool = self.state.lock().unwrap();
            for endpoint in pool.endpoints.values() {
                endpoint.close();
            }
            pool.endpoints.clear();
            std::mem::take(&mut pool.tasks)
        };
        tasks.shutdown().await;
    }
}

pub(crate) struct Flow {
    endpoint: Arc<Endpoint>,
    peer: SocketAddr,
    receiver: mpsc::Receiver<Datagram>,
}

impl Flow {
    async fn send(&self, payload: &[u8]) -> io::Result<()> {
        loop {
            tokio::select! {
                biased;
                _ = self.endpoint.closed.cancelled() => return Err(io::ErrorKind::BrokenPipe.into()),
                ready = self.endpoint.socket.writable() => { ready?; }
            }
            let mut state = self.endpoint.state.lock().unwrap();
            if self.endpoint.closed.is_cancelled() {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            // No await under the retirement lock: a completed close forbids
            // both outbound sends and queued reply injection.
            match self.endpoint.socket.try_send_to(payload, self.peer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => {
                    result?;
                }
            }
            state.last_activity = Instant::now();
            return Ok(());
        }
    }

    pub(crate) async fn relay(mut self, mut stack: IpStackUdpStream) -> crate::Result<()> {
        let mut buffer = vec![0; u16::MAX as usize];
        let (mut sent, mut received) = (0u64, 0u64);
        let source = stack.local_addr();
        let peer = self.peer;
        let result: crate::Result<()> = async {
            loop {
                tokio::select! {
                    _ = self.endpoint.closed.cancelled() => break,
                    packet = stack.recv(&mut buffer) => {
                        let Some(length) = packet? else { break };
                        self.send(&buffer[..length]).await?;
                        crate::traffic_status::traffic_status_update(length, 0)?;
                        sent += 1;
                    }
                    packet = self.receiver.recv() => {
                        let Some(packet) = packet else { break };
                        // Serialize injection with retirement: queued replies
                        // must not escape after a new owner replaces this socket.
                        let state = self.endpoint.state.lock().unwrap();
                        if self.endpoint.closed.is_cancelled() { break; }
                        stack.send(&packet.bytes)?;
                        drop(state);
                        crate::traffic_status::traffic_status_update(0, packet.bytes.len())?;
                        received += 1;
                    }
                }
            }
            Ok(())
        }
        .await;
        log::info!(
            "Ending UDP bypass flow: source={source}, peer={peer}, sent_datagrams={sent}, received_datagrams={received}, result={result:?}"
        );
        result
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        let mut state = self.endpoint.state.lock().unwrap();
        // Registration is exclusive for this Flow's lifetime, and a retired
        // endpoint never accepts a replacement route.
        state.routes.remove(&self.peer);
    }
}

#[cfg(test)]
mod tests;
