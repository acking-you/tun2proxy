//! Windows process bypass keeps a physical UDP socket per application socket,
//! not per destination. Flow-specific writers still restore the original (even
//! Fake-IP) peer, and only explicitly contacted peers can deliver replies.

use crate::{
    direct::{self, BindInterface},
    process::{SocketOwner, UdpOwners},
};
use ipstack::IpStackUdpStream;
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinSet,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_PEERS: usize = 256;
const QUEUED_BYTES: usize = 8 * 1024 * 1024;
const PEER_QUEUE: usize = 16;

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
    fn close(&self) {
        let mut state = self.state.lock().unwrap();
        self.closed.cancel();
        state.routes.clear();
    }

    fn expired(&self) -> bool {
        let state = self.state.lock().unwrap();
        self.closed.is_cancelled() || (state.routes.is_empty() && state.last_activity.elapsed() >= IDLE_TIMEOUT)
    }

    async fn receive(self: Arc<Self>, budget: Arc<Semaphore>) {
        let _cancel_on_exit = self.closed.clone().drop_guard();
        let mut buffer = vec![0; u16::MAX as usize];
        loop {
            let result = tokio::select! {
                biased;
                _ = self.closed.cancelled() => break,
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
    limit: usize,
}

impl Pool {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            state: Mutex::new(PoolState {
                endpoints: HashMap::new(),
                tasks: JoinSet::new(),
            }),
            budget: Arc::new(Semaphore::new(QUEUED_BYTES)),
            owner_lookup: Arc::new(Semaphore::new(1)),
            limit: limit.min(1024),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.state.lock().unwrap().endpoints.is_empty()
    }

    pub(crate) async fn open(
        &self,
        source: SocketAddr,
        peer: SocketAddr,
        owner: SocketOwner,
        interface: Arc<BindInterface>,
    ) -> io::Result<Flow> {
        // Fake-IP recovery can await DNS after classification. Revalidate the
        // binding before attaching it, including when the old pool entry expired.
        // Keep the permit in the OS job if the calling flow is cancelled.
        let permit = self.owner_lookup.clone().acquire_owned().await.map_err(io::Error::other)?;
        let current = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            UdpOwners::snapshot().map(|owners| owners.get(source))
        })
        .await
        .map_err(io::Error::other)??;
        if current != Some(owner) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "UDP bypass socket owner changed during setup",
            ));
        }
        self.open_with(source, peer, owner, interface, direct::bind_udp_unconnected)
    }

    fn open_with(
        &self,
        source: SocketAddr,
        peer: SocketAddr,
        owner: SocketOwner,
        interface: Arc<BindInterface>,
        bind: impl FnOnce(bool, &BindInterface) -> io::Result<UdpSocket>,
    ) -> io::Result<Flow> {
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
            && (endpoint.owner != owner || *endpoint.interface != *interface)
        {
            if endpoint.owner != owner && owner.bound_at <= endpoint.owner.bound_at {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "stale UDP bypass socket generation",
                ));
            }
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
                    return Err(io::Error::other("UDP bypass endpoint limit reached"));
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
            pool.tasks.spawn(endpoint.clone().receive(self.budget.clone()));
            pool.endpoints.insert(source, endpoint);
        }
        let endpoint = pool.endpoints[&source].clone();
        let mut state = endpoint.state.lock().unwrap();
        // Two virtual destinations can resolve to the same real peer. Their
        // replies cannot be disambiguated, so never steal an existing route.
        if state.routes.contains_key(&peer) {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, "ambiguous UDP bypass reply route"));
        }
        if state.routes.len() >= MAX_PEERS {
            return Err(io::Error::other("UDP bypass peer limit reached"));
        }
        let (sender, receiver) = mpsc::channel(PEER_QUEUE);
        state.routes.insert(peer, sender.clone());
        state.last_activity = Instant::now();
        drop(state);
        Ok(Flow {
            endpoint,
            peer,
            sender,
            receiver,
        })
    }

    pub(crate) fn maintain(&self, owners: Option<&UdpOwners>, interface: Option<&BindInterface>) {
        let mut pool = self.state.lock().unwrap();
        pool.endpoints.retain(|source, endpoint| {
            let keep = owners.and_then(|owners| owners.get(*source)) == Some(endpoint.owner)
                && interface == Some(endpoint.interface.as_ref())
                && !endpoint.expired();
            if !keep {
                endpoint.close();
            }
            keep
        });
        pool.reap();
    }

    pub(crate) fn invalidate(&self, source: SocketAddr, owner: SocketOwner) {
        let mut pool = self.state.lock().unwrap();
        if pool.endpoints.get(&source).is_some_and(|endpoint| endpoint.owner == owner) {
            pool.endpoints.remove(&source).unwrap().close();
        }
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
    sender: mpsc::Sender<Datagram>,
    receiver: mpsc::Receiver<Datagram>,
}

impl Flow {
    async fn send(&self, payload: &[u8]) -> io::Result<()> {
        tokio::select! {
            biased;
            _ = self.endpoint.closed.cancelled() => return Err(io::ErrorKind::BrokenPipe.into()),
            sent = self.endpoint.socket.send_to(payload, self.peer) => { sent?; }
        }
        self.endpoint.state.lock().unwrap().last_activity = Instant::now();
        Ok(())
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
        if state.routes.get(&self.peer).is_some_and(|route| route.same_channel(&self.sender)) {
            state.routes.remove(&self.peer);
        }
    }
}

#[cfg(test)]
mod tests;
