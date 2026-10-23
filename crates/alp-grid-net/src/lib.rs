//! libp2p transport for The Grid.
//!
//! Kademlia is used for routing only (`FIND_NODE`); data travels over dedicated
//! `/alp/atlas/*/1` request-response protocols, CBOR-encoded. Peers advertise their operator key
//! in the Identify agent string (`grid/<version> op=<hex>`), and the diversity rule reads their
//! network prefix from the connection address.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use alp_grid_core::ids::Position;
use alp_grid_core::keys::{Bytes32, PublicKey};
use alp_grid_core::transport::{InboundHandler, NetPrefix, NodeRef, Transport, TransportError};
use alp_grid_core::wire::{AtlasRequest, AtlasResponse, ALL_PROTOCOLS};
use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport, ResponseChannel};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, kad, noise, ping, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm};
use parking_lot::RwLock;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

pub const KAD_PROTOCOL: &str = "/alp/atlas/kad/1";
pub const IDENTIFY_PROTOCOL: &str = "/alp/atlas/id/1";
pub const AGENT_PREFIX: &str = "grid/";

#[derive(Clone, Debug)]
pub struct NetConfig {
    pub listen: Vec<Multiaddr>,
    pub bootstrap: Vec<Multiaddr>,
    pub operator_pubkey: PublicKey,
    pub version: String,
    pub request_timeout: Duration,
    /// Max request/response size (vault shards can be large).
    pub max_message_bytes: usize,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            listen: vec!["/ip4/0.0.0.0/udp/4001/quic-v1".parse().unwrap(), "/ip4/0.0.0.0/tcp/4001".parse().unwrap()],
            bootstrap: vec![],
            operator_pubkey: PublicKey::zero(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            request_timeout: Duration::from_secs(10),
            max_message_bytes: 32 * 1024 * 1024,
        }
    }
}

/// CBOR codec with a configurable size limit (vault shards can be tens of MiB).
#[derive(Clone)]
pub struct AtlasCodec {
    max: u64,
}

#[async_trait]
impl request_response::Codec for AtlasCodec {
    type Protocol = StreamProtocol;
    type Request = AtlasRequest;
    type Response = AtlasResponse;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> std::io::Result<AtlasRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(self.max).read_to_end(&mut buf).await?;
        alp_grid_core::canon::from_cbor(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> std::io::Result<AtlasResponse>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(self.max).read_to_end(&mut buf).await?;
        alp_grid_core::canon::from_cbor(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn write_request<T>(&mut self, _: &StreamProtocol, io: &mut T, req: AtlasRequest) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = alp_grid_core::canon::to_cbor(&req).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        io.write_all(&bytes).await?;
        io.close().await
    }

    async fn write_response<T>(&mut self, _: &StreamProtocol, io: &mut T, resp: AtlasResponse) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = alp_grid_core::canon::to_cbor(&resp).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        io.write_all(&bytes).await?;
        io.close().await
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    kad: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    rr: request_response::Behaviour<AtlasCodec>,
}

#[allow(clippy::large_enum_variant)]
enum Command {
    Closest {
        key: Vec<u8>,
        reply: oneshot::Sender<Vec<PeerId>>,
    },
    Request {
        peer: PeerId,
        req: AtlasRequest,
        reply: oneshot::Sender<Result<AtlasResponse, TransportError>>,
    },
    Respond {
        channel: ResponseChannel<AtlasResponse>,
        resp: AtlasResponse,
    },
    Dial(Multiaddr),
    Listeners(oneshot::Sender<Vec<Multiaddr>>),
}

#[derive(Default)]
struct PeerBook {
    nodes: HashMap<PeerId, NodeRef>,
    prefixes: HashMap<PeerId, NetPrefix>,
}

pub struct Network {
    cmd: mpsc::Sender<Command>,
    me: NodeRef,
    local_peer_id: PeerId,
    peers: Arc<RwLock<PeerBook>>,
    timeout: Duration,
}

pub fn peer_id_of(pubkey: &PublicKey) -> Option<PeerId> {
    let pk = libp2p::identity::ed25519::PublicKey::try_from_bytes(&pubkey.0).ok()?;
    Some(PeerId::from_public_key(&libp2p::identity::PublicKey::from(pk)))
}

pub fn pubkey_of(peer: &PeerId) -> Option<PublicKey> {
    let mh = peer.as_ref();
    if mh.code() != 0x00 {
        return None;
    }
    let pk = libp2p::identity::PublicKey::try_decode_protobuf(mh.digest()).ok()?;
    let ed = pk.try_into_ed25519().ok()?;
    Some(Bytes32(ed.to_bytes()))
}

fn prefix_of(addr: &Multiaddr) -> NetPrefix {
    for p in addr.iter() {
        match p {
            Protocol::Ip4(ip) => return NetPrefix::of(&std::net::IpAddr::V4(ip)),
            Protocol::Ip6(ip) => return NetPrefix::of(&std::net::IpAddr::V6(ip)),
            _ => {}
        }
    }
    NetPrefix::default()
}

fn operator_from_agent(agent: &str, fallback: PublicKey) -> PublicKey {
    agent
        .split_whitespace()
        .find_map(|t| t.strip_prefix("op="))
        .and_then(|h| PublicKey::from_hex(h).ok())
        .unwrap_or(fallback)
}

impl Network {
    /// Start the swarm. `seed` is the node's Ed25519 seed (same key as the Atlas node identity).
    pub async fn start(seed: [u8; 32], cfg: NetConfig, handler: Arc<dyn InboundHandler>) -> anyhow::Result<Arc<Network>> {
        let mut seed_bytes = seed;
        let id_keys = libp2p::identity::Keypair::ed25519_from_bytes(&mut seed_bytes)?;
        let local_peer_id = PeerId::from(id_keys.public());
        let my_pubkey = Bytes32(id_keys.public().try_into_ed25519()?.to_bytes());
        let agent_version = format!("{AGENT_PREFIX}{} op={}", cfg.version, cfg.operator_pubkey.to_hex());
        let max = cfg.max_message_bytes;
        let timeout = cfg.request_timeout;

        let mut swarm: Swarm<Behaviour> = libp2p::SwarmBuilder::with_existing_identity(id_keys)
            .with_tokio()
            .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)?
            .with_quic()
            .with_dns()?
            .with_behaviour(|key| {
                let peer_id = key.public().to_peer_id();
                let mut kcfg = kad::Config::new(StreamProtocol::new(KAD_PROTOCOL));
                kcfg.set_query_timeout(Duration::from_secs(20));
                let mut kademlia = kad::Behaviour::with_config(peer_id, kad::store::MemoryStore::new(peer_id), kcfg);
                kademlia.set_mode(Some(kad::Mode::Server));
                let identify =
                    identify::Behaviour::new(identify::Config::new(IDENTIFY_PROTOCOL.to_string(), key.public()).with_agent_version(agent_version.clone()));
                let codec = AtlasCodec { max: max as u64 };
                let protocols = ALL_PROTOCOLS.iter().map(|p| (StreamProtocol::new(p), ProtocolSupport::Full));
                let rr = request_response::Behaviour::with_codec(codec, protocols, request_response::Config::default().with_request_timeout(timeout));
                Ok(Behaviour {
                    kad: kademlia,
                    identify,
                    ping: ping::Behaviour::default(),
                    rr,
                })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
            .build();

        for addr in &cfg.listen {
            if let Err(e) = swarm.listen_on(addr.clone()) {
                warn!(%addr, "listen failed: {e}");
            }
        }
        for addr in &cfg.bootstrap {
            if let Some(Protocol::P2p(pid)) = addr.iter().last() {
                swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
            }
            if let Err(e) = swarm.dial(addr.clone()) {
                warn!(%addr, "bootstrap dial failed: {e}");
            }
        }

        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let peers = Arc::new(RwLock::new(PeerBook::default()));
        let me = NodeRef {
            pubkey: my_pubkey,
            operator: cfg.operator_pubkey,
            prefix: NetPrefix::default(),
        };
        let net = Arc::new(Network {
            cmd: cmd_tx.clone(),
            me,
            local_peer_id,
            peers: peers.clone(),
            timeout,
        });
        tokio::spawn(event_loop(swarm, cmd_rx, cmd_tx, peers, handler, my_pubkey));
        info!(%local_peer_id, "network started");
        Ok(net)
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    pub async fn listeners(&self) -> Vec<Multiaddr> {
        let (tx, rx) = oneshot::channel();
        let _ = self.cmd.send(Command::Listeners(tx)).await;
        rx.await.unwrap_or_default()
    }

    pub async fn dial(&self, addr: Multiaddr) {
        let _ = self.cmd.send(Command::Dial(addr)).await;
    }

    pub fn peer_count(&self) -> usize {
        self.peers.read().nodes.len()
    }

    fn node_ref(&self, peer: &PeerId) -> Option<NodeRef> {
        let book = self.peers.read();
        if let Some(n) = book.nodes.get(peer) {
            return Some(n.clone());
        }
        let pubkey = pubkey_of(peer)?;
        Some(NodeRef {
            pubkey,
            operator: pubkey,
            prefix: book.prefixes.get(peer).cloned().unwrap_or_default(),
        })
    }
}

#[async_trait]
impl Transport for Network {
    fn me(&self) -> NodeRef {
        self.me.clone()
    }

    async fn closest(&self, key: &Position, k: usize) -> Vec<NodeRef> {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd
            .send(Command::Closest {
                key: key.0 .0.to_vec(),
                reply: tx,
            })
            .await
            .is_err()
        {
            return vec![self.me.clone()];
        }
        let peers = tokio::time::timeout(Duration::from_secs(25), rx)
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or_default();
        let mut nodes: Vec<NodeRef> = peers.iter().filter_map(|p| self.node_ref(p)).collect();
        nodes.push(self.me.clone());
        nodes.sort_by_key(|n| n.position().distance(key));
        nodes.dedup_by(|a, b| a.pubkey == b.pubkey);
        nodes.truncate(k);
        nodes
    }

    fn known(&self) -> Vec<NodeRef> {
        self.peers.read().nodes.values().cloned().collect()
    }

    async fn request(&self, to: &NodeRef, req: AtlasRequest) -> Result<AtlasResponse, TransportError> {
        let peer = peer_id_of(&to.pubkey).ok_or_else(|| TransportError::Unreachable("bad public key".into()))?;
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Command::Request { peer, req, reply: tx })
            .await
            .map_err(|_| TransportError::Unreachable("network stopped".into()))?;
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(TransportError::Unreachable("dropped".into())),
            Err(_) => Err(TransportError::Timeout),
        }
    }
}

async fn event_loop(
    mut swarm: Swarm<Behaviour>,
    mut cmd_rx: mpsc::Receiver<Command>,
    cmd_tx: mpsc::Sender<Command>,
    peers: Arc<RwLock<PeerBook>>,
    handler: Arc<dyn InboundHandler>,
    my_pubkey: PublicKey,
) {
    let mut pending_closest: HashMap<kad::QueryId, oneshot::Sender<Vec<PeerId>>> = HashMap::new();
    let mut pending_requests: HashMap<OutboundRequestId, oneshot::Sender<Result<AtlasResponse, TransportError>>> = HashMap::new();
    let mut bootstrap_tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = bootstrap_tick.tick() => {
                if swarm.behaviour_mut().kad.kbuckets().count() > 0 {
                    let _ = swarm.behaviour_mut().kad.bootstrap();
                }
            }
            Some(cmd) = cmd_rx.recv() => match cmd {
                Command::Closest { key, reply } => {
                    let id = swarm.behaviour_mut().kad.get_closest_peers(key);
                    pending_closest.insert(id, reply);
                }
                Command::Request { peer, req, reply } => {
                    let id = swarm.behaviour_mut().rr.send_request(&peer, req);
                    pending_requests.insert(id, reply);
                }
                Command::Respond { channel, resp } => {
                    let _ = swarm.behaviour_mut().rr.send_response(channel, resp);
                }
                Command::Dial(addr) => {
                    if let Some(Protocol::P2p(pid)) = addr.iter().last() {
                        swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
                    }
                    let _ = swarm.dial(addr);
                }
                Command::Listeners(reply) => {
                    let _ = reply.send(swarm.listeners().cloned().collect());
                }
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => info!(%address, "listening"),
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    let prefix = prefix_of(endpoint.get_remote_address());
                    let mut book = peers.write();
                    book.prefixes.insert(peer_id, prefix.clone());
                    if let Some(n) = book.nodes.get_mut(&peer_id) {
                        n.prefix = prefix;
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                    for addr in &info.listen_addrs {
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                    }
                    if let Ok(ed) = info.public_key.clone().try_into_ed25519() {
                        let pubkey = Bytes32(ed.to_bytes());
                        if pubkey != my_pubkey {
                            let operator = operator_from_agent(&info.agent_version, pubkey);
                            let mut book = peers.write();
                            let prefix = book.prefixes.get(&peer_id).cloned().unwrap_or_default();
                            book.nodes.insert(peer_id, NodeRef { pubkey, operator, prefix });
                            debug!(%peer_id, agent = %info.agent_version, "peer identified");
                        }
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result: kad::QueryResult::GetClosestPeers(res), step, .. })) => {
                    if step.last {
                        if let Some(reply) = pending_closest.remove(&id) {
                            let peers_found: Vec<PeerId> = match res {
                                Ok(ok) => ok.peers.into_iter().map(|p| p.peer_id).collect(),
                                Err(kad::GetClosestPeersError::Timeout { peers, .. }) => peers.into_iter().map(|p| p.peer_id).collect(),
                            };
                            let _ = reply.send(peers_found);
                        }
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Rr(request_response::Event::Message { peer, message, .. })) => match message {
                    request_response::Message::Request { request, channel, .. } => {
                        let from = {
                            let book = peers.read();
                            book.nodes.get(&peer).cloned().or_else(|| pubkey_of(&peer).map(|pk| NodeRef { pubkey: pk, operator: pk, prefix: book.prefixes.get(&peer).cloned().unwrap_or_default() }))
                        };
                        let handler = handler.clone();
                        let tx = cmd_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let resp = handler.handle(from, request);
                            let _ = tx.blocking_send(Command::Respond { channel, resp });
                        });
                    }
                    request_response::Message::Response { request_id, response } => {
                        if let Some(reply) = pending_requests.remove(&request_id) {
                            let _ = reply.send(Ok(response));
                        }
                    }
                },
                SwarmEvent::Behaviour(BehaviourEvent::Rr(request_response::Event::OutboundFailure { request_id, error, .. })) => {
                    if let Some(reply) = pending_requests.remove(&request_id) {
                        let err = match error {
                            request_response::OutboundFailure::Timeout => TransportError::Timeout,
                            other => TransportError::Unreachable(other.to_string()),
                        };
                        let _ = reply.send(Err(err));
                    }
                }
                SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } => {
                    debug!(%peer_id, "disconnected");
                }
                _ => {}
            }
        }
    }
}
