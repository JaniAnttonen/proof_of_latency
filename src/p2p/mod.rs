use async_std::task;
use futures::future::BoxFuture;
use futures::prelude::*;
use libp2p::{
    core::{connection::ConnectionId, UpgradeInfo},
    identity,
    swarm::{
        KeepAlive, NegotiatedSubstream, NetworkBehaviour,
        NetworkBehaviourAction, PollParameters, ProtocolsHandler,
        ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
    },
    InboundUpgrade, Multiaddr, OutboundUpgrade, PeerId, Swarm,
};
use rand::{distributions, prelude::*};
use std::{
    collections::VecDeque,
    error::Error,
    fmt, io, iter,
    num::NonZeroU32,
    task::{Context, Poll},
    time::Duration,
};
use void::Void;
use wasm_timer::{Delay, Instant};

use crate::vdf::{PoLMessage, ProofOfLatency};

pub fn run_p2p() -> Result<(), Box<dyn Error>> {
    println!("Hello, world!");

    // create a random peerid.
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());
    println!("Local peer id: {:?}", peer_id);

    // create a transport.
    let transport = libp2p::build_development_transport(id_keys)?;

    // create a ping network behaviour.
    let behaviour = PoL::new(PoLConfig::new().with_keep_alive(true));

    // create a swarm that establishes connections through the given transport
    // and applies the ping behaviour on each connection.
    let mut swarm = Swarm::new(transport, behaviour, peer_id);

    // Dial the peer identified by the multi-address given as the second
    // cli arg.
    if let Some(addr) = std::env::args().nth(1) {
        let remote = addr.parse()?;
        Swarm::dial_addr(&mut swarm, remote)?;
        println!("Dialed {}", addr)
    }

    // Tell the swarm to listen on all interfaces and a random, OS-assigned
    // port.
    Swarm::listen_on(&mut swarm, "/ip4/0.0.0.0/tcp/0".parse()?)?;

    let mut listening = false;
    task::block_on(future::poll_fn(move |cx: &mut Context<'_>| loop {
        match swarm.poll_next_unpin(cx) {
            Poll::Ready(Some(event)) => println!("{:?}", event),
            Poll::Ready(None) => return Poll::Ready(()),
            Poll::Pending => {
                if !listening {
                    for addr in Swarm::listeners(&swarm) {
                        println!("Listening on {}", addr);
                        listening = true;
                    }
                }
                return Poll::Pending;
            }
        }
    }));

    Ok(())
}

// PoL protocol implementation

pub struct PoL {
    config: PoLConfig,
    events: VecDeque<PoLEvent>,
}

impl PoL {
    pub fn new(config: PoLConfig) -> Self {
        PoL {
            config,
            events: VecDeque::new(),
        }
    }
}

#[derive(Debug)]
pub struct PoLEvent {
    pub peer: PeerId,
    pub result: PoLResult,
}

pub type PoLResult = Result<PoLMessage, PoLFailure>;

#[derive(Debug)]
pub enum PoLSuccess {
    Pong,
    PoL { rtt: Duration },
}

#[derive(Debug)]
pub enum PoLFailure {
    Timeout,
    Other {
        error: Box<dyn std::error::Error + Send + 'static>,
    },
}

impl fmt::Display for PoLFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoLFailure::Timeout => f.write_str("PoL timeout"),
            PoLFailure::Other { error } => write!(f, "PoL error: {}", error),
        }
    }
}

impl Error for PoLFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PoLFailure::Timeout => None,
            PoLFailure::Other { error } => Some(&**error),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PoLConfig {
    timeout: Duration,
    interval: Duration,
    max_failures: NonZeroU32,
    keep_alive: bool,
}

impl PoLConfig {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(20),
            interval: Duration::from_secs(15),
            max_failures: NonZeroU32::new(1).expect("1 != 0"),
            keep_alive: false,
        }
    }

    pub fn with_keep_alive(mut self, b: bool) -> Self {
        self.keep_alive = b;
        self
    }
}

impl NetworkBehaviour for PoL {
    type ProtocolsHandler = PoLHandler;
    type OutEvent = PoLEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        PoLHandler::new(self.config.clone())
    }

    fn addresses_of_peer(&mut self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    fn inject_connected(&mut self, _: &PeerId) {}

    fn inject_disconnected(&mut self, _: &PeerId) {}

    fn inject_event(
        &mut self,
        peer: PeerId,
        _: ConnectionId,
        result: PoLResult,
    ) {
        self.events.push_front(PoLEvent { peer, result })
    }

    fn poll(
        &mut self,
        _: &mut Context<'_>,
        _: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Void, PoLEvent>> {
        if let Some(e) = self.events.pop_back() {
            Poll::Ready(NetworkBehaviourAction::GenerateEvent(e))
        } else {
            Poll::Pending
        }
    }
}

pub struct PoLHandler {
    config: PoLConfig,
    timer: Delay,
    pending_errors: VecDeque<PoLFailure>,
    failures: u32,
    outbound: Option<PoLState>,
    inbound: Option<PongFuture>,
}

impl PoLHandler {
    /// Builds a new `PoLHandler` with the given configuration.
    pub fn new(config: PoLConfig) -> Self {
        PoLHandler {
            config,
            timer: Delay::new(Duration::new(0, 0)),
            pending_errors: VecDeque::with_capacity(2),
            failures: 0,
            outbound: None,
            inbound: None,
        }
    }
}

enum PoLState {
    OpenStream,
    Idle(NegotiatedSubstream),
    PoL(PoLFuture),
}

type PoLFuture =
    BoxFuture<'static, Result<(NegotiatedSubstream, Duration), io::Error>>;
type PongFuture = BoxFuture<'static, Result<NegotiatedSubstream, io::Error>>;

impl ProtocolsHandler for PoLHandler {
    type InEvent = Void;
    type OutEvent = PoLResult;
    type Error = PoLFailure;
    type InboundProtocol = PoLProtocol;
    type OutboundProtocol = PoLProtocol;
    type OutboundOpenInfo = ();
    type InboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<PoLProtocol, ()> {
        SubstreamProtocol::new(PoLProtocol, ())
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        stream: NegotiatedSubstream,
        (): (),
    ) {
        self.inbound = Some(recv_ping(stream).boxed());
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        stream: NegotiatedSubstream,
        (): (),
    ) {
        self.timer.reset(self.config.timeout);
        self.outbound = Some(PoLState::PoL(send_ping(stream).boxed()));
    }

    fn inject_event(&mut self, _: Void) {}

    fn inject_dial_upgrade_error(
        &mut self,
        _info: (),
        error: ProtocolsHandlerUpgrErr<Void>,
    ) {
        self.outbound = None; // Request a new substream on the next `poll`.
        self.pending_errors.push_front(match error {
            ProtocolsHandlerUpgrErr::Timeout => PoLFailure::Timeout,
            e => PoLFailure::Other { error: Box::new(e) },
        })
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        if self.config.keep_alive {
            KeepAlive::Yes
        } else {
            KeepAlive::No
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ProtocolsHandlerEvent<PoLProtocol, (), PoLResult, Self::Error>>
    {
        // respond to inbound pings.
        if let Some(fut) = self.inbound.as_mut() {
            match fut.poll_unpin(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    log::debug!("Inbound ping error: {:?}", e);
                    self.inbound = None;
                }
                Poll::Ready(Ok(stream)) => {
                    self.inbound = Some(recv_ping(stream).boxed());
                    return Poll::Ready(ProtocolsHandlerEvent::Custom(Ok(
                        PoLSuccess::Pong,
                    )));
                }
            }
        }

        loop {
            // check for outbound ping failures.
            if let Some(error) = self.pending_errors.pop_back() {
                log::debug!("PoL failure: {:?}", error);

                self.failures += 1;

                if self.failures > 1 || self.config.max_failures.get() > 1 {
                    if self.failures >= self.config.max_failures.get() {
                        log::debug!(
                            "Too many failures ({}). Closing connection.",
                            self.failures
                        );
                        return Poll::Ready(ProtocolsHandlerEvent::Close(
                            error,
                        ));
                    }

                    return Poll::Ready(ProtocolsHandlerEvent::Custom(Err(
                        error,
                    )));
                }
            }

            // continue outbound pings
            match self.outbound.take() {
                Some(PoLState::PoL(mut ping)) => match ping.poll_unpin(cx) {
                    Poll::Pending => {
                        if self.timer.poll_unpin(cx).is_ready() {
                            self.pending_errors.push_front(PoLFailure::Timeout);
                        } else {
                            self.outbound = Some(PoLState::PoL(ping));
                            break;
                        }
                    }
                    Poll::Ready(Ok((stream, rtt))) => {
                        self.failures = 0;
                        self.timer.reset(self.config.interval);
                        self.outbound = Some(PoLState::Idle(stream));
                        return Poll::Ready(ProtocolsHandlerEvent::Custom(Ok(
                            PoLSuccess::PoL { rtt },
                        )));
                    }
                    Poll::Ready(Err(e)) => self
                        .pending_errors
                        .push_front(PoLFailure::Other { error: Box::new(e) }),
                },
                Some(PoLState::Idle(stream)) => {
                    match self.timer.poll_unpin(cx) {
                        Poll::Pending => {
                            self.outbound = Some(PoLState::Idle(stream));
                            break;
                        }
                        Poll::Ready(Ok(())) => {
                            self.timer.reset(self.config.timeout);
                            self.outbound =
                                Some(PoLState::PoL(send_ping(stream).boxed()));
                        }
                        Poll::Ready(Err(e)) => {
                            return Poll::Ready(ProtocolsHandlerEvent::Close(
                                PoLFailure::Other { error: Box::new(e) },
                            ))
                        }
                    }
                }
                Some(PoLState::OpenStream) => {
                    self.outbound = Some(PoLState::OpenStream);
                    break;
                }
                None => {
                    self.outbound = Some(PoLState::OpenStream);
                    let protocol = SubstreamProtocol::new(PoLProtocol, ())
                        .with_timeout(self.config.timeout);
                    return Poll::Ready(
                        ProtocolsHandlerEvent::OutboundSubstreamRequest {
                            protocol,
                        },
                    );
                }
            }
        }

        Poll::Pending
    }
}

const PING_SIZE: usize = 32;

pub async fn recv_ping<S>(mut stream: S) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut payload = [0u8; PING_SIZE];
    log::debug!("Waiting for ping ...");
    stream.read_exact(&mut payload).await?;
    log::debug!("Sending pong for {:?}", payload);
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(stream)
}

pub async fn send_ping<S>(mut stream: S) -> io::Result<(S, Duration)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let payload: [u8; PING_SIZE] = thread_rng().sample(distributions::Standard);
    log::debug!("Preparing ping payload {:?}", payload);
    stream.write_all(&payload).await?;
    stream.flush().await?;
    let started = Instant::now();
    let mut recv_payload = [0u8; PING_SIZE];
    log::debug!("Awaiting pong for {:?}", payload);
    stream.read_exact(&mut recv_payload).await?;
    if recv_payload == payload {
        Ok((stream, started.elapsed()))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PoL payload mismatch",
        ))
    }
}

#[derive(Default, Debug, Copy, Clone)]
pub struct PoLProtocol;

impl InboundUpgrade<NegotiatedSubstream> for PoLProtocol {
    type Output = NegotiatedSubstream;
    type Error = Void;
    type Future = future::Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(
        self,
        stream: NegotiatedSubstream,
        _: Self::Info,
    ) -> Self::Future {
        future::ok(stream)
    }
}

impl OutboundUpgrade<NegotiatedSubstream> for PoLProtocol {
    type Output = NegotiatedSubstream;
    type Error = Void;
    type Future = future::Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(
        self,
        stream: NegotiatedSubstream,
        _: Self::Info,
    ) -> Self::Future {
        future::ok(stream)
    }
}

impl UpgradeInfo for PoLProtocol {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/ipfs/ping/1.0.0")
    }
}
