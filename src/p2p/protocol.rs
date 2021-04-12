use async_std::task;
use futures::future::BoxFuture;
use futures::prelude::*;
use libp2p::{
    core::{connection::ConnectionId, UpgradeInfo},
    swarm::{
        KeepAlive, NegotiatedSubstream, NetworkBehaviour,
        NetworkBehaviourAction, PollParameters, ProtocolsHandler,
        ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
    },
    InboundUpgrade, Multiaddr, OutboundUpgrade, PeerId,
};
use rand::{distributions, prelude::*};
use std::{
    collections::VecDeque,
    error::Error,
    fmt, io, iter,
    task::{Context, Poll},
    time::Duration,
};
use void::Void;

use crate::{PoLMessage, ProofOfLatency};

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
pub enum PoLFailure {
    Timeout,
}

impl fmt::Display for PoLFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoLFailure::Timeout => f.write_str("PoL timeout"),
        }
    }
}

impl Error for PoLFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PoLFailure::Timeout => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PoLConfig {
    timeout: Duration,
}

impl PoLConfig {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(20),
        }
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
    outbound: Option<PoLState>,
    inbound: Option<PongFuture>,
}

impl PoLHandler {
    pub fn new(config: PoLConfig) -> Self {
        PoLHandler {
            config,
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
    type InEvent = PoLMessage;
    type OutEvent = PoLMessage;
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
        self.inbound = Some(recv_PoL(stream).boxed());
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        stream: NegotiatedSubstream,
        (): (),
    ) {
        self.outbound = Some(PoLState::PoL(send_PoL(stream).boxed()));
    }

    fn inject_event(&mut self, _: Void) {}

    fn inject_dial_upgrade_error(
        &mut self,
        _info: (),
        error: ProtocolsHandlerUpgrErr<Void>,
    ) {
        self.outbound = None; // Request a new substream on the next `poll`.
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        KeepAlive::Yes
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ProtocolsHandlerEvent<PoLProtocol, (), PoLResult, Self::Error>>
    {
        // respond to inbound PoLMessages.
        if let Some(fut) = self.inbound.as_mut() {
            match fut.poll_unpin(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    log::debug!("Inbound PoL error: {:?}", e);
                    self.inbound = None;
                }
                Poll::Ready(Ok(stream)) => {
                    self.inbound = Some(recv_PoL(stream).boxed());
                    return Poll::Ready(ProtocolsHandlerEvent::Custom(Ok(
                        PoLSuccess::Pong,
                    )));
                }
            }
        }

        loop {
            // continue outbound PoLMessages
            match self.outbound.take() {
                Some(PoLState::PoL(mut PoL)) => match PoL.poll_unpin(cx) {
                    Poll::Pending => {
                        self.outbound = Some(PoLState::PoL(PoL));
                        break;
                    }
                    Poll::Ready(Ok((stream, rtt))) => {
                        self.outbound = Some(PoLState::Idle(stream));
                        return Poll::Ready(ProtocolsHandlerEvent::Custom(Ok(
                            PoLSuccess::PoL { rtt },
                        )));
                    }
                },
                Some(PoLState::Idle(stream)) => match self.timer.poll_unpin(cx)
                {
                    Poll::Pending => {
                        self.outbound = Some(PoLState::Idle(stream));
                        break;
                    }
                    Poll::Ready(Ok(())) => {
                        self.outbound =
                            Some(PoLState::PoL(send_PoL(stream).boxed()));
                    }
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(ProtocolsHandlerEvent::Close(
                            PoLFailure::Other { error: Box::new(e) },
                        ))
                    }
                },
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

// HANDLE INPUT
pub async fn recv_PoL<S>(mut stream: S) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut payload = [0u8; PING_SIZE];
    log::debug!("Waiting for PoL ...");
    stream.read_exact(&mut payload).await?;
    log::debug!("Sending pong for {:?}", payload);
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(stream)
}

// HANDLE OUTPUT
pub async fn send_PoL<S>(mut stream: S) -> io::Result<(S, Duration)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let payload: [u8; PING_SIZE] = thread_rng().sample(distributions::Standard);
    log::debug!("Preparing PoL payload {:?}", payload);
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
        iter::once(b"/ipfs/PoL/1.0.0")
    }
}
