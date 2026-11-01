//! Loopback-only two-router broker for the V4R4 lab.
//!
//! Run with `cargo run -p transport-ws --example lab_broker -- 127.0.0.1:18743`.
//! Router A uses token `lab-a`; router B uses token `lab-b`. This intentionally
//! omits production authentication, policy, persistence, and multi-circuit routing.

use prost::Message as _;
use std::{
    env, io,
    net::{TcpListener, TcpStream},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Duration,
};
use transport_ws::{wire, SUBPROTOCOL};
use tungstenite::{
    accept_hdr,
    handshake::server::{Request, Response},
    http::{HeaderValue, Response as HttpResponse, StatusCode},
    Message, WebSocket,
};

type Body = wire::ws_envelope::Body;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const ROUTER_IDS: [[u8; 16]; 2] = [[0xa1; 16], [0xb2; 16]];
const EPOCHS: [[u8; 16]; 2] = [[0x11; 16], [0x22; 16]];
const CIRCUIT_ID: [u8; 16] = [0xc3; 16];

enum Incoming {
    Message(usize, Body),
    Closed(usize, String),
}

struct PendingOpen {
    source: usize,
    target: usize,
    request_id: u64,
    source_allowance: u64,
}

struct Broker {
    outbound: [mpsc::SyncSender<Body>; 2],
    routes: [Option<wire::RouteSnapshot>; 2],
    pending: Option<PendingOpen>,
    active: bool,
}

impl Broker {
    fn send(&self, side: usize, body: Body) -> io::Result<()> {
        self.outbound[side]
            .try_send(body)
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "router queue full or closed"))
    }

    fn handle(&mut self, side: usize, body: Body) -> io::Result<()> {
        match body {
            Body::PublishRoutes(snapshot) => {
                if snapshot.epoch != EPOCHS[side] || snapshot.routes.len() != 1 {
                    return Err(invalid("unexpected route snapshot"));
                }
                eprintln!("broker: router {side} published CP route");
                self.routes[side] = Some(snapshot.clone());
                self.send(
                    1 - side,
                    Body::OriginRoutes(wire::OriginRouteSnapshot {
                        router_id: ROUTER_IDS[side].to_vec(),
                        snapshot: Some(snapshot),
                    }),
                )?;
            }
            Body::OpenRequest(request) => {
                let target = 1 - side;
                let reference = request
                    .target
                    .clone()
                    .ok_or_else(|| invalid("missing target"))?;
                let route = self.routes[target]
                    .as_ref()
                    .and_then(|snapshot| snapshot.routes.first())
                    .ok_or_else(|| invalid("target route absent"))?;
                if self.pending.is_some()
                    || self.active
                    || reference.router_id != ROUTER_IDS[target]
                    || reference.epoch != EPOCHS[target]
                    || reference.route_id != route.id
                    || reference.route_generation != route.generation
                {
                    return Err(invalid("invalid or competing circuit open"));
                }
                self.pending = Some(PendingOpen {
                    source: side,
                    target,
                    request_id: request.request_id,
                    source_allowance: request.receive_allowance_bytes,
                });
                eprintln!("broker: router {side} opened circuit to router {target}");
                self.send(
                    target,
                    Body::IncomingOpen(wire::IncomingOpen {
                        circuit_id: CIRCUIT_ID.to_vec(),
                        source_router_id: ROUTER_IDS[side].to_vec(),
                        target: Some(reference),
                        source_receive_allowance_bytes: request.receive_allowance_bytes,
                    }),
                )?;
            }
            Body::OpenDecision(decision) => {
                let pending = self
                    .pending
                    .take()
                    .ok_or_else(|| invalid("decision without open"))?;
                if side != pending.target || decision.circuit_id != CIRCUIT_ID {
                    return Err(invalid("wrong open decision"));
                }
                if decision.accept {
                    self.active = true;
                    self.send(
                        side,
                        Body::OpenReady(wire::OpenReady {
                            circuit_id: CIRCUIT_ID.to_vec(),
                        }),
                    )?;
                }
                self.send(
                    pending.source,
                    Body::OpenResult(wire::OpenResult {
                        request_id: pending.request_id,
                        circuit_id: if decision.accept {
                            CIRCUIT_ID.to_vec()
                        } else {
                            Vec::new()
                        },
                        accepted: decision.accept,
                        peer_receive_allowance_bytes: if decision.accept {
                            decision.receive_allowance_bytes
                        } else {
                            0
                        },
                        reason: decision.reason,
                    }),
                )?;
                eprintln!("broker: open accepted={}", decision.accept);
                let _ = pending.source_allowance;
            }
            Body::CircuitEvent(event) if self.active && event.circuit_id == CIRCUIT_ID => {
                let kind = match event.event.as_ref() {
                    Some(wire::circuit_event::Event::Type1(_)) => "XID/TEST",
                    Some(wire::circuit_event::Event::LinkReady(_)) => "link-ready",
                    Some(wire::circuit_event::Event::SnaInformation(_)) => "SNA information",
                    None => return Err(invalid("empty circuit event")),
                };
                eprintln!("broker: router {side} -> {} {kind}", 1 - side);
                self.send(1 - side, Body::CircuitEvent(event))?;
            }
            Body::CircuitCredit(credit) if self.active && credit.circuit_id == CIRCUIT_ID => {
                self.send(1 - side, Body::CircuitCredit(credit))?;
            }
            Body::CircuitClose(close) if self.active && close.circuit_id == CIRCUIT_ID => {
                self.send(1 - side, Body::CircuitClose(close))?;
                self.active = false;
                eprintln!("broker: circuit closed by router {side}");
            }
            Body::CircuitReset(reset) if self.active && reset.circuit_id == CIRCUIT_ID => {
                self.send(1 - side, Body::CircuitReset(reset))?;
                self.active = false;
                eprintln!("broker: circuit reset by router {side}");
            }
            _ => return Err(invalid("unsupported or out-of-order router message")),
        }
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn error_response(status: StatusCode) -> HttpResponse<Option<String>> {
    HttpResponse::builder()
        .status(status)
        .body(Some("rejected".into()))
        .unwrap()
}

fn accept_router(stream: TcpStream) -> io::Result<(usize, WebSocket<TcpStream>)> {
    let selected = Arc::new(Mutex::new(None));
    let chosen = Arc::clone(&selected);
    let socket = accept_hdr(stream, move |request: &Request, mut response: Response| {
        let auth = request
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok());
        let side = match auth {
            Some("Bearer lab-a") => 0,
            Some("Bearer lab-b") => 1,
            _ => return Err(error_response(StatusCode::UNAUTHORIZED)),
        };
        if request
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            != Some(SUBPROTOCOL)
        {
            return Err(error_response(StatusCode::BAD_REQUEST));
        }
        response.headers_mut().insert(
            "sec-websocket-protocol",
            HeaderValue::from_static(SUBPROTOCOL),
        );
        *chosen.lock().unwrap() = Some(side);
        Ok(response)
    })
    .map_err(io::Error::other)?;
    let side = selected
        .lock()
        .unwrap()
        .ok_or_else(|| invalid("missing router side"))?;
    Ok((side, socket))
}

fn send(socket: &mut WebSocket<TcpStream>, body: Body) -> io::Result<()> {
    let payload = wire::WsEnvelope { body: Some(body) }.encode_to_vec();
    if payload.len() > MAX_MESSAGE_BYTES {
        return Err(invalid("message too large"));
    }
    socket
        .send(Message::Binary(payload.into()))
        .map_err(io::Error::other)
}

fn worker(
    side: usize,
    mut socket: WebSocket<TcpStream>,
    outbound: mpsc::Receiver<Body>,
    incoming: mpsc::SyncSender<Incoming>,
) {
    let _ = socket
        .get_mut()
        .set_read_timeout(Some(Duration::from_millis(10)));
    socket.set_config(|config| {
        config.max_message_size = Some(MAX_MESSAGE_BYTES);
        config.max_frame_size = Some(MAX_MESSAGE_BYTES);
    });
    loop {
        while let Ok(body) = outbound.try_recv() {
            if let Err(error) = send(&mut socket, body) {
                let _ = incoming.send(Incoming::Closed(side, error.to_string()));
                return;
            }
        }
        match socket.read() {
            Ok(Message::Binary(payload)) => {
                if payload.len() > MAX_MESSAGE_BYTES {
                    let _ = incoming.send(Incoming::Closed(side, "message too large".into()));
                    return;
                }
                match wire::WsEnvelope::decode(payload).ok().and_then(|v| v.body) {
                    Some(body) => {
                        if incoming.send(Incoming::Message(side, body)).is_err() {
                            return;
                        }
                    }
                    None => {
                        let _ = incoming.send(Incoming::Closed(side, "invalid envelope".into()));
                        return;
                    }
                }
            }
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {
                let _ = socket.flush();
            }
            Ok(Message::Close(_)) => {
                let _ = incoming.send(Incoming::Closed(side, "normal close".into()));
                return;
            }
            Ok(_) => {
                let _ = incoming.send(Incoming::Closed(side, "non-binary message".into()));
                return;
            }
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                let _ = incoming.send(Incoming::Closed(side, error.to_string()));
                return;
            }
        }
    }
}

fn main() -> io::Result<()> {
    let bind = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:18743".into());
    if !bind.starts_with("127.0.0.1:") {
        return Err(invalid("bind to 127.0.0.1 only"));
    }
    let listener = TcpListener::bind(&bind)?;
    eprintln!("broker: listening on {bind}; tokens lab-a and lab-b");
    let mut sockets: [Option<WebSocket<TcpStream>>; 2] = [None, None];
    while sockets.iter().any(Option::is_none) {
        let (stream, _) = listener.accept()?;
        match accept_router(stream) {
            Ok((side, mut socket)) if sockets[side].is_none() => {
                send(
                    &mut socket,
                    Body::Welcome(wire::RouterWelcome {
                        router_id: ROUTER_IDS[side].to_vec(),
                        connection_epoch: EPOCHS[side].to_vec(),
                        max_message_bytes: MAX_MESSAGE_BYTES as u32,
                        max_circuits: 1,
                        display_name: format!("V4R4 lab {}", if side == 0 { "A" } else { "B" }),
                        allowed_netid: "SOLNET".into(),
                    }),
                )?;
                eprintln!("broker: router {side} connected");
                sockets[side] = Some(socket);
            }
            Ok((side, _)) => eprintln!("broker: duplicate router {side} rejected"),
            Err(error) => eprintln!("broker: rejected connection: {error}"),
        }
    }
    let (incoming_tx, incoming_rx) = mpsc::sync_channel(128);
    let (send_a, receive_a) = mpsc::sync_channel(64);
    let (send_b, receive_b) = mpsc::sync_channel(64);
    for (side, outbound) in [receive_a, receive_b].into_iter().enumerate() {
        let socket = sockets[side].take().unwrap();
        let incoming = incoming_tx.clone();
        thread::spawn(move || worker(side, socket, outbound, incoming));
    }
    let mut broker = Broker {
        outbound: [send_a, send_b],
        routes: [None, None],
        pending: None,
        active: false,
    };
    while let Ok(message) = incoming_rx.recv() {
        match message {
            Incoming::Message(side, body) => broker.handle(side, body)?,
            Incoming::Closed(side, reason) => {
                eprintln!("broker: router {side} disconnected: {reason}");
                break;
            }
        }
    }
    Ok(())
}
