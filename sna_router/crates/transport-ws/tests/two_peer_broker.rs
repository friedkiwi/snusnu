//! A loopback concentrator script exercises the wire contract across two
//! authenticated router connections without requiring TAPs or OS/400.

use prost::Message as _;
use std::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
    time::Duration,
};
use transport_ws::{wire, WsClient, SUBPROTOCOL};
use tungstenite::{
    accept_hdr,
    handshake::server::{Request, Response},
    http::HeaderValue,
    Message, WebSocket,
};

type Body = wire::ws_envelope::Body;
type Event = wire::circuit_event::Event;

fn envelope(body: Body) -> wire::WsEnvelope {
    wire::WsEnvelope { body: Some(body) }
}

fn send_server(socket: &mut WebSocket<TcpStream>, body: Body) {
    socket
        .send(Message::Binary(envelope(body).encode_to_vec().into()))
        .unwrap();
}

fn read_server(socket: &mut WebSocket<TcpStream>) -> Body {
    match socket.read().unwrap() {
        Message::Binary(bytes) => wire::WsEnvelope::decode(bytes).unwrap().body.unwrap(),
        other => panic!("expected binary WebSocket message, got {other:?}"),
    }
}

fn send_client(client: &mut WsClient, body: Body) {
    client.send(envelope(body)).unwrap();
}

fn read_client(client: &mut WsClient) -> Body {
    client.recv().unwrap().body.unwrap()
}

fn accept_router(listener: &TcpListener, token: &'static str) -> WebSocket<TcpStream> {
    let (stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let expected = format!("Bearer {token}");
    accept_hdr(stream, move |request: &Request, mut response: Response| {
        assert_eq!(
            request.headers().get("authorization").unwrap(),
            expected.as_str()
        );
        assert_eq!(
            request.headers().get("sec-websocket-protocol").unwrap(),
            SUBPROTOCOL
        );
        response.headers_mut().insert(
            "sec-websocket-protocol",
            HeaderValue::from_static(SUBPROTOCOL),
        );
        Ok(response)
    })
    .unwrap()
}

fn cp(name: &str) -> wire::SnaName {
    wire::SnaName {
        netid: "SOLNET".into(),
        name: name.into(),
    }
}

fn snapshot(epoch: Vec<u8>, name: &str) -> wire::RouteSnapshot {
    wire::RouteSnapshot {
        epoch,
        revision: 1,
        routes: vec![wire::RouteExport {
            id: 1,
            generation: 1,
            resource: Some(wire::route_export::Resource::ControlPoint(cp(name))),
        }],
    }
}

fn welcome(router_id: Vec<u8>, epoch: Vec<u8>, name: &str) -> wire::RouterWelcome {
    wire::RouterWelcome {
        router_id,
        connection_epoch: epoch,
        max_message_bytes: 64 * 1024,
        max_circuits: 4,
        display_name: name.into(),
        allowed_netid: "SOLNET".into(),
    }
}

#[test]
fn two_authenticated_peers_exchange_routes_and_circuit_traffic() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}/router/v1/ws", listener.local_addr().unwrap());
    let a_id = vec![0xa1; 16];
    let b_id = vec![0xb2; 16];
    let a_epoch = vec![0x11; 16];
    let b_epoch = vec![0x22; 16];
    let circuit_id = vec![0xc3; 16];
    let (a_connected_tx, a_connected_rx) = mpsc::channel();

    let server = {
        let (a_id, b_id, a_epoch, b_epoch, circuit_id) = (
            a_id.clone(),
            b_id.clone(),
            a_epoch.clone(),
            b_epoch.clone(),
            circuit_id.clone(),
        );
        thread::spawn(move || {
            let mut a = accept_router(&listener, "router-a");
            send_server(
                &mut a,
                Body::Welcome(welcome(a_id.clone(), a_epoch.clone(), "A")),
            );
            let mut b = accept_router(&listener, "router-b");
            send_server(
                &mut b,
                Body::Welcome(welcome(b_id.clone(), b_epoch.clone(), "B")),
            );

            assert_eq!(
                read_server(&mut a),
                Body::PublishRoutes(snapshot(a_epoch.clone(), "SNAA"))
            );
            assert_eq!(
                read_server(&mut b),
                Body::PublishRoutes(snapshot(b_epoch.clone(), "SNAB"))
            );
            send_server(
                &mut a,
                Body::OriginRoutes(wire::OriginRouteSnapshot {
                    router_id: b_id.clone(),
                    snapshot: Some(snapshot(b_epoch.clone(), "SNAB")),
                }),
            );
            send_server(
                &mut b,
                Body::OriginRoutes(wire::OriginRouteSnapshot {
                    router_id: a_id.clone(),
                    snapshot: Some(snapshot(a_epoch.clone(), "SNAA")),
                }),
            );

            let target = wire::RouteReference {
                router_id: b_id,
                epoch: b_epoch,
                route_id: 1,
                route_generation: 1,
            };
            assert_eq!(
                read_server(&mut a),
                Body::OpenRequest(wire::OpenRequest {
                    request_id: 7,
                    target: Some(target.clone()),
                    receive_allowance_bytes: 1500,
                })
            );
            send_server(
                &mut b,
                Body::IncomingOpen(wire::IncomingOpen {
                    circuit_id: circuit_id.clone(),
                    source_router_id: a_id,
                    target: Some(target),
                    source_receive_allowance_bytes: 1500,
                }),
            );
            assert_eq!(
                read_server(&mut b),
                Body::OpenDecision(wire::OpenDecision {
                    circuit_id: circuit_id.clone(),
                    accept: true,
                    receive_allowance_bytes: 1500,
                    reason: wire::OpenFailure::Unspecified as i32,
                })
            );
            send_server(
                &mut b,
                Body::OpenReady(wire::OpenReady {
                    circuit_id: circuit_id.clone(),
                }),
            );
            send_server(
                &mut a,
                Body::OpenResult(wire::OpenResult {
                    request_id: 7,
                    circuit_id: circuit_id.clone(),
                    accepted: true,
                    peer_receive_allowance_bytes: 1500,
                    reason: wire::OpenFailure::Unspecified as i32,
                }),
            );

            for from_a in [true, false, true, false, true, false, false] {
                let (source, target) = if from_a {
                    (&mut a, &mut b)
                } else {
                    (&mut b, &mut a)
                };
                let body = read_server(source);
                assert!(matches!(
                    body,
                    Body::CircuitEvent(_) | Body::CircuitCredit(_) | Body::CircuitClose(_)
                ));
                send_server(target, body);
            }
        })
    };

    let a = {
        let (url, a_id, a_epoch, b_id, b_epoch, circuit_id) = (
            url.clone(),
            a_id.clone(),
            a_epoch.clone(),
            b_id.clone(),
            b_epoch.clone(),
            circuit_id.clone(),
        );
        thread::spawn(move || {
            let (mut client, received) = WsClient::connect(&url, "router-a").unwrap();
            assert_eq!(received.router_id, a_id);
            a_connected_tx.send(()).unwrap();
            send_client(&mut client, Body::PublishRoutes(snapshot(a_epoch, "SNAA")));
            assert!(
                matches!(read_client(&mut client), Body::OriginRoutes(routes) if routes.router_id == b_id && routes.snapshot.as_ref().unwrap().epoch == b_epoch)
            );
            send_client(
                &mut client,
                Body::OpenRequest(wire::OpenRequest {
                    request_id: 7,
                    target: Some(wire::RouteReference {
                        router_id: b_id,
                        epoch: b_epoch,
                        route_id: 1,
                        route_generation: 1,
                    }),
                    receive_allowance_bytes: 1500,
                }),
            );
            assert!(
                matches!(read_client(&mut client), Body::OpenResult(result) if result.accepted && result.circuit_id == circuit_id)
            );
            let xid = wire::DlcType1 {
                kind: wire::Type1Kind::Xid as i32,
                response: false,
                poll_final: true,
                dsap: 4,
                ssap: 4,
                information: vec![0x81, 0x10, 0x20],
            };
            send_client(
                &mut client,
                Body::CircuitEvent(wire::CircuitEvent {
                    circuit_id: circuit_id.clone(),
                    event: Some(Event::Type1(xid)),
                }),
            );
            assert!(
                matches!(read_client(&mut client), Body::CircuitEvent(event) if
                matches!(&event.event, Some(Event::Type1(reply)) if reply.response && reply.information == vec![0x81, 0x10, 0x20]))
            );
            send_client(
                &mut client,
                Body::CircuitEvent(wire::CircuitEvent {
                    circuit_id: circuit_id.clone(),
                    event: Some(Event::LinkReady(wire::LinkReady {})),
                }),
            );
            assert!(
                matches!(read_client(&mut client), Body::CircuitEvent(event) if matches!(event.event, Some(Event::LinkReady(_))))
            );
            send_client(
                &mut client,
                Body::CircuitEvent(wire::CircuitEvent {
                    circuit_id: circuit_id.clone(),
                    event: Some(Event::SnaInformation(vec![0x2d, 0x00, 0x01])),
                }),
            );
            assert!(
                matches!(read_client(&mut client), Body::CircuitCredit(credit) if credit.circuit_id == circuit_id && credit.allowance_bytes == 1503)
            );
            assert!(
                matches!(read_client(&mut client), Body::CircuitClose(close) if close.circuit_id == circuit_id)
            );
        })
    };

    a_connected_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let b = {
        let (url, b_id, b_epoch, a_id, a_epoch, circuit_id) =
            (url, b_id, b_epoch, a_id, a_epoch, circuit_id);
        thread::spawn(move || {
            let (mut client, received) = WsClient::connect(&url, "router-b").unwrap();
            assert_eq!(received.router_id, b_id);
            send_client(&mut client, Body::PublishRoutes(snapshot(b_epoch, "SNAB")));
            assert!(
                matches!(read_client(&mut client), Body::OriginRoutes(routes) if routes.router_id == a_id && routes.snapshot.as_ref().unwrap().epoch == a_epoch)
            );
            assert!(
                matches!(read_client(&mut client), Body::IncomingOpen(open) if open.circuit_id == circuit_id && open.source_router_id == a_id)
            );
            send_client(
                &mut client,
                Body::OpenDecision(wire::OpenDecision {
                    circuit_id: circuit_id.clone(),
                    accept: true,
                    receive_allowance_bytes: 1500,
                    reason: wire::OpenFailure::Unspecified as i32,
                }),
            );
            assert!(
                matches!(read_client(&mut client), Body::OpenReady(ready) if ready.circuit_id == circuit_id)
            );
            assert!(
                matches!(read_client(&mut client), Body::CircuitEvent(event) if
                matches!(&event.event, Some(Event::Type1(xid)) if !xid.response && xid.poll_final && xid.information == vec![0x81, 0x10, 0x20]))
            );
            send_client(
                &mut client,
                Body::CircuitEvent(wire::CircuitEvent {
                    circuit_id: circuit_id.clone(),
                    event: Some(Event::Type1(wire::DlcType1 {
                        kind: wire::Type1Kind::Xid as i32,
                        response: true,
                        poll_final: true,
                        dsap: 4,
                        ssap: 4,
                        information: vec![0x81, 0x10, 0x20],
                    })),
                }),
            );
            assert!(
                matches!(read_client(&mut client), Body::CircuitEvent(event) if matches!(event.event, Some(Event::LinkReady(_))))
            );
            send_client(
                &mut client,
                Body::CircuitEvent(wire::CircuitEvent {
                    circuit_id: circuit_id.clone(),
                    event: Some(Event::LinkReady(wire::LinkReady {})),
                }),
            );
            assert!(
                matches!(read_client(&mut client), Body::CircuitEvent(event) if
                matches!(&event.event, Some(Event::SnaInformation(data)) if data == &vec![0x2d, 0x00, 0x01]))
            );
            send_client(
                &mut client,
                Body::CircuitCredit(wire::CircuitCredit {
                    circuit_id: circuit_id.clone(),
                    allowance_bytes: 1503,
                }),
            );
            send_client(
                &mut client,
                Body::CircuitClose(wire::CircuitClose { circuit_id }),
            );
        })
    };

    a.join().unwrap();
    b.join().unwrap();
    server.join().unwrap();
}
