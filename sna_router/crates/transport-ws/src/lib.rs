//! Authenticated WebSocket hop to the concentrator.
//!
//! This is a blocking transport. A router with local packet ports should run
//! it on a dedicated thread and exchange bounded events with that thread.

use prost::Message as ProstMessage;
use std::fmt;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use tungstenite::client::IntoClientRequest;
use tungstenite::http::header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL};
use tungstenite::http::HeaderValue;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{connect, Message, WebSocket};
use url::Url;

pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/snusnu.control.v1.rs"));
}

pub const SUBPROTOCOL: &str = "snusnu.v1";
pub const SUBPROTOCOL_V2: &str = "snusnu.v2";
pub const MAX_V1_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub enum Error {
    InvalidUrl,
    InsecureRemoteUrl,
    InvalidBearer,
    Handshake(&'static str),
    Protocol(&'static str),
    MessageTooLarge,
    WebSocket(tungstenite::Error),
    Decode(prost::DecodeError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl => write!(f, "invalid router WebSocket URL"),
            Self::InsecureRemoteUrl => write!(f, "remote router WebSocket must use wss"),
            Self::InvalidBearer => write!(f, "invalid router bearer credential"),
            Self::Handshake(reason) => write!(f, "WebSocket handshake: {reason}"),
            Self::Protocol(reason) => write!(f, "router protocol: {reason}"),
            Self::MessageTooLarge => write!(f, "router WebSocket message exceeds limit"),
            Self::WebSocket(error) => write!(f, "WebSocket: {error}"),
            Self::Decode(error) => write!(f, "protobuf: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Whether a fresh connection may succeed without changing local
    /// configuration. A missing handler (404) may become available while the
    /// concentrator is deployed; rejected credentials must fail promptly.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::WebSocket(tungstenite::Error::Http(response)) => {
                !matches!(response.status().as_u16(), 400 | 401 | 403 | 426)
            }
            Self::WebSocket(
                tungstenite::Error::ConnectionClosed
                | tungstenite::Error::Io(_)
                | tungstenite::Error::WriteBufferFull(_),
            ) => true,
            Self::Protocol("server closed connection") => true,
            _ => false,
        }
    }
}

impl From<tungstenite::Error> for Error {
    fn from(value: tungstenite::Error) -> Self {
        Self::WebSocket(value)
    }
}

impl From<prost::DecodeError> for Error {
    fn from(value: prost::DecodeError) -> Self {
        Self::Decode(value)
    }
}

pub struct WsClient {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    max_message_bytes: usize,
    subprotocol: &'static str,
}

impl WsClient {
    /// The resolved TCP peer, useful for logging the actual upstream IP.
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        match self.socket.get_ref() {
            MaybeTlsStream::Plain(stream) => stream.peer_addr(),
            MaybeTlsStream::Rustls(stream) => stream.sock.peer_addr(),
            #[allow(unreachable_patterns)]
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "unknown WebSocket stream type",
            )),
        }
    }

    /// Connect using an HTTP Authorization header. A plaintext `ws` URL is
    /// accepted only for loopback development servers.
    pub fn connect(url: &str, bearer: &str) -> Result<(Self, wire::RouterWelcome), Error> {
        Self::connect_with_subprotocol(url, bearer, SUBPROTOCOL)
    }

    /// Connect with source-LU authenticated circuit opens. Both circuit ends
    /// must select v2 before the server will relay an LU gateway open.
    pub fn connect_v2(url: &str, bearer: &str) -> Result<(Self, wire::RouterWelcome), Error> {
        Self::connect_with_subprotocol(url, bearer, SUBPROTOCOL_V2)
    }

    pub fn subprotocol(&self) -> &'static str {
        self.subprotocol
    }

    fn connect_with_subprotocol(
        url: &str,
        bearer: &str,
        subprotocol: &'static str,
    ) -> Result<(Self, wire::RouterWelcome), Error> {
        validate_url(url)?;
        if bearer.is_empty() {
            return Err(Error::InvalidBearer);
        }
        let auth =
            HeaderValue::from_str(&format!("Bearer {bearer}")).map_err(|_| Error::InvalidBearer)?;
        let mut request = url.into_client_request().map_err(|_| Error::InvalidUrl)?;
        request.headers_mut().insert(AUTHORIZATION, auth);
        request.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(subprotocol),
        );
        let (socket, response) = connect(request)?;
        if response
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|value| value.to_str().ok())
            != Some(subprotocol)
        {
            return Err(Error::Handshake(
                "server selected a different snusnu subprotocol",
            ));
        }
        let mut client = Self {
            socket,
            max_message_bytes: MAX_V1_MESSAGE_BYTES,
            subprotocol,
        };
        client.socket.set_config(|config| {
            config.max_message_size = Some(MAX_V1_MESSAGE_BYTES);
            config.max_frame_size = Some(MAX_V1_MESSAGE_BYTES);
        });
        let welcome = match client.recv()?.body {
            Some(wire::ws_envelope::Body::Welcome(welcome)) => welcome,
            _ => return Err(Error::Protocol("first message is not RouterWelcome")),
        };
        validate_welcome(&welcome)?;
        client.max_message_bytes = welcome.max_message_bytes as usize;
        client.socket.set_config(|config| {
            config.max_message_size = Some(welcome.max_message_bytes as usize);
            config.max_frame_size = Some(welcome.max_message_bytes as usize);
        });
        Ok((client, welcome))
    }

    pub fn send(&mut self, envelope: wire::WsEnvelope) -> Result<(), Error> {
        if envelope.body.is_none() {
            return Err(Error::Protocol("empty envelope"));
        }
        let payload = envelope.encode_to_vec();
        if payload.len() > self.max_message_bytes {
            return Err(Error::MessageTooLarge);
        }
        self.socket.send(Message::Binary(payload.into()))?;
        Ok(())
    }

    pub fn recv(&mut self) -> Result<wire::WsEnvelope, Error> {
        loop {
            match self.socket.read()? {
                Message::Binary(payload) => {
                    if payload.len() > self.max_message_bytes {
                        return Err(Error::MessageTooLarge);
                    }
                    let envelope = wire::WsEnvelope::decode(payload)?;
                    if envelope.body.is_none() {
                        return Err(Error::Protocol("empty envelope"));
                    }
                    return Ok(envelope);
                }
                Message::Ping(_) | Message::Pong(_) => {
                    // Tungstenite queues Pong automatically; flush it promptly.
                    self.socket.flush()?;
                }
                Message::Close(_) => return Err(Error::Protocol("server closed connection")),
                Message::Text(_) => return Err(Error::Protocol("text message is not allowed")),
                Message::Frame(_) => return Err(Error::Protocol("unexpected raw WebSocket frame")),
            }
        }
    }

    /// Wait for one application envelope, returning `None` on an idle timeout.
    /// A partial WebSocket frame remains buffered for the next call.
    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<Option<wire::WsEnvelope>, Error> {
        self.tcp_stream()
            .set_read_timeout(Some(timeout.max(Duration::from_micros(1))))
            .map_err(|error| Error::WebSocket(tungstenite::Error::Io(error)))?;
        let result = self.recv();
        self.tcp_stream()
            .set_read_timeout(None)
            .map_err(|error| Error::WebSocket(tungstenite::Error::Io(error)))?;
        match result {
            Ok(envelope) => Ok(Some(envelope)),
            Err(Error::WebSocket(tungstenite::Error::Io(error)))
                if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn tcp_stream(&mut self) -> &mut TcpStream {
        match self.socket.get_mut() {
            MaybeTlsStream::Plain(stream) => stream,
            MaybeTlsStream::Rustls(stream) => &mut stream.sock,
            _ => unreachable!("only plain and rustls streams are enabled"),
        }
    }

    pub fn close(&mut self) -> Result<(), Error> {
        self.socket.close(None)?;
        Ok(())
    }
}

pub fn validate_welcome(welcome: &wire::RouterWelcome) -> Result<(), Error> {
    if welcome.router_id.len() != 16 || welcome.connection_epoch.len() != 16 {
        return Err(Error::Protocol("welcome UUID or epoch is not 16 bytes"));
    }
    if !(1..=80).contains(&welcome.display_name.chars().count()) {
        return Err(Error::Protocol("invalid router display name"));
    }
    let netid = welcome.allowed_netid.as_bytes();
    if netid.is_empty()
        || netid.len() > 8
        || !matches!(netid[0], b'A'..=b'Z' | b'@' | b'#' | b'$')
        || !netid
            .iter()
            .all(|value| matches!(value, b'A'..=b'Z' | b'0'..=b'9' | b'@' | b'#' | b'$'))
    {
        return Err(Error::Protocol("invalid allowed NETID"));
    }
    if welcome.max_message_bytes == 0
        || welcome.max_message_bytes as usize > MAX_V1_MESSAGE_BYTES
        || welcome.max_circuits == 0
    {
        return Err(Error::Protocol("invalid server limits"));
    }
    Ok(())
}

fn validate_url(raw: &str) -> Result<(), Error> {
    let url = Url::parse(raw).map_err(|_| Error::InvalidUrl)?;
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
        return Err(Error::InvalidUrl);
    }
    match url.scheme() {
        "wss" => Ok(()),
        "ws" if matches!(url.host_str(), Some("localhost")) => Ok(()),
        "ws" if url
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback()) =>
        {
            Ok(())
        }
        "ws" => Err(Error::InsecureRemoteUrl),
        _ => Err(Error::InvalidUrl),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn rejects_remote_plaintext_and_url_credentials() {
        assert!(matches!(
            validate_url("ws://example.com/router/v1/ws"),
            Err(Error::InsecureRemoteUrl)
        ));
        assert!(validate_url("ws://127.0.0.1/router/v1/ws").is_ok());
        assert!(validate_url("wss://example.com/router/v1/ws").is_ok());
        assert!(matches!(
            validate_url("wss://secret@example.com/router/v1/ws"),
            Err(Error::InvalidUrl)
        ));
    }

    #[test]
    fn validates_server_owned_identity_and_limits() {
        let mut welcome = wire::RouterWelcome {
            router_id: vec![1; 16],
            connection_epoch: vec![2; 16],
            max_message_bytes: MAX_V1_MESSAGE_BYTES as u32,
            max_circuits: 100,
            display_name: "Lab router".into(),
            allowed_netid: "SOLNET".into(),
        };
        assert!(validate_welcome(&welcome).is_ok());
        welcome.allowed_netid = "1BAD".into();
        assert!(matches!(
            validate_welcome(&welcome),
            Err(Error::Protocol(_))
        ));
        welcome.allowed_netid = "SOLNET".into();
        welcome.connection_epoch.pop();
        assert!(matches!(
            validate_welcome(&welcome),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn envelope_is_one_protobuf_websocket_message() {
        let envelope = wire::WsEnvelope {
            body: Some(wire::ws_envelope::Body::PublishRoutes(
                wire::RouteSnapshot {
                    epoch: vec![1; 16],
                    revision: 1,
                    routes: vec![],
                },
            )),
        };
        assert_eq!(
            wire::WsEnvelope::decode(envelope.encode_to_vec().as_slice()).unwrap(),
            envelope
        );
    }

    #[test]
    fn handshake_sends_bearer_and_subprotocol_then_receives_welcome() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut socket = tungstenite::accept_hdr(
                tcp,
                |request: &tungstenite::handshake::server::Request,
                 mut response: tungstenite::handshake::server::Response| {
                    assert_eq!(request.headers()[AUTHORIZATION], "Bearer test-token");
                    assert_eq!(request.headers()[SEC_WEBSOCKET_PROTOCOL], SUBPROTOCOL);
                    response.headers_mut().insert(
                        SEC_WEBSOCKET_PROTOCOL,
                        HeaderValue::from_static(SUBPROTOCOL),
                    );
                    Ok(response)
                },
            )
            .unwrap();
            let welcome = wire::WsEnvelope {
                body: Some(wire::ws_envelope::Body::Welcome(wire::RouterWelcome {
                    router_id: vec![7; 16],
                    connection_epoch: vec![8; 16],
                    max_message_bytes: 1024,
                    max_circuits: 16,
                    display_name: "Test router".into(),
                    allowed_netid: "SOLNET".into(),
                })),
            };
            socket
                .send(Message::Binary(welcome.encode_to_vec().into()))
                .unwrap();
            let received = socket.read().unwrap();
            let Message::Binary(payload) = received else {
                panic!("expected binary route snapshot");
            };
            let envelope = wire::WsEnvelope::decode(payload).unwrap();
            assert!(matches!(
                envelope.body,
                Some(wire::ws_envelope::Body::PublishRoutes(_))
            ));
        });
        let url = format!("ws://{address}/router/v1/ws");
        let (mut client, welcome) = WsClient::connect(&url, "test-token").unwrap();
        assert_eq!(client.peer_addr().unwrap(), address);
        assert_eq!(welcome.router_id, vec![7; 16]);
        client
            .send(wire::WsEnvelope {
                body: Some(wire::ws_envelope::Body::PublishRoutes(
                    wire::RouteSnapshot {
                        epoch: welcome.connection_epoch,
                        revision: 1,
                        routes: vec![],
                    },
                )),
            })
            .unwrap();
        server.join().unwrap();
    }

    #[test]
    fn v2_handshake_requires_explicit_v2_selection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tungstenite::accept_hdr(
                tcp,
                |request: &tungstenite::handshake::server::Request,
                 mut response: tungstenite::handshake::server::Response| {
                    assert_eq!(request.headers()[SEC_WEBSOCKET_PROTOCOL], SUBPROTOCOL_V2);
                    response.headers_mut().insert(
                        SEC_WEBSOCKET_PROTOCOL,
                        HeaderValue::from_static(SUBPROTOCOL),
                    );
                    Ok(response)
                },
            )
            .unwrap();
        });
        let url = format!("ws://{address}/router/v1/ws");
        assert!(WsClient::connect_v2(&url, "test-token").is_err());
        server.join().unwrap();
    }

    #[test]
    fn timed_receive_returns_none_then_reads_next_envelope() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut socket = tungstenite::accept_hdr(
                tcp,
                |_: &tungstenite::handshake::server::Request,
                 mut response: tungstenite::handshake::server::Response| {
                    response.headers_mut().insert(
                        SEC_WEBSOCKET_PROTOCOL,
                        HeaderValue::from_static(SUBPROTOCOL),
                    );
                    Ok(response)
                },
            )
            .unwrap();
            let welcome = wire::WsEnvelope {
                body: Some(wire::ws_envelope::Body::Welcome(wire::RouterWelcome {
                    router_id: vec![7; 16],
                    connection_epoch: vec![8; 16],
                    max_message_bytes: 1024,
                    max_circuits: 16,
                    display_name: "Test router".into(),
                    allowed_netid: "SOLNET".into(),
                })),
            };
            socket
                .send(Message::Binary(welcome.encode_to_vec().into()))
                .unwrap();
            std::thread::sleep(Duration::from_millis(50));
            let update = wire::WsEnvelope {
                body: Some(wire::ws_envelope::Body::IdentityUpdate(
                    wire::RouterIdentityUpdate {
                        display_name: "Renamed router".into(),
                    },
                )),
            };
            socket
                .send(Message::Binary(update.encode_to_vec().into()))
                .unwrap();
        });
        let url = format!("ws://{address}/router/v1/ws");
        let (mut client, _) = WsClient::connect(&url, "test-token").unwrap();
        assert!(client
            .recv_timeout(Duration::from_millis(10))
            .unwrap()
            .is_none());
        let received = client
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert!(matches!(
            received.body,
            Some(wire::ws_envelope::Body::IdentityUpdate(_))
        ));
        server.join().unwrap();
    }

    #[test]
    fn retry_policy_distinguishes_credentials_from_pending_deployment() {
        let rejection = |status| {
            Error::WebSocket(tungstenite::Error::Http(Box::new(
                tungstenite::http::Response::builder()
                    .status(status)
                    .body(None)
                    .unwrap(),
            )))
        };
        assert!(!rejection(401).is_retryable());
        assert!(!rejection(403).is_retryable());
        assert!(rejection(404).is_retryable());
        assert!(rejection(503).is_retryable());
    }
}
