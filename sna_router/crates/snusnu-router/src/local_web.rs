//! Embedded, local read-only status UI. It uses the same observation snapshot
//! as the router and never makes concentrator policy decisions.

use crate::{config::WebConfig, local_status::LocalStatus, STOP};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const INDEX: &str = include_str!("../assets/index.html");
const LOGIN: &str = include_str!("../assets/login.html");
const APP_JS: &str = include_str!("../assets/app.js");
const LOGIN_JS: &str = include_str!("../assets/login.js");
const CSS: &str = include_str!("../assets/style.css");
const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 4 * 1024;
const MAX_CONNECTIONS: usize = 32;
const SESSION_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);

struct Request {
    method: String,
    path: String,
    cookie: Option<String>,
    body: Vec<u8>,
}

#[derive(Default)]
struct Sessions {
    tokens: HashMap<String, Instant>,
}

impl Sessions {
    fn accepts(&mut self, cookie: Option<&str>) -> bool {
        let Some(token) = cookie.and_then(session_cookie) else {
            return false;
        };
        let now = Instant::now();
        self.tokens.retain(|_, expiry| *expiry > now);
        self.tokens.get(token).is_some_and(|expiry| *expiry > now)
    }

    fn create(&mut self) -> io::Result<String> {
        let mut random = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let mut token = String::with_capacity(64);
        for byte in random {
            use std::fmt::Write as _;
            write!(&mut token, "{byte:02x}").expect("hex token write");
        }
        let now = Instant::now();
        self.tokens.retain(|_, expiry| *expiry > now);
        if self.tokens.len() >= 64 {
            if let Some(oldest) = self
                .tokens
                .iter()
                .min_by_key(|(_, expiry)| *expiry)
                .map(|(token, _)| token.clone())
            {
                self.tokens.remove(&oldest);
            }
        }
        self.tokens.insert(token.clone(), now + SESSION_LIFETIME);
        Ok(token)
    }

    fn remove(&mut self, cookie: Option<&str>) {
        if let Some(token) = cookie.and_then(session_cookie) {
            self.tokens.remove(token);
        }
    }
}

/// Bind synchronously so a bad listen address fails router startup instead
/// of silently losing the UI. The server thread ends with the router STOP flag.
pub(crate) fn start(config: &WebConfig, status: LocalStatus) -> io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(config.listen)?;
    listener.set_nonblocking(true)?;
    let listen = listener.local_addr()?;
    let password = Arc::<str>::from(config.password.as_str());
    let sessions = Arc::new(Mutex::new(Sessions::default()));
    let active = Arc::new(AtomicUsize::new(0));
    tracing::info!(listen = %listen, authentication = !password.is_empty(), "local web UI listening");
    thread::Builder::new()
        .name("snusnu-local-web".to_owned())
        .spawn(move || {
            while !STOP.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        if active.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
                            active.fetch_sub(1, Ordering::Relaxed);
                            drop(stream);
                            continue;
                        }
                        let status = status.clone();
                        let password = password.clone();
                        let sessions = sessions.clone();
                        let active_for_handler = active.clone();
                        if let Err(error) = thread::Builder::new()
                            .name("snusnu-web-request".to_owned())
                            .spawn(move || {
                                if let Err(error) = handle_connection(stream, &password, &sessions, &status) {
                                    tracing::debug!(peer = %peer, error = %error, "local web request failed");
                                }
                                active_for_handler.fetch_sub(1, Ordering::Relaxed);
                            })
                        {
                            tracing::warn!(error = %error, "local web request thread failed");
                            // Spawn failed before the closure could decrement the count.
                            // The closure has been dropped with its captures.
                            // This branch is rare, but keep accepting requests.
                            active.fetch_sub(1, Ordering::Relaxed);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "local web accept failed");
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        })
}

fn handle_connection(
    mut stream: TcpStream,
    password: &str,
    sessions: &Mutex<Sessions>,
    status: &LocalStatus,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = match read_request(&mut stream) {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(error) => {
            response(
                &mut stream,
                "400 Bad Request",
                "text/plain; charset=utf-8",
                b"Bad request",
                &[],
            )?;
            return Err(error);
        }
    };
    let auth_required = !password.is_empty();
    let authorized = !auth_required
        || sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .accepts(request.cookie.as_deref());
    let path = request.path.split('?').next().unwrap_or("");
    match (request.method.as_str(), path) {
        ("GET", "/assets/style.css") => response(
            &mut stream,
            "200 OK",
            "text/css; charset=utf-8",
            CSS.as_bytes(),
            &[],
        ),
        ("GET", "/assets/app.js") => response(
            &mut stream,
            "200 OK",
            "text/javascript; charset=utf-8",
            APP_JS.as_bytes(),
            &[],
        ),
        ("GET", "/assets/login.js") => response(
            &mut stream,
            "200 OK",
            "text/javascript; charset=utf-8",
            LOGIN_JS.as_bytes(),
            &[],
        ),
        ("GET", "/api/auth") => response(
            &mut stream,
            "200 OK",
            "application/json; charset=utf-8",
            if auth_required {
                b"{\"required\":true}"
            } else {
                b"{\"required\":false}"
            },
            &[],
        ),
        ("GET", "/login") if auth_required && authorized => redirect(&mut stream, "/", None),
        ("GET", "/login") if auth_required => response(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            LOGIN.as_bytes(),
            &[],
        ),
        ("POST", "/login") if auth_required => {
            let entered = form_password(&request.body).unwrap_or_default();
            if constant_time_eq(entered.as_bytes(), password.as_bytes()) {
                let token = sessions
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .create()?;
                redirect(
                    &mut stream,
                    "/",
                    Some(format!(
                        "snusnu_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200"
                    )),
                )
            } else {
                tracing::warn!("local web sign-in rejected");
                thread::sleep(Duration::from_millis(200));
                redirect(&mut stream, "/login?error=1", None)
            }
        }
        ("GET", "/login") => redirect(&mut stream, "/", None),
        ("POST", "/logout") if auth_required => {
            sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(request.cookie.as_deref());
            redirect(
                &mut stream,
                "/login",
                Some("snusnu_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".into()),
            )
        }
        (
            "GET",
            "/"
            | "/peers"
            | "/addresses"
            | "/circuits"
            | "/concentrator"
            | "/routes"
            | "/concentrator/routes",
        ) if !authorized => redirect(&mut stream, "/login", None),
        (
            "GET",
            "/"
            | "/peers"
            | "/addresses"
            | "/circuits"
            | "/concentrator"
            | "/routes"
            | "/concentrator/routes",
        ) => response(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            INDEX.as_bytes(),
            &[],
        ),
        ("GET", "/api/status" | "/api/view" | "/api/routes") if !authorized => response(
            &mut stream,
            "401 Unauthorized",
            "application/json; charset=utf-8",
            b"{\"error\":\"authentication required\"}",
            &[],
        ),
        ("GET", "/api/status") => {
            let snapshot = status.snapshot();
            let body = serde_json::to_vec(&snapshot)?;
            response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &body,
                &[],
            )
        }
        ("GET", "/api/view") => {
            let body = serde_json::to_vec(&status.view())?;
            response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &body,
                &[],
            )
        }
        ("GET", "/api/routes") => {
            if let Some((query, page, per_page)) = route_query(&request.path) {
                let body = serde_json::to_vec(&status.route_page(&query, page, per_page))?;
                response(
                    &mut stream,
                    "200 OK",
                    "application/json; charset=utf-8",
                    &body,
                    &[],
                )
            } else {
                response(
                    &mut stream,
                    "400 Bad Request",
                    "application/json; charset=utf-8",
                    b"{\"error\":\"invalid route query\"}",
                    &[],
                )
            }
        }
        ("GET", "/healthz") => response(&mut stream, "200 OK", "text/plain", b"ok", &[]),
        ("GET" | "POST", _) => response(
            &mut stream,
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"Not found",
            &[],
        ),
        _ => response(
            &mut stream,
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            b"Method not allowed",
            &[],
        ),
    }
}

fn route_query(path: &str) -> Option<(String, usize, usize)> {
    let mut query = String::new();
    let mut page = 1;
    let mut per_page = 25;
    if let Some((_, parameters)) = path.split_once('?') {
        for parameter in parameters.split('&') {
            let (key, value) = parameter.split_once('=').unwrap_or((parameter, ""));
            match key {
                "q" => {
                    query = url_decode(value)?;
                    if query.len() > 128 {
                        return None;
                    }
                }
                "page" => {
                    page = value.parse().ok()?;
                    if page == 0 || page > 1_000_000 {
                        return None;
                    }
                }
                "per_page" => {
                    per_page = value.parse().ok()?;
                    if !(1..=100).contains(&per_page) {
                        return None;
                    }
                }
                "" => {}
                _ => return None,
            }
        }
    }
    Some((query, page, per_page))
}

fn url_decode(value: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => decoded.push(b' '),
            b'%' => {
                let high = (bytes.next()? as char).to_digit(16)? as u8;
                let low = (bytes.next()? as char).to_digit(16)? as u8;
                decoded.push(high << 4 | low);
            }
            other => decoded.push(other),
        }
    }
    String::from_utf8(decoded).ok()
}

fn read_request(stream: &mut TcpStream) -> io::Result<Option<Request>> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break end + 4;
        }
        if bytes.len() >= MAX_HEADER {
            return Err(invalid("request headers too large"));
        }
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            if bytes.is_empty() {
                return Ok(None);
            }
            return Err(invalid("incomplete HTTP headers"));
        }
        bytes.extend_from_slice(&chunk[..count]);
    };
    if header_end > MAX_HEADER {
        return Err(invalid("request headers too large"));
    }
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| invalid("HTTP headers are not UTF-8"))?;
    let mut lines = header[..header.len() - 4].split("\r\n");
    let first = lines
        .next()
        .ok_or_else(|| invalid("missing request line"))?;
    let mut words = first.split_ascii_whitespace();
    let method = words.next().ok_or_else(|| invalid("missing method"))?;
    let path = words.next().ok_or_else(|| invalid("missing path"))?;
    let version = words
        .next()
        .ok_or_else(|| invalid("missing HTTP version"))?;
    if words.next().is_some()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || !path.starts_with('/')
        || path.contains("..")
    {
        return Err(invalid("invalid request line"));
    }
    let mut cookie = None;
    let mut content_length = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("invalid HTTP header"))?;
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("Cookie") {
            cookie = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("Content-Length") {
            if content_length.is_some() {
                return Err(invalid("duplicate Content-Length"));
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| invalid("invalid Content-Length"))?,
            );
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(invalid("chunked requests are not supported"));
        }
    }
    let length = content_length.unwrap_or(0);
    if length > MAX_BODY {
        return Err(invalid("request body too large"));
    }
    let mut body = bytes[header_end..].to_vec();
    if body.len() > length {
        body.truncate(length);
    }
    while body.len() < length {
        let limit = chunk.len().min(length - body.len());
        let count = stream.read(&mut chunk[..limit])?;
        if count == 0 {
            return Err(invalid("incomplete request body"));
        }
        body.extend_from_slice(&chunk[..count]);
    }
    Ok(Some(Request {
        method: method.to_owned(),
        path: path.to_owned(),
        cookie,
        body,
    }))
}

fn response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    extra: &[(&str, String)],
) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; form-action 'self'\r\n", body.len())?;
    for (name, value) in extra {
        write!(stream, "{name}: {value}\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(body)
}

fn redirect(stream: &mut TcpStream, location: &str, cookie: Option<String>) -> io::Result<()> {
    let mut headers = vec![("Location", location.to_owned())];
    if let Some(cookie) = cookie {
        headers.push(("Set-Cookie", cookie));
    }
    response(stream, "303 See Other", "text/plain", b"", &headers)
}

fn session_cookie(header: &str) -> Option<&str> {
    header
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| {
            if name == "snusnu_session"
                && value.len() == 64
                && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                Some(value)
            } else {
                None
            }
        })
}

fn form_password(body: &[u8]) -> Option<String> {
    let form = std::str::from_utf8(body).ok()?;
    let value = form
        .split('&')
        .filter_map(|part| part.split_once('='))
        .find_map(|(key, value)| (key == "password").then_some(value))?;
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => decoded.push(b' '),
            b'%' => {
                let high = (bytes.next()? as char).to_digit(16)? as u8;
                let low = (bytes.next()? as char).to_digit(16)? as u8;
                decoded.push(high << 4 | low);
            }
            other => decoded.push(other),
        }
    }
    String::from_utf8(decoded).ok()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..max {
        diff |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    diff == 0
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Shutdown;

    fn exchange(request: &str, sessions: &Mutex<Sessions>, status: &LocalStatus) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        thread::scope(|scope| {
            let worker = scope.spawn(|| handle_connection(server, "test secret", sessions, status));
            client.write_all(request.as_bytes()).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let mut reply = String::new();
            client.read_to_string(&mut reply).unwrap();
            worker.join().unwrap().unwrap();
            reply
        })
    }

    #[test]
    fn password_form_round_trips_special_characters_without_a_username() {
        assert_eq!(
            form_password(b"password=a%2Bb+c%26d"),
            Some("a+b c&d".into())
        );
        assert!(form_password(b"username=x").is_none());
        assert!(!constant_time_eq(b"secret", b"secret\0"));
        assert!(constant_time_eq(b"secret", b"secret"));
    }

    #[test]
    fn cookie_requires_exact_session_name_and_shape() {
        let token = "a".repeat(64);
        assert_eq!(
            session_cookie(&format!("other=1; snusnu_session={token}")),
            Some(token.as_str())
        );
        assert!(session_cookie("snusnu_session=short").is_none());
        assert!(session_cookie(&format!("other_session={token}")).is_none());
    }

    #[test]
    fn status_requires_password_cookie_and_login_issues_one() {
        let status = LocalStatus::new();
        let sessions = Mutex::new(Sessions::default());
        let denied = exchange(
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &sessions,
            &status,
        );
        assert!(denied.starts_with("HTTP/1.1 401 Unauthorized\r\n"));

        let body = "password=test+secret";
        let login = exchange(
            &format!(
                "POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
            &sessions,
            &status,
        );
        assert!(login.starts_with("HTTP/1.1 303 See Other\r\n"));
        let cookie = login
            .lines()
            .find_map(|line| line.strip_prefix("Set-Cookie: "))
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let accepted = exchange(
            &format!("GET /api/status HTTP/1.1\r\nHost: localhost\r\nCookie: {cookie}\r\n\r\n"),
            &sessions,
            &status,
        );
        assert!(accepted.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(accepted.contains("\"local_peers\":[]"));
    }

    #[test]
    fn route_query_accepts_search_and_rejects_unbounded_pages() {
        assert_eq!(route_query("/api/routes"), Some((String::new(), 1, 25)));
        assert_eq!(
            route_query("/api/routes?q=NETA%2eCPA&page=2&per_page=50"),
            Some(("NETA.CPA".into(), 2, 50))
        );
        assert!(route_query("/api/routes?page=0").is_none());
        assert!(route_query("/api/routes?per_page=101").is_none());
        assert!(route_query("/api/routes?q=%zz").is_none());
    }
}
