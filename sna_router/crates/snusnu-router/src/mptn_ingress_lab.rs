//! Explicit, single-association-at-a-time TCP62 management ingress diagnostic.
//! Production routing never constructs this listener. User Connects and every
//! UDP/397 datagram fail closed; no native or WebSocket user route is opened.

use std::{
    fs::File,
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

use transport_ip_sna::{
    mptn_compensations::CompensationSet,
    mptn_ingress::{IngressKind, IngressPolicy, IngressSession},
    mptn_management_responder::{ManagementResponder, V5Options},
    mptn_reverse_management::classify_reverse_management_connect,
};

use crate::STOP;

const RECORD_LIMIT: usize = 4096;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(20);

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn check_udp(udp: &UdpSocket) -> io::Result<()> {
    let mut bytes = [0u8; 2048];
    match udp.recv_from(&mut bytes) {
        Ok((len, from)) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("experimental TCP62 ingress rejects UDP/397 from {from}, {len} bytes"),
        )),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error),
    }
}

fn read_exact_checked(stream: &mut TcpStream, udp: &UdpSocket, bytes: &mut [u8]) -> io::Result<()> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut offset = 0;
    while offset < bytes.len() {
        if STOP.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "router stopped"));
        }
        check_udp(udp)?;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TCP62 management read timed out",
            ));
        }
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TCP62 peer closed early",
                ))
            }
            Ok(n) => offset += n,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_record(stream: &mut TcpStream, udp: &UdpSocket) -> io::Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    read_exact_checked(stream, udp, &mut prefix)?;
    let len = u32::from_be_bytes(prefix) as usize;
    if !(5..=RECORD_LIMIT).contains(&len) {
        return Err(invalid("TCP62 management record length outside bound"));
    }
    let mut bytes = vec![0u8; len];
    bytes[..4].copy_from_slice(&prefix);
    read_exact_checked(stream, udp, &mut bytes[4..])?;
    Ok(bytes)
}

fn write_record(stream: &mut TcpStream, udp: &UdpSocket, bytes: &[u8]) -> io::Result<()> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut offset = 0;
    while offset < bytes.len() {
        if STOP.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "router stopped"));
        }
        check_udp(udp)?;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TCP62 management write timed out",
            ));
        }
        match stream.write(&bytes[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TCP62 write stopped",
                ))
            }
            Ok(n) => offset += n,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn serve(mut stream: TcpStream, udp: &UdpSocket, peer_lu: &str, local_lu: &str) -> io::Result<()> {
    stream.set_read_timeout(Some(POLL))?;
    stream.set_write_timeout(Some(POLL))?;
    let available =
        CompensationSet::from_codes(&[0, 1, 3, 0x10, 0x20, 0x83]).map_err(io::Error::other)?;
    let mut ingress = IngressSession::new(IngressPolicy {
        source_lu: peer_lu.to_owned(),
        destination_lu: local_lu.to_owned(),
        user_mode: None,
        allow_blank_user_mode: false,
        // X'83' is acknowledged only in this explicit diagnostic. Any UDP
        // datagram aborts the association; production remains disabled.
        available_compensations: available,
        forbidden_fqpcid: None,
    })?;
    let connect = read_record(&mut stream, udp)?;
    let offer = ingress.receive(&connect)?;
    if offer.kind() != &IngressKind::Management {
        return Err(invalid(
            "user TCP62 Connect requires an unimplemented native route",
        ));
    }
    let admitted =
        classify_reverse_management_connect(offer.connect().clone(), peer_lu, local_lu, None)?;
    let mut entropy = [0u8; 4];
    File::open("/dev/urandom")?.read_exact(&mut entropy)?;
    if entropy == [0; 4] {
        return Err(invalid("management response token entropy was zero"));
    }
    let token = [
        0x23, entropy[0], entropy[1], entropy[2], entropy[3], 0x80, 0,
    ];
    let mut responder = ManagementResponder::new(
        &admitted,
        available,
        V5Options {
            son_handler: false,
            keepalive_handler: false,
        },
        token,
        "",
        8,
    )?;
    tracing::info!(peer_lu, local_lu, fqpcid = ?admitted.fqpcid(), "inbound TCP62 management BIND admitted");
    let positive = responder.connect_response().to_vec();
    write_record(&mut stream, udp, &positive)?;
    responder.mark_connect_response_sent(&positive)?;
    let cnos = responder.accept_cnos(&read_record(&mut stream, udp)?)?;
    write_record(&mut stream, udp, &cnos)?;
    responder.mark_cnos_reply_sent(&cnos)?;
    let bis = responder.accept_bis(&read_record(&mut stream, udp)?)?;
    write_record(&mut stream, udp, &bis)?;
    responder.mark_bis_reply_sent(&bis)?;
    responder.accept_unbind(&read_record(&mut stream, udp)?)?;
    check_udp(udp)?;
    stream.shutdown(Shutdown::Both)?;
    responder.mark_close_sent()?;
    tracing::info!(
        peer_lu,
        local_lu,
        "inbound TCP62 management CNOS completed and socket closed"
    );
    Ok(())
}

pub fn run(local_ip: Ipv4Addr, peer_ip: Ipv4Addr, peer_lu: &str, local_lu: &str) -> io::Result<()> {
    // Validate policy before opening sockets. This does not accept a user
    // route and cannot be selected through --config.
    IngressSession::new(IngressPolicy {
        source_lu: peer_lu.to_owned(),
        destination_lu: local_lu.to_owned(),
        user_mode: None,
        allow_blank_user_mode: false,
        available_compensations: CompensationSet::default(),
        forbidden_fqpcid: None,
    })?;
    let udp = UdpSocket::bind(SocketAddr::new(local_ip.into(), 397))?;
    udp.set_nonblocking(true)?;
    let listener = TcpListener::bind(SocketAddr::new(local_ip.into(), 397))?;
    listener.set_nonblocking(true)?;
    tracing::warn!(local_ip = %local_ip, peer_ip = %peer_ip, peer_lu, local_lu, "experimental inbound TCP62 management listener on port 397");
    while !STOP.load(Ordering::Relaxed) {
        check_udp(&udp)?;
        match listener.accept() {
            Ok((stream, from)) if from.ip() == peer_ip => {
                tracing::info!(remote = %from, "inbound TCP62 association accepted");
                if let Err(error) = serve(stream, &udp, peer_lu, local_lu) {
                    tracing::warn!(remote = %from, error = %error, "inbound TCP62 association rejected");
                }
            }
            Ok((stream, from)) => {
                let _ = stream.shutdown(Shutdown::Both);
                tracing::warn!(remote = %from, expected_ip = %peer_ip, "inbound TCP62 peer IP rejected");
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::cnos::{CnosGds, Service};
    use transport_ip_sna::{
        mptn_bind_negotiation::validate_positive_response, mptn_connect::Connect,
        mptn_management_initiator::ManagementInitiator,
    };

    fn client_record(stream: &mut TcpStream) -> Vec<u8> {
        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix).unwrap();
        let len = u32::from_be_bytes(prefix) as usize;
        assert!(len <= RECORD_LIMIT);
        let mut bytes = vec![0u8; len];
        bytes[..4].copy_from_slice(&prefix);
        stream.read_exact(&mut bytes[4..]).unwrap();
        bytes
    }

    fn closed_without_data(result: io::Result<usize>) -> bool {
        match result {
            Ok(0) => true,
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => true,
            _ => false,
        }
    }

    #[test]
    fn loopback_management_finishes_but_no_user_route_is_opened() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve(stream, &udp, "QABOB.SNAB", "QAALICE.SNAA")
        });
        let mut client = TcpStream::connect(listen_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let source = [0xd8, 0xc1, 0xc2, 0xd6, 0xc2, 0x4b, 0xe2, 0xd5, 0xc1, 0xc2];
        let mut fqpcid = vec![0x60, 19];
        fqpcid.extend_from_slice(&[0x22; 8]);
        fqpcid.push(10);
        fqpcid.extend_from_slice(&source);
        let initiator = ManagementInitiator::new(
            "QABOB.SNAB",
            "QAALICE.SNAA",
            fqpcid.clone(),
            [0x11; 8],
            [0x23, 0x11, 0x11, 0x11, 0x11, 0x80, 0],
            "",
            8,
        )
        .unwrap();
        client.write_all(initiator.connect_request()).unwrap();
        let positive = Connect::decode(&client_record(&mut client)).unwrap();
        assert_eq!(positive.options[2].value, [0]);
        assert_eq!(positive.options[4].value, [0]);
        assert_eq!(
            validate_positive_response(
                Connect::decode(initiator.connect_request())
                    .unwrap()
                    .connection_data(),
                positive.connection_data(),
            ),
            Ok(())
        );
        let cnos = CnosGds {
            service: Service::Request,
            modifier: 0,
            session_limit: 8,
            source_winners: 4,
            target_winners: 4,
            mode: String::new(),
            mode_field_length: 8,
        };
        let mut body = vec![
            0, 1, 0x0b, 0x90, 0x20, 12, 5, 2, 0xff, 0, 3, 0xd0, 0, 0, 2, 6, 0xf1,
        ];
        body.extend_from_slice(&cnos.encode().unwrap());
        let mut cnos_record = Vec::new();
        cnos_record.extend_from_slice(&((5 + body.len()) as u32).to_be_bytes());
        cnos_record.push(0);
        cnos_record.extend_from_slice(&body);
        client.write_all(&cnos_record).unwrap();
        let cnos_reply = client_record(&mut client);
        assert_eq!(cnos_reply.len(), 35);
        assert_eq!(
            CnosGds::decode(&cnos_reply[10..]).unwrap().service,
            Service::AcceptedPending
        );
        client.write_all(&BIS_REQUEST_FOR_TEST).unwrap();
        assert_eq!(client_record(&mut client), BIS_REPLY_FOR_TEST);
        let mut unbind = vec![0; 4];
        unbind.push(0x10);
        unbind.extend_from_slice(&[0, 0, 0x6b, 0x80, 0, 0x32, 1, 0, 0, 0, 0]);
        unbind.extend_from_slice(&fqpcid);
        let unbind_len = unbind.len() as u32;
        unbind[..4].copy_from_slice(&unbind_len.to_be_bytes());
        client.write_all(&unbind).unwrap();
        let mut tail = [0u8; 1];
        assert_eq!(client.read(&mut tail).unwrap(), 0);
        assert!(server.join().unwrap().is_ok());
    }

    #[test]
    fn valid_shape_user_bind_receives_no_positive_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve(stream, &udp, "QABOB.SNAB", "QAALICE.SNAA")
        });
        let source = [0xd8, 0xc1, 0xc2, 0xd6, 0xc2, 0x4b, 0xe2, 0xd5, 0xc1, 0xc2];
        let mut fqpcid = vec![0x60, 19];
        fqpcid.extend_from_slice(&[0x22; 8]);
        fqpcid.push(10);
        fqpcid.extend_from_slice(&source);
        let management = ManagementInitiator::new(
            "QABOB.SNAB",
            "QAALICE.SNAA",
            fqpcid,
            [0x11; 8],
            [0x23, 0x11, 0x11, 0x11, 0x11, 0x80, 0],
            "",
            8,
        )
        .unwrap();
        let mut user = Connect::decode(management.connect_request()).unwrap();
        let data = &mut user.options[1].value;
        data[5..32].copy_from_slice(&[
            0x31, 0, 0x13, 7, 0xb0, 0xb0, 0x51, 0x33, 3, 0x83, 0x8c, 0x8c, 0x83, 3, 6, 2, 0, 0, 0,
            0, 0, 0, 0, 0x94, 0x43, 0, 0,
        ]);
        let user_start = 5 + 27 + 1 + source.len() + 1;
        data[user_start + 3..user_start + 11].fill(0x40);
        data[user_start + 19] = 0;
        data[user_start + 32 + source.len()] = 0;
        let tail = data.len() - 12;
        data[tail + 2] = 1;
        let mut client = TcpStream::connect(listen_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(&user.encode().unwrap()).unwrap();
        let mut one = [0u8; 1];
        assert!(closed_without_data(client.read(&mut one)));
        assert!(server.join().unwrap().is_err());
    }

    #[test]
    fn udp_397_packet_aborts_pending_management_without_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_addr = udp.local_addr().unwrap();
        udp.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve(stream, &udp, "QABOB.SNAB", "QAALICE.SNAA")
        });
        let mut client = TcpStream::connect(listen_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(&[0, 0]).unwrap(); // incomplete Connect
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(&[0, 0, 0, 5, 0x83], udp_addr).unwrap();
        let mut one = [0u8; 1];
        assert!(closed_without_data(client.read(&mut one)));
        let error = server.join().unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    const BIS_REQUEST_FOR_TEST: [u8; 11] = [0, 0, 0, 11, 0, 0, 2, 0x4b, 0x90, 0, 0x70];
    const BIS_REPLY_FOR_TEST: [u8; 11] = [0, 0, 0, 11, 0, 0, 2, 0x4b, 0xb0, 0, 0x70];
}
