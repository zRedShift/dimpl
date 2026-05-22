//! Auto-negotiation handshake integration tests.
//!
//! Tests the `Dtls::new_auto()` + `set_active(true)` (client) path against
//! explicit DTLS 1.2, DTLS 1.3, and auto-sense servers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Dtls, Error, Output};

use crate::common::*;

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls13_server() {
    //! An auto-sensing client should complete a full handshake against an
    //! explicit DTLS 1.3 server.
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);
    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(
        client_connected,
        "Auto client should connect to DTLS 1.3 server"
    );
    assert!(
        server_connected,
        "DTLS 1.3 server should connect to auto client"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls13_server_keying_material() {
    //! Verify that an auto-client and DTLS 1.3 server derive identical
    //! SRTP keying material.
    use dimpl::SrtpProfile;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);
    let mut client_km: Option<(Vec<u8>, SrtpProfile)> = None;
    let mut server_km: Option<(Vec<u8>, SrtpProfile)> = None;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if let Some(km) = client_out.keying_material {
            client_km = Some(km);
        }
        if let Some(km) = server_out.keying_material {
            server_km = Some(km);
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_km.is_some() && server_km.is_some() {
            break;
        }

        now += Duration::from_millis(10);
    }

    let client_km = client_km.expect("Client should have keying material");
    let server_km = server_km.expect("Server should have keying material");

    assert_eq!(
        client_km.0, server_km.0,
        "Client and server keying material should match"
    );
    assert_eq!(
        client_km.1, server_km.1,
        "Client and server SRTP profile should match"
    );
    assert!(
        !client_km.0.is_empty(),
        "Keying material should not be empty"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_auto_server() {
    //! Both sides use auto-sense. They should negotiate DTLS 1.3 (the
    //! hybrid CH includes supported_versions with DTLS 1.3 first).
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_auto(config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(
        client_connected,
        "Auto client should connect to auto server"
    );
    assert!(
        server_connected,
        "Auto server should connect to auto client"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls12_server() {
    //! An auto-sensing client against an explicit DTLS 1.2 server.
    //! The server sends HelloVerifyRequest, triggering the 1.2 fork.
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(
        client_connected,
        "Auto client should connect to DTLS 1.2 server"
    );
    assert!(
        server_connected,
        "DTLS 1.2 server should connect to auto client"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls12_server_keying_material() {
    //! Verify that an auto-client and DTLS 1.2 server derive identical
    //! SRTP keying material after HVR-based version negotiation.
    use dimpl::SrtpProfile;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

    let mut client_km: Option<(Vec<u8>, SrtpProfile)> = None;
    let mut server_km: Option<(Vec<u8>, SrtpProfile)> = None;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if let Some(km) = client_out.keying_material {
            client_km = Some(km);
        }
        if let Some(km) = server_out.keying_material {
            server_km = Some(km);
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_km.is_some() && server_km.is_some() {
            break;
        }

        now += Duration::from_millis(10);
    }

    let client_km = client_km.expect("Client should have keying material");
    let server_km = server_km.expect("Server should have keying material");

    assert_eq!(
        client_km.0, server_km.0,
        "Client and server keying material should match"
    );
    assert_eq!(
        client_km.1, server_km.1,
        "Client and server SRTP profile should match"
    );
    assert!(
        !client_km.0.is_empty(),
        "Keying material should not be empty"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls13_server_application_data() {
    //! After handshake, auto-client and DTLS 1.3 server can exchange
    //! application data in both directions.
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);
    let mut client_connected = false;
    let mut server_connected = false;

    // Complete the handshake
    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(
        client_connected && server_connected,
        "Handshake should complete"
    );

    // Send data client -> server
    let msg = b"hello from auto client";
    client.send_application_data(msg).expect("client send");
    now += Duration::from_millis(10);
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);
    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d == msg),
        "Server should receive client's application data"
    );

    // Send data server -> client
    let reply = b"hello from server";
    server.send_application_data(reply).expect("server send");
    now += Duration::from_millis(10);
    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    deliver_packets(&server_out.packets, &mut client);
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    assert!(
        client_out.app_data.iter().any(|d| d == reply),
        "Client should receive server's application data"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls12_server_no_cookie() {
    //! An auto-sensing client against a DTLS 1.2 server that skips
    //! HelloVerifyRequest (use_server_cookie = false). The server sends
    //! ServerHello directly.
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let client_config = default_config();
    let server_config = no_cookie_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(
        client_connected,
        "Auto client should connect to DTLS 1.2 server (no cookie)"
    );
    assert!(
        server_connected,
        "DTLS 1.2 server (no cookie) should connect to auto client"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls13_server_no_cookie() {
    //! An auto-sensing client against a DTLS 1.3 server that skips
    //! HelloRetryRequest cookie exchange (use_server_cookie = false).
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let client_config = default_config();
    let server_config = no_cookie_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(server_config, server_cert, now);
    server.set_active(false);
    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(
        client_connected,
        "Auto client should connect to DTLS 1.3 server (no cookie)"
    );
    assert!(
        server_connected,
        "DTLS 1.3 server (no cookie) should connect to auto client"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls13_server_no_cookie_coalesced_server_flight_progresses_without_retransmit() {
    //! The auto client must process a no-cookie DTLS 1.3 server flight where
    //! plaintext ServerHello is followed by short-header encrypted records in
    //! the same UDP datagram. Progress must not depend on a later server
    //! retransmission.
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let client_config = default_config();
    let server_config = no_cookie_config();

    let now = Instant::now();

    let mut client = Dtls::new_auto(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(server_config, server_cert, now);
    server.set_active(false);

    client.handle_timeout(now).expect("client timeout");
    server.handle_timeout(now).expect("server timeout");
    let client_out = drain_outputs(&mut client);
    assert!(
        !client_out.packets.is_empty(),
        "client should emit initial ClientHello"
    );
    deliver_packets(&client_out.packets, &mut server);

    let server_out = drain_outputs(&mut server);
    let server_flight = coalesced_server_flight(&server_out.packets);
    assert!(
        packet_has_plaintext_server_hello_then_ciphertext_tail(&server_flight),
        "test must deliver a coalesced ServerHello + encrypted tail flight"
    );

    client
        .handle_packet(&server_flight)
        .expect("client should accept coalesced server flight");
    let client_out = drain_outputs(&mut client);

    assert!(
        !client_out.packets.is_empty(),
        "client should answer the first coalesced server flight without waiting for retransmit"
    );
}

fn coalesced_server_flight(packets: &[Vec<u8>]) -> Vec<u8> {
    if let Some(packet) = packets
        .iter()
        .find(|packet| packet_has_plaintext_server_hello_then_ciphertext_tail(packet))
    {
        return packet.clone();
    }

    let mut combined = Vec::new();
    for packet in packets {
        combined.extend_from_slice(packet);
    }
    combined
}

fn packet_has_plaintext_server_hello_then_ciphertext_tail(mut packet: &[u8]) -> bool {
    let mut saw_server_hello = false;

    while !packet.is_empty() {
        if packet[0] & 0b1110_0000 == 0b0010_0000 {
            return saw_server_hello;
        }

        if packet.len() < 13 {
            return false;
        }

        let record_len = u16::from_be_bytes([packet[11], packet[12]]) as usize;
        let Some(record_end) = 13usize.checked_add(record_len) else {
            return false;
        };
        let Some(record_body) = packet.get(13..record_end) else {
            return false;
        };

        if packet[0] == 0x16 && record_body.first() == Some(&2) {
            saw_server_hello = true;
        }

        packet = &packet[record_end..];
    }

    false
}

/// Auto-sense client defers the hybrid ClientHello when the poll buffer
/// is too small, and emits it on the next poll with a large enough buffer.
#[test]
#[cfg(feature = "rcgen")]
fn auto_client_poll_output_undersized_buffer() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let cert = generate_self_signed_certificate().expect("gen cert");
    let config = default_config();

    let now = Instant::now();
    let mut client = Dtls::new_auto(config, cert, now);
    client.set_active(true);

    // Trigger the hybrid ClientHello
    client.handle_timeout(now).expect("handle_timeout");

    // Poll with a buffer that is too small for the wire packet.
    // Before the fix this would panic with an index-out-of-bounds.
    let mut tiny_buf = [0u8; 4];
    let tiny_len = tiny_buf.len();
    let output = client.poll_output(&mut tiny_buf);

    // Should return BufferTooSmall (packet deferred), not a Packet or Timeout.
    assert!(
        matches!(output, Output::BufferTooSmall { needed } if needed > tiny_len),
        "undersized buffer should yield BufferTooSmall, got: {output:?}"
    );

    // Now poll with a large buffer — the deferred packet should come through.
    let mut big_buf = vec![0u8; 2048];
    let output = client.poll_output(&mut big_buf);
    assert!(
        matches!(output, Output::Packet(_)),
        "large buffer should yield Packet, got: {output:?}"
    );
}

/// Auto-sense client returns an error when the server response cannot be
/// identified as any known DTLS version.
#[test]
#[cfg(feature = "rcgen")]
fn auto_client_rejects_unknown_version_response() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let cert = generate_self_signed_certificate().expect("gen cert");
    let config = default_config();

    let now = Instant::now();
    let mut client = Dtls::new_auto(config, cert, now);
    client.set_active(true);

    // Trigger the hybrid ClientHello
    client.handle_timeout(now).expect("handle_timeout");
    drain_outputs(&mut client);

    // Feed a garbage "server response" that won't parse as any known version.
    // server_hello_version returns Unknown for non-handshake content types.
    let garbage = vec![0xFF, 0x00, 0x01, 0x02];
    let result = client.handle_packet(&garbage);

    assert!(
        result.is_err(),
        "Unknown version response should be an error"
    );
    match result.unwrap_err() {
        Error::UnexpectedMessage(msg) => assert!(
            msg.contains("Unrecognized"),
            "error should mention unrecognized: {msg}"
        ),
        other => panic!("expected UnexpectedMessage, got: {other:?}"),
    }
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_protocol_version_after_negotiating_dtls13() {
    //! After completing a handshake against a DTLS 1.3 server, the
    //! auto-sense client should report `Some(ProtocolVersion::DTLS1_3)`.
    use dimpl::ProtocolVersion;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();
    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

    // Before negotiation, auto-sense returns None.
    assert_eq!(client.protocol_version(), None);

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(10);
    }

    assert!(
        client_connected && server_connected,
        "Handshake should complete"
    );
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::DTLS1_3));
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_protocol_version_after_negotiating_dtls12() {
    //! After completing a handshake against a DTLS 1.2 server, the
    //! auto-sense client should report `Some(ProtocolVersion::DTLS1_2)`.
    use dimpl::ProtocolVersion;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();
    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

    // Before negotiation, auto-sense returns None.
    assert_eq!(client.protocol_version(), None);

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(10);
    }

    assert!(
        client_connected && server_connected,
        "Handshake should complete"
    );
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::DTLS1_2));
}
