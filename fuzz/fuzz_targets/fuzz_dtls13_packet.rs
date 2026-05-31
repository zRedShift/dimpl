#![no_main]

//! Fuzz target for DTLS 1.3 packet handling.
//!
//! This target exercises the main packet processing path in the DTLS 1.3 engine.
//! It creates a DTLS 1.3 instance and feeds it arbitrary byte sequences to find
//! parsing bugs, panics, or other issues in packet handling.

use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use std::time::Instant;

use dimpl::{Config, Dtls, Output, certificate};

fuzz_target!(|data: &[u8]| {
    // Generate a certificate once for the test instance
    let cert = match certificate::generate_self_signed_certificate() {
        Ok(c) => c,
        Err(_) => return, // Skip if certificate generation fails
    };

    let config = Arc::new(Config::default());
    let now = Instant::now();

    // Test as server (default mode)
    // Servers can receive packets immediately
    {
        let mut dtls = Dtls::new_13(Arc::clone(&config), cert.clone(), now);
        // Ignore errors - we're looking for panics, not handling errors
        let _ = dtls.handle_packet(data);
    }

    // Test as client
    // Clients need handle_timeout called first to initialize
    {
        let mut dtls = Dtls::new_13(Arc::clone(&config), cert, now);
        dtls.set_active(true); // Switch to client mode

        // Initialize the client by calling handle_timeout to set up state
        let mut buf = vec![0u8; 2048];
        let _ = dtls.handle_timeout(now);

        // Drain any initial packets (ClientHello) with a limit to prevent infinite loops
        for _ in 0..10 {
            let output_buf = match dtls.output_buffer(&mut buf) {
                Ok(output_buf) => output_buf,
                Err(err) => {
                    buf.resize(err.minimum(), 0);
                    continue;
                }
            };

            match dtls.poll_output(output_buf) {
                Ok(Output::Timeout(_)) => break,
                Ok(Output::Packet(_)) => continue,
                Ok(_) => break,
                Err(err) => {
                    buf.resize(err.minimum(), 0);
                    continue;
                }
            }
        }

        let _ = dtls.handle_packet(data);
    }
});
