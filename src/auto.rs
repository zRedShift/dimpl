/// Version detection and hybrid ClientHello for auto-sensing DTLS endpoints.
///
/// `server_hello_version` does lightweight parsing of records in a datagram.
/// It looks for a `HelloVerifyRequest` or a `ServerHello` with the
/// `supported_versions` extension to decide between DTLS 1.2 and 1.3 for the
/// client auto-sense path.
///
/// [`HybridClientHello`] constructs a ClientHello compatible with both
/// DTLS 1.2 and 1.3 servers: it offers both versions cipher suites and
/// includes `supported_versions` with both versions. Once the server
/// responds, the caller inspects the reply with `server_hello_version`
/// and forks into the appropriate handshake path.
///
/// Server-side auto-sense does not use lightweight detection. Instead,
/// it starts a DTLS 1.3 server which handles fragment reassembly natively
/// and falls back to DTLS 1.2 via [`Error::Dtls12Fallback`] if the
/// reassembled ClientHello does not offer DTLS 1.3.
use std::sync::Arc;
use std::time::{Duration, Instant};

use arrayvec::ArrayVec;

use crate::buffer::Buf;
use crate::crypto::ActiveKeyExchange;
use crate::dtls13::message::KeyShareClientHello;
use crate::dtls13::message::KeyShareEntry;
use crate::dtls13::message::Random;
use crate::dtls13::message::SignatureAlgorithmsExtension;
use crate::dtls13::message::SupportedGroupsExtension;
use crate::dtls13::message::UseSrtpExtension;
use crate::types::NamedGroup;
use crate::{Config, DtlsCertificate, Error, Output, SeededRng};
// Extension type constants
const EXT_SUPPORTED_GROUPS: u16 = 0x000A;
const EXT_EC_POINT_FORMATS: u16 = 0x000B;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000D;
const EXT_USE_SRTP: u16 = 0x000E;
const EXT_PADDING: u16 = 0x0015;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_RENEGOTIATION_INFO: u16 = 0xFF01;

const MAX_PENDING_SERVER_RESPONSE_PACKETS: usize = 8;
const MAX_PENDING_SERVER_RESPONSE_BYTES: usize =
    MAX_PENDING_SERVER_RESPONSE_PACKETS * (MAX_SERVER_HELLO_REASSEMBLY + 64);
const MAX_SERVER_HELLO_RECORDS_PER_PACKET: usize = 8;
const MAX_SERVER_HELLO_FRAGMENTS: usize = 64;
const MAX_SERVER_HELLO_REASSEMBLY: usize = 4096;

/// A self-contained hybrid ClientHello compatible with both DTLS 1.2 and 1.3.
///
/// Holds the serialized bytes and crypto state needed to fork into either
/// version's handshake once the server responds:
///
/// - **DTLS 1.3 fork**: transcript bytes and ECDHE private key are injected
///   into a `Client13` via `new_from_hybrid`.
/// - **DTLS 1.2 fork**: all state is discarded (HelloVerifyRequest clears
///   the transcript), and a fresh `Client12` is created.
pub(crate) struct HybridClientHello {
    /// Client random used in the ClientHello.
    pub random: Random,

    /// ECDHE private key from the key_share extension.
    pub active_key_exchange: Box<dyn ActiveKeyExchange>,

    /// TLS-style transcript bytes: msg_type(1) + length(3) + CH body.
    /// Does not include DTLS message_seq/fragment_offset/fragment_length.
    pub transcript_bytes: Buf,

    /// DTLS handshake fragment: msg_type(1) + length(3) + message_seq(2)
    ///     + fragment_offset(3) + fragment_length(3) + CH body.
    ///     Used by [`wire_packet`](Self::wire_packet) to build the on-wire record
    ///     and by `Client12::new_from_hybrid` for transcript injection.
    pub handshake_fragment: Buf,
}

impl HybridClientHello {
    /// Build a hybrid ClientHello from the given configuration.
    ///
    /// Serializes the ClientHello body with both DTLS 1.2 and 1.3 cipher
    /// suites, `supported_versions` offering both versions, and 1.2-compat
    /// extensions (`ec_point_formats`, `extended_master_secret`,
    /// `renegotiation_info`).
    pub fn new(config: &Arc<Config>) -> Result<Self, Error> {
        let mut rng = SeededRng::new(config.rng_seed());
        let random = Random::new(&mut rng);

        // Start ECDHE key exchange with the first supported group (filtered)
        let group = config
            .kx_groups()
            .next()
            .ok_or_else(|| Error::CryptoError("No supported key exchange groups".into()))?;
        let kx_buf = Buf::new();
        let key_exchange = group
            .start_exchange(kx_buf)
            .map_err(|e| Error::CryptoError(format!("Failed to start key exchange: {}", e)))?;

        // ---- Build the ClientHello body ----
        let mut ch_body = Buf::new();

        // legacy_version: DTLS 1.2
        ch_body.extend_from_slice(&0xFEFDu16.to_be_bytes());

        // random
        random.serialize(&mut ch_body);

        // legacy_session_id: empty
        ch_body.push(0);

        // legacy_cookie: empty (DTLS 1.3 requires zero-length)
        ch_body.push(0);

        // cipher_suites: 1.3 suites first, then non-PSK DTLS 1.2 suites.
        // The DTLS 1.2 fallback (`Client12::new_from_hybrid`) is
        // certificate-auth only and cannot complete a PSK suite.
        let mut suites: ArrayVec<u16, 16> = ArrayVec::new();
        for cs in config.dtls13_cipher_suites() {
            suites.push(cs.suite().as_u16());
        }
        for cs in config
            .dtls12_cipher_suites()
            .filter(|cs| !cs.suite().is_psk())
        {
            suites.push(cs.suite().as_u16());
        }
        ch_body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
        for &suite in &suites {
            ch_body.extend_from_slice(&suite.to_be_bytes());
        }

        // compression_methods: [null]
        ch_body.push(1);
        ch_body.push(0);

        // ---- Extensions ----
        // Build extension data into a separate buffer, then write the
        // extensions_length + extension entries into ch_body.
        let mut ext_buf = Buf::new();
        let mut ext_entries: Vec<(u16, usize, usize)> = Vec::new();

        // 1. supported_versions: [DTLS 1.3, DTLS 1.2]
        let start = ext_buf.len();
        ext_buf.push(4); // list_len = 2 versions * 2 bytes
        ext_buf.extend_from_slice(&0xFEFCu16.to_be_bytes()); // DTLS 1.3
        ext_buf.extend_from_slice(&0xFEFDu16.to_be_bytes()); // DTLS 1.2
        ext_entries.push((EXT_SUPPORTED_VERSIONS, start, ext_buf.len()));

        // 2. supported_groups (filtered by config)
        let start = ext_buf.len();
        let groups: ArrayVec<NamedGroup, 4> = config.kx_groups().map(|g| g.name()).collect();
        let sg = SupportedGroupsExtension { groups };
        sg.serialize(&mut ext_buf);
        ext_entries.push((EXT_SUPPORTED_GROUPS, start, ext_buf.len()));

        // 3. key_share (ECDHE public key)
        let pub_key = key_exchange.pub_key();
        let mut key_data = Buf::new();
        let pub_key_start = key_data.len();
        key_data.extend_from_slice(pub_key);
        let pub_key_end = key_data.len();

        let start = ext_buf.len();
        let mut entries = ArrayVec::new();
        entries.push(KeyShareEntry {
            group: group.name(),
            key_exchange_range: pub_key_start..pub_key_end,
        });
        let ks = KeyShareClientHello { entries };
        ks.serialize(&key_data, &mut ext_buf);
        ext_entries.push((EXT_KEY_SHARE, start, ext_buf.len()));

        // 4. signature_algorithms
        let start = ext_buf.len();
        let sa = SignatureAlgorithmsExtension::default();
        sa.serialize(&mut ext_buf);
        ext_entries.push((EXT_SIGNATURE_ALGORITHMS, start, ext_buf.len()));

        // 5. use_srtp
        let start = ext_buf.len();
        let use_srtp = UseSrtpExtension::default();
        use_srtp.serialize(&mut ext_buf);
        ext_entries.push((EXT_USE_SRTP, start, ext_buf.len()));

        // 6. ec_point_formats (DTLS 1.2 compat: uncompressed only)
        let start = ext_buf.len();
        ext_buf.push(1); // list length
        ext_buf.push(0); // ECPointFormat::Uncompressed
        ext_entries.push((EXT_EC_POINT_FORMATS, start, ext_buf.len()));

        // 7. extended_master_secret (empty, DTLS 1.2 compat)
        ext_entries.push((EXT_EXTENDED_MASTER_SECRET, ext_buf.len(), ext_buf.len()));

        // 8. renegotiation_info (empty renegotiated_connection, DTLS 1.2 compat)
        let start = ext_buf.len();
        ext_buf.push(0); // renegotiated_connection length = 0
        ext_entries.push((EXT_RENEGOTIATION_INFO, start, ext_buf.len()));

        // 9. padding: fill to MTU
        let record_header = 13usize;
        let handshake_header = 12usize;
        let body_so_far = ch_body.len()
            + 2 // extensions_length field
            + ext_entries.iter().map(|(_, s, e)| 4 + (e - s)).sum::<usize>();
        let total_so_far = record_header + handshake_header + body_so_far;
        let deficit = config.mtu().saturating_sub(total_so_far);
        if deficit >= 4 {
            let pad_data_len = deficit - 4; // 4 = type(2) + len(2)
            let start = ext_buf.len();
            for _ in 0..pad_data_len {
                ext_buf.push(0);
            }
            ext_entries.push((EXT_PADDING, start, ext_buf.len()));
        }

        // Write extensions into ch_body
        let ext_total_len: usize = ext_entries.iter().map(|(_, s, e)| 4 + (e - s)).sum();
        ch_body.extend_from_slice(&(ext_total_len as u16).to_be_bytes());
        for &(ext_type, start, end) in &ext_entries {
            ch_body.extend_from_slice(&ext_type.to_be_bytes());
            ch_body.extend_from_slice(&((end - start) as u16).to_be_bytes());
            if end > start {
                ch_body.extend_from_slice(&ext_buf[start..end]);
            }
        }

        // ---- Build transcript bytes: msg_type(1) + length(3) + body ----
        let mut transcript_bytes = Buf::new();
        transcript_bytes.push(0x01); // ClientHello msg_type
        let body_len = ch_body.len() as u32;
        transcript_bytes.extend_from_slice(&body_len.to_be_bytes()[1..]);
        transcript_bytes.extend_from_slice(&ch_body);

        // ---- Build DTLS handshake fragment ----
        // msg_type(1) + length(3) + message_seq(2) + frag_offset(3) + frag_len(3) + body
        let mut handshake_fragment = Buf::new();
        handshake_fragment.push(0x01); // msg_type = ClientHello
        handshake_fragment.extend_from_slice(&body_len.to_be_bytes()[1..]); // length (3 bytes)
        handshake_fragment.extend_from_slice(&0u16.to_be_bytes()); // message_seq = 0
        handshake_fragment.extend_from_slice(&0u32.to_be_bytes()[1..]); // fragment_offset (3 bytes)
        handshake_fragment.extend_from_slice(&body_len.to_be_bytes()[1..]); // fragment_length (3 bytes)
        handshake_fragment.extend_from_slice(&ch_body);

        Ok(HybridClientHello {
            random,
            active_key_exchange: key_exchange,
            transcript_bytes,
            handshake_fragment,
        })
    }

    /// Build the full wire-format DTLSPlaintext record for the hybrid CH.
    pub fn wire_packet(&self) -> Buf {
        let mut pkt = Buf::new();
        // DTLSPlaintext header: content_type(1) + version(2) + epoch(2) + seq(6) + length(2)
        pkt.push(0x16); // Handshake
        pkt.extend_from_slice(&0xFEFDu16.to_be_bytes()); // DTLS 1.2
        pkt.extend_from_slice(&0u16.to_be_bytes()); // epoch 0
        pkt.extend_from_slice(&[0u8; 6]); // sequence 0
        pkt.extend_from_slice(&(self.handshake_fragment.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&self.handshake_fragment);
        pkt
    }
}

/// Auto-sense client that sends a hybrid ClientHello and waits for the server's response
/// to determine the DTLS version.
pub(crate) struct ClientPending {
    hybrid: HybridClientHello,
    config: Arc<Config>,
    certificate: DtlsCertificate,
    /// Pre-built wire packet (record header + handshake fragment).
    wire_packet: Buf,
    /// Whether the wire_packet hasn't been polled yet.
    needs_send: bool,
    /// Last time handle_timeout was called.
    last_now: Instant,
    /// When to retransmit the wire_packet.
    retransmit_at: Option<Instant>,
    /// How many retransmits have occurred.
    retransmit_count: usize,
    /// ServerHello fragments that were not sufficient to resolve auto mode yet.
    server_response_fragments: ArrayVec<Buf, MAX_PENDING_SERVER_RESPONSE_PACKETS>,
}

impl ClientPending {
    pub fn new(
        config: Arc<Config>,
        certificate: DtlsCertificate,
        now: Instant,
    ) -> Result<Self, Error> {
        let hybrid = HybridClientHello::new(&config)?;
        let wire_packet = hybrid.wire_packet();
        Ok(ClientPending {
            hybrid,
            config,
            certificate,
            wire_packet,
            needs_send: true,
            last_now: now,
            retransmit_at: None,
            retransmit_count: 0,
            server_response_fragments: ArrayVec::new(),
        })
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        self.last_now = now;
        // Arm initial retransmit timer on first call
        if self.retransmit_at.is_none() {
            self.retransmit_at = Some(now + Duration::from_secs(1));
            return Ok(());
        }
        if let Some(deadline) = self.retransmit_at {
            if now >= deadline {
                if self.retransmit_count >= self.config.flight_retries() {
                    return Err(Error::Timeout("hybrid ClientHello"));
                }
                self.retransmit_count += 1;
                self.needs_send = true;
                // Exponential backoff: 2s, 4s, 8s, ...
                let shift = self.retransmit_count.min(5) as u32;
                let rto = Duration::from_secs(1u64 << shift);
                self.retransmit_at = Some(now + rto);
            }
        }
        Ok(())
    }

    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Output<'a> {
        if self.needs_send {
            let len = self.wire_packet.len();
            if buf.len() < len {
                // Buffer too small; keep needs_send armed so the packet
                // is emitted on the next poll with a sufficiently large buffer.
                return Output::BufferTooSmall { needed: len };
            }
            self.needs_send = false;
            buf[..len].copy_from_slice(&self.wire_packet);
            return Output::Packet(&buf[..len]);
        }
        let next = self
            .retransmit_at
            .unwrap_or(self.last_now + Duration::from_secs(1));
        Output::Timeout(next)
    }

    pub fn push_server_response_fragment(
        &mut self,
        packet: &[u8],
    ) -> Result<DetectedVersion, Error> {
        if packet_has_new_server_hello_fragment(&self.server_response_fragments, packet) {
            if self.server_response_fragments.is_full() {
                return Err(Error::TooManyServerHelloFragments);
            }
            let queued_bytes: usize = self
                .server_response_fragments
                .iter()
                .map(|queued| queued.len())
                .sum();
            if queued_bytes.saturating_add(packet.len()) > MAX_PENDING_SERVER_RESPONSE_BYTES {
                return Err(Error::TooManyServerHelloFragments);
            }

            let mut queued = Buf::new();
            queued.extend_from_slice(packet);
            self.server_response_fragments.push(queued);
        }

        Ok(server_hello_version_from_fragments(
            self.server_response_fragments
                .iter()
                .map(|queued| queued.as_ref()),
        ))
    }

    pub fn has_server_response_fragments(&self) -> bool {
        !self.server_response_fragments.is_empty()
    }

    pub fn into_parts(
        self,
    ) -> (
        HybridClientHello,
        Arc<Config>,
        DtlsCertificate,
        Instant,
        ArrayVec<Buf, MAX_PENDING_SERVER_RESPONSE_PACKETS>,
    ) {
        (
            self.hybrid,
            self.config,
            self.certificate,
            self.last_now,
            self.server_response_fragments,
        )
    }
}

// =========================================================================
// Version detection helpers
// =========================================================================

/// Detected DTLS version from packet inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DetectedVersion {
    Dtls12,
    Dtls13,
    Incomplete,
    Unknown,
}

/// Detect DTLS version from a server response (ServerHello or HelloVerifyRequest).
///
/// - HelloVerifyRequest (msg_type 3) → `Dtls12`
/// - ServerHello with `supported_versions` containing DTLS 1.3 → `Dtls13`
/// - ServerHello without `supported_versions` → `Dtls12`
/// - Incomplete initial ServerHello fragment without enough evidence → `Incomplete`
/// - Anything else → `Unknown`
pub(crate) fn server_hello_version(packet: &[u8]) -> DetectedVersion {
    server_hello_version_inner(packet)
}

pub(crate) fn server_hello_version_from_fragments<'a>(
    packets: impl IntoIterator<Item = &'a [u8]>,
) -> DetectedVersion {
    let mut fragments = Vec::new();
    let mut saw_hello_verify_request = false;
    let mut saw_opaque_tail = false;

    for packet in packets {
        match collect_server_hello_fragments(packet, &mut fragments) {
            PacketServerHelloFragments::Parsed(flags) => {
                saw_hello_verify_request |= flags.saw_hello_verify_request;
                saw_opaque_tail |= flags.saw_opaque_tail;
            }
            PacketServerHelloFragments::Unknown => return DetectedVersion::Unknown,
        }
    }

    if saw_hello_verify_request {
        return if fragments.is_empty() {
            DetectedVersion::Dtls12
        } else {
            DetectedVersion::Unknown
        };
    }

    reject_dtls12_after_opaque_tail(
        server_hello_version_from_collected_fragments(&fragments),
        saw_opaque_tail,
    )
}

fn server_hello_version_inner(packet: &[u8]) -> DetectedVersion {
    let mut fragments = Vec::new();
    match collect_server_hello_fragments(packet, &mut fragments) {
        PacketServerHelloFragments::Parsed(flags)
            if flags.saw_hello_verify_request && fragments.is_empty() =>
        {
            DetectedVersion::Dtls12
        }
        PacketServerHelloFragments::Parsed(flags)
            if flags.saw_hello_verify_request && !fragments.is_empty() =>
        {
            DetectedVersion::Unknown
        }
        PacketServerHelloFragments::Unknown => DetectedVersion::Unknown,
        PacketServerHelloFragments::Parsed(flags) => reject_dtls12_after_opaque_tail(
            server_hello_version_from_collected_fragments(&fragments),
            flags.saw_opaque_tail,
        ),
    }
}

#[derive(Clone, Copy)]
struct ServerHelloFragmentRef<'a> {
    message_len: usize,
    message_seq: u16,
    fragment_offset: usize,
    fragment_len: usize,
    body: &'a [u8],
}

#[derive(Clone, Copy, Default)]
struct PacketServerHelloFlags {
    saw_hello_verify_request: bool,
    saw_opaque_tail: bool,
}

enum PacketServerHelloFragments {
    Parsed(PacketServerHelloFlags),
    Unknown,
}

fn collect_server_hello_fragments<'a>(
    mut packet: &'a [u8],
    fragments: &mut Vec<ServerHelloFragmentRef<'a>>,
) -> PacketServerHelloFragments {
    let initial_len = fragments.len();
    let mut records = 0usize;
    let mut flags = PacketServerHelloFlags::default();
    while !packet.is_empty() {
        if packet[0] != 0x16 {
            if fragments.len() != initial_len
                && is_dtls13_ciphertext_header(packet[0])
                && ciphertext_tail_boundaries_are_valid(packet, records)
            {
                flags.saw_opaque_tail = true;
                break;
            }
            return PacketServerHelloFragments::Unknown;
        }

        let Some((record_body, record_end)) = next_record_body(packet) else {
            return PacketServerHelloFragments::Unknown;
        };

        records += 1;
        if records > MAX_SERVER_HELLO_RECORDS_PER_PACKET {
            return PacketServerHelloFragments::Unknown;
        }

        match collect_record_server_hello_fragments(record_body, fragments) {
            PacketServerHelloFragments::Parsed(record_flags) => {
                flags.saw_hello_verify_request |= record_flags.saw_hello_verify_request;
                flags.saw_opaque_tail |= record_flags.saw_opaque_tail;
            }
            PacketServerHelloFragments::Unknown => return PacketServerHelloFragments::Unknown,
        }

        packet = &packet[record_end..];
    }

    if fragments.len() == initial_len && !flags.saw_hello_verify_request {
        PacketServerHelloFragments::Unknown
    } else {
        PacketServerHelloFragments::Parsed(flags)
    }
}

fn next_record_body(packet: &[u8]) -> Option<(&[u8], usize)> {
    // Record header: content_type(1) + version(2) + epoch(2) + seq(6) + length(2) = 13
    if packet.len() < 13 {
        return None;
    }
    let version = [packet[1], packet[2]];
    if !matches!(version, [0xFE, 0xFF] | [0xFE, 0xFD]) {
        return None;
    }
    if packet[3] != 0 || packet[4] != 0 {
        return None;
    }

    let record_len = u16::from_be_bytes([packet[11], packet[12]]) as usize;
    let record_end = 13usize.checked_add(record_len)?;
    let record_body = packet.get(13..record_end)?;

    Some((record_body, record_end))
}

fn collect_record_server_hello_fragments<'a>(
    mut record_body: &'a [u8],
    fragments: &mut Vec<ServerHelloFragmentRef<'a>>,
) -> PacketServerHelloFragments {
    let mut flags = PacketServerHelloFlags::default();
    while !record_body.is_empty() {
        // Handshake header: msg_type(1) + length(3) + message_seq(2) +
        //   fragment_offset(3) + fragment_length(3) = 12
        if record_body.len() < 12 {
            return PacketServerHelloFragments::Unknown;
        }

        let msg_type = record_body[0];
        let message_len = ((record_body[1] as usize) << 16)
            | ((record_body[2] as usize) << 8)
            | (record_body[3] as usize);
        let message_seq = u16::from_be_bytes([record_body[4], record_body[5]]);
        let fragment_offset = ((record_body[6] as usize) << 16)
            | ((record_body[7] as usize) << 8)
            | (record_body[8] as usize);
        let fragment_len = ((record_body[9] as usize) << 16)
            | ((record_body[10] as usize) << 8)
            | (record_body[11] as usize);
        if fragment_offset > message_len || fragment_len > message_len - fragment_offset {
            return PacketServerHelloFragments::Unknown;
        }

        let Some(body_end) = 12usize.checked_add(fragment_len) else {
            return PacketServerHelloFragments::Unknown;
        };
        let Some(body) = record_body.get(12..body_end) else {
            return PacketServerHelloFragments::Unknown;
        };

        // HelloVerifyRequest → DTLS 1.2, but only when it is structurally
        // valid and not mixed with ServerHello evidence in the same response.
        if msg_type == 3 {
            if !hello_verify_request_body_is_valid(
                body,
                message_len,
                message_seq,
                fragment_offset,
                fragment_len,
            ) {
                return PacketServerHelloFragments::Unknown;
            }
            flags.saw_hello_verify_request = true;
            record_body = &record_body[body_end..];
            continue;
        }

        // ServerHello → inspect supported_versions.
        if msg_type == 2 {
            if message_len > MAX_SERVER_HELLO_REASSEMBLY
                || fragments.len() >= MAX_SERVER_HELLO_FRAGMENTS
            {
                return PacketServerHelloFragments::Unknown;
            }
            fragments.push(ServerHelloFragmentRef {
                message_len,
                message_seq,
                fragment_offset,
                fragment_len,
                body,
            });
        }

        record_body = &record_body[body_end..];
    }

    PacketServerHelloFragments::Parsed(flags)
}

fn hello_verify_request_body_is_valid(
    body: &[u8],
    message_len: usize,
    message_seq: u16,
    fragment_offset: usize,
    fragment_len: usize,
) -> bool {
    if message_seq != 0
        || fragment_offset != 0
        || fragment_len != message_len
        || body.len() != message_len
    {
        return false;
    }

    let Some((&cookie_len, cookie)) = body.get(2).zip(body.get(3..)) else {
        return false;
    };

    let version = u16::from_be_bytes([body[0], body[1]]);
    matches!(version, 0xFEFF | 0xFEFD) && cookie_len > 0 && cookie.len() == cookie_len as usize
}

fn is_dtls13_ciphertext_header(byte: u8) -> bool {
    byte & 0b1110_0000 == 0b0010_0000
}

fn ciphertext_tail_boundaries_are_valid(mut packet: &[u8], mut records: usize) -> bool {
    while !packet.is_empty() {
        if !is_dtls13_ciphertext_header(packet[0]) || packet[0] & 0b0001_0000 != 0 {
            return false;
        }

        let flags = packet[0];
        let seq_len = if flags & 0b0000_1000 != 0 { 2 } else { 1 };
        let len_len = if flags & 0b0000_0100 != 0 { 2 } else { 0 };
        let header_len = 1 + seq_len + len_len;
        if packet.len() < header_len {
            return false;
        }

        records += 1;
        if records > MAX_SERVER_HELLO_RECORDS_PER_PACKET {
            return false;
        }

        let record_end = if len_len == 2 {
            let len_offset = 1 + seq_len;
            let length = u16::from_be_bytes([packet[len_offset], packet[len_offset + 1]]) as usize;
            let Some(record_end) = header_len.checked_add(length) else {
                return false;
            };
            if record_end > packet.len() {
                return false;
            }
            record_end
        } else {
            packet.len()
        };

        packet = &packet[record_end..];
    }

    true
}

fn packet_has_new_server_hello_fragment(
    queued_packets: &ArrayVec<Buf, MAX_PENDING_SERVER_RESPONSE_PACKETS>,
    packet: &[u8],
) -> bool {
    let mut incoming = Vec::new();
    let incoming_flags = match collect_server_hello_fragments(packet, &mut incoming) {
        PacketServerHelloFragments::Parsed(flags) => flags,
        PacketServerHelloFragments::Unknown => {
            return !queued_packets
                .iter()
                .any(|queued| queued.as_ref() == packet);
        }
    };

    if incoming_flags.saw_hello_verify_request {
        return !queued_packets
            .iter()
            .any(|queued| queued.as_ref() == packet);
    }

    let mut queued_fragments = Vec::new();
    for queued in queued_packets {
        if matches!(
            collect_server_hello_fragments(queued.as_ref(), &mut queued_fragments),
            PacketServerHelloFragments::Parsed(PacketServerHelloFlags {
                saw_hello_verify_request: true,
                ..
            })
        ) {
            return true;
        }
    }

    incoming.iter().any(|fragment| {
        !queued_fragments
            .iter()
            .any(|queued| server_hello_fragment_eq(fragment, queued))
    })
}

fn server_hello_fragment_eq(
    left: &ServerHelloFragmentRef<'_>,
    right: &ServerHelloFragmentRef<'_>,
) -> bool {
    left.message_len == right.message_len
        && left.message_seq == right.message_seq
        && left.fragment_offset == right.fragment_offset
        && left.fragment_len == right.fragment_len
        && left.body == right.body
}

fn reassembled_server_hello_version(fragments: &[ServerHelloFragmentRef<'_>]) -> DetectedVersion {
    let Some(first) = fragments.first().copied() else {
        return DetectedVersion::Incomplete;
    };

    if fragments.iter().any(|fragment| {
        fragment.message_len != first.message_len || fragment.message_seq != first.message_seq
    }) {
        return DetectedVersion::Unknown;
    }

    let mut body = vec![None; first.message_len];
    let mut filled = 0usize;
    for fragment in fragments {
        for (index, byte) in fragment.body.iter().copied().enumerate() {
            let pos = fragment.fragment_offset + index;
            match body[pos] {
                Some(existing) if existing != byte => return DetectedVersion::Unknown,
                Some(_) => {}
                None => {
                    body[pos] = Some(byte);
                    filled += 1;
                }
            }
        }
    }

    if filled != first.message_len {
        return DetectedVersion::Incomplete;
    }

    let mut reassembled = Vec::with_capacity(first.message_len);
    for byte in body {
        let Some(byte) = byte else {
            return DetectedVersion::Incomplete;
        };
        reassembled.push(byte);
    }

    server_hello_body_version(&reassembled, first.message_len, true)
}

fn server_hello_version_from_collected_fragments(
    fragments: &[ServerHelloFragmentRef<'_>],
) -> DetectedVersion {
    if !server_hello_fragments_are_consistent(fragments) {
        return DetectedVersion::Unknown;
    }

    reassembled_server_hello_version(fragments)
}

fn server_hello_fragments_are_consistent(fragments: &[ServerHelloFragmentRef<'_>]) -> bool {
    let Some(first) = fragments.first().copied() else {
        return true;
    };

    let mut body = vec![None; first.message_len];
    for fragment in fragments {
        if fragment.message_len != first.message_len || fragment.message_seq != first.message_seq {
            return false;
        }

        for (index, byte) in fragment.body.iter().copied().enumerate() {
            let pos = fragment.fragment_offset + index;
            match body[pos] {
                Some(existing) if existing != byte => return false,
                Some(_) => {}
                None => body[pos] = Some(byte),
            }
        }
    }

    true
}

fn reject_dtls12_after_opaque_tail(
    version: DetectedVersion,
    saw_opaque_tail: bool,
) -> DetectedVersion {
    if saw_opaque_tail && version == DetectedVersion::Dtls12 {
        DetectedVersion::Unknown
    } else {
        version
    }
}

fn server_hello_body_version(
    body: &[u8],
    message_len: usize,
    is_complete: bool,
) -> DetectedVersion {
    // ServerHello body:
    //   server_version(2) + random(32) + session_id_len(1) + session_id + ...
    let Some(version) = body.get(0..2) else {
        return incomplete_or_unknown(is_complete);
    };
    if version != [0xFE, 0xFD] {
        return DetectedVersion::Unknown;
    }
    if body.len() < 34 {
        return incomplete_or_unknown(is_complete);
    }
    let mut pos = 34; // past version(2) + random(32)

    // session_id: 1-byte length + data
    let Some(sid_len) = body.get(pos).copied() else {
        return incomplete_or_unknown(is_complete);
    };
    let sid_len = sid_len as usize;
    if sid_len > 32 {
        return DetectedVersion::Unknown;
    }
    let Some(next_pos) = pos.checked_add(1).and_then(|pos| pos.checked_add(sid_len)) else {
        return DetectedVersion::Unknown;
    };
    pos = next_pos;
    if pos > body.len() {
        return incomplete_or_unknown(is_complete);
    }

    // cipher_suite(2) + compression_method(1)
    if pos + 3 > body.len() {
        return incomplete_or_unknown(is_complete);
    }
    let compression_method = body[pos + 2];
    if compression_method != 0 {
        return DetectedVersion::Unknown;
    }
    pos += 3;

    // extensions: 2-byte total length (optional)
    if pos == body.len() {
        return if is_complete {
            // No extensions → DTLS 1.2
            DetectedVersion::Dtls12
        } else {
            DetectedVersion::Incomplete
        };
    }
    if pos + 2 > body.len() {
        return incomplete_or_unknown(is_complete);
    }
    let ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let Some(ext_end) = pos.checked_add(ext_total_len) else {
        return DetectedVersion::Unknown;
    };
    if ext_end > message_len {
        return DetectedVersion::Unknown;
    }
    if is_complete {
        if ext_end != body.len() {
            return DetectedVersion::Unknown;
        }
    } else if ext_end <= body.len() {
        // The extensions vector is the last ServerHello field. If a partial
        // fragment already contains the complete vector, the full body cannot
        // legally have more bytes after it.
        return DetectedVersion::Unknown;
    }

    // Walk extensions looking for supported_versions (0x002B)
    let mut selected_version = None;
    let visible_end = body.len().min(ext_end);
    while pos < visible_end {
        if pos + 4 > visible_end {
            if is_complete {
                return DetectedVersion::Unknown;
            }
            return detected_or_incomplete(selected_version);
        }

        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > visible_end {
            if is_complete {
                return DetectedVersion::Unknown;
            }
            if ext_type == 0x002B && ext_len != 2 {
                return DetectedVersion::Unknown;
            }
            return detected_or_incomplete(selected_version);
        }

        if ext_type == 0x002B {
            // ServerHello supported_versions: just 2 bytes (selected_version)
            if ext_len != 2 {
                return DetectedVersion::Unknown;
            }

            if selected_version
                .replace(u16::from_be_bytes([body[pos], body[pos + 1]]))
                .is_some()
            {
                return DetectedVersion::Unknown;
            }
        }

        pos += ext_len;
    }

    if pos != ext_end {
        if is_complete {
            return DetectedVersion::Unknown;
        }
        return detected_or_incomplete(selected_version);
    }

    match selected_version {
        Some(0xFEFC) => DetectedVersion::Dtls13,
        Some(_) => DetectedVersion::Unknown,
        None => DetectedVersion::Dtls12,
    }
}

fn incomplete_or_unknown(is_complete: bool) -> DetectedVersion {
    if is_complete {
        DetectedVersion::Unknown
    } else {
        DetectedVersion::Incomplete
    }
}

fn detected_or_incomplete(selected_version: Option<u16>) -> DetectedVersion {
    match selected_version {
        Some(0xFEFC) => DetectedVersion::Dtls13,
        Some(_) => DetectedVersion::Unknown,
        None => DetectedVersion::Incomplete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PskResolver;
    use crate::dtls12::message::Dtls12CipherSuite;

    fn offered_cipher_suites(hybrid: &HybridClientHello) -> Vec<u16> {
        let body = &hybrid.handshake_fragment[12..];
        let mut offset = 2 + 32; // legacy_version + random

        let session_id_len = body[offset] as usize;
        offset += 1 + session_id_len;

        let cookie_len = body[offset] as usize;
        offset += 1 + cookie_len;

        let suites_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2;

        body[offset..offset + suites_len]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect()
    }

    struct DummyResolver;

    impl PskResolver for DummyResolver {
        fn resolve(&self, _identity: &[u8]) -> Option<Vec<u8>> {
            Some(b"0123456789abcdef".to_vec())
        }
    }

    fn server_hello_packet_with_body(body: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Record header
        pkt.push(0x16);
        pkt.extend_from_slice(&[0xFE, 0xFD]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]);

        // Handshake header: msg_type=2 (ServerHello)
        pkt.push(2);
        let hs_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        let frag_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);

        pkt.extend_from_slice(body);

        let body_len = body.len();
        pkt[hs_len_pos] = 0;
        pkt[hs_len_pos + 1] = (body_len >> 8) as u8;
        pkt[hs_len_pos + 2] = body_len as u8;
        pkt[frag_len_pos] = 0;
        pkt[frag_len_pos + 1] = (body_len >> 8) as u8;
        pkt[frag_len_pos + 2] = body_len as u8;

        let record_len = (pkt.len() - 13) as u16;
        pkt[len_pos] = (record_len >> 8) as u8;
        pkt[len_pos + 1] = record_len as u8;

        pkt
    }

    fn server_hello_body_with_extensions(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0xFE, 0xFD]); // legacy version DTLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id length = 0
        body.extend_from_slice(&[0x13, 0x01]); // cipher_suite AES_128_GCM_SHA256
        body.push(0x00); // compression_method = null
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        body
    }

    fn server_hello_packet_with_extensions(extensions: &[u8]) -> Vec<u8> {
        server_hello_packet_with_body(&server_hello_body_with_extensions(extensions))
    }

    fn fragmented_server_hello_packet(full_body: &[u8], offset: usize, len: usize) -> Vec<u8> {
        let fragment = &full_body[offset..offset + len];
        let mut pkt = Vec::new();

        pkt.push(0x16);
        pkt.extend_from_slice(&[0xFE, 0xFD]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let record_len = 12 + fragment.len();
        pkt.extend_from_slice(&(record_len as u16).to_be_bytes());

        pkt.push(2);
        pkt.extend_from_slice(&(full_body.len() as u32).to_be_bytes()[1..]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&(offset as u32).to_be_bytes()[1..]);
        pkt.extend_from_slice(&(fragment.len() as u32).to_be_bytes()[1..]);
        pkt.extend_from_slice(fragment);

        pkt
    }

    fn fragmented_server_hello_handshake(full_body: &[u8], offset: usize, len: usize) -> Vec<u8> {
        fragmented_server_hello_packet(full_body, offset, len)[13..].to_vec()
    }

    fn hello_verify_request_handshake(body: &[u8]) -> Vec<u8> {
        let mut handshake = Vec::new();
        handshake.push(3);
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&[0x00, 0x00]);
        handshake.extend_from_slice(&[0x00, 0x00, 0x00]);
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(body);
        handshake
    }

    fn handshake_record(handshakes: &[Vec<u8>]) -> Vec<u8> {
        let record_len: usize = handshakes.iter().map(Vec::len).sum();
        let mut pkt = Vec::new();
        pkt.push(0x16);
        pkt.extend_from_slice(&[0xFE, 0xFD]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&(record_len as u16).to_be_bytes());
        for handshake in handshakes {
            pkt.extend_from_slice(handshake);
        }
        pkt
    }

    fn assert_record_header_variants_are_unknown(packet: Vec<u8>) {
        let mut invalid_version = packet.clone();
        invalid_version[1..3].copy_from_slice(&[0xFE, 0xFC]);
        assert_eq!(
            server_hello_version(&invalid_version),
            DetectedVersion::Unknown
        );

        let mut nonzero_epoch = packet;
        nonzero_epoch[3..5].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            server_hello_version(&nonzero_epoch),
            DetectedVersion::Unknown
        );
    }

    fn ignored_handshake_record() -> Vec<u8> {
        handshake_record(&[make_empty_handshake(99)])
    }

    fn make_empty_handshake(msg_type: u8) -> Vec<u8> {
        let mut handshake = Vec::new();
        handshake.push(msg_type);
        handshake.extend_from_slice(&[0x00, 0x00, 0x00]);
        handshake.extend_from_slice(&[0x00, 0x00]);
        handshake.extend_from_slice(&[0x00, 0x00, 0x00]);
        handshake.extend_from_slice(&[0x00, 0x00, 0x00]);
        handshake
    }

    #[test]
    fn hello_verify_request_is_dtls12() {
        // Minimal HelloVerifyRequest packet
        let mut pkt = Vec::new();
        // Record header: content_type=22, version=DTLS1.2, epoch=0, seq=0, length=TBD
        pkt.push(0x16); // handshake
        pkt.extend_from_slice(&[0xFE, 0xFD]); // DTLS 1.2
        pkt.extend_from_slice(&[0x00, 0x00]); // epoch 0
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // seq 0
        // length placeholder (will fill)
        let len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]);

        // Handshake header: msg_type=3 (HVR), length=5, msg_seq=0, frag_off=0, frag_len=5
        pkt.push(3); // HelloVerifyRequest
        pkt.extend_from_slice(&[0x00, 0x00, 0x05]); // length
        pkt.extend_from_slice(&[0x00, 0x00]); // message_seq
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // fragment_offset
        pkt.extend_from_slice(&[0x00, 0x00, 0x05]); // fragment_length

        // HVR body: server_version(2) + cookie_len(1) + cookie(2)
        pkt.extend_from_slice(&[0xFE, 0xFD]); // server_version
        pkt.push(0x02); // cookie length
        pkt.extend_from_slice(&[0xAA, 0xBB]); // cookie

        // Fill record length
        let record_len = (pkt.len() - 13) as u16;
        pkt[len_pos] = (record_len >> 8) as u8;
        pkt[len_pos + 1] = record_len as u8;

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Dtls12);
    }

    #[test]
    fn hello_verify_request_dtls10_is_dtls12() {
        let pkt = handshake_record(&[hello_verify_request_handshake(&[0xFE, 0xFF, 0x01, 0xAA])]);

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Dtls12);
    }

    #[test]
    fn hello_verify_request_rejects_nonzero_message_seq() {
        let mut pkt = handshake_record(&[hello_verify_request_handshake(&[
            0xFE, 0xFD, 0x02, 0xAA, 0xBB,
        ])]);
        pkt[18] = 1;

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
    }

    #[test]
    fn hello_verify_request_rejects_empty_cookie() {
        let pkt = handshake_record(&[hello_verify_request_handshake(&[0xFE, 0xFD, 0x00])]);

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
    }

    #[test]
    fn hello_verify_request_rejects_dtls13_version() {
        let pkt = handshake_record(&[hello_verify_request_handshake(&[0xFE, 0xFC, 0x01, 0xAA])]);

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
    }

    #[test]
    fn hello_verify_request_rejects_malformed_record_header() {
        let pkt = handshake_record(&[hello_verify_request_handshake(&[
            0xFE, 0xFD, 0x02, 0xAA, 0xBB,
        ])]);

        assert_record_header_variants_are_unknown(pkt);
    }

    #[test]
    fn hello_verify_request_rejects_opaque_tail() {
        let mut pkt = handshake_record(&[hello_verify_request_handshake(&[
            0xFE, 0xFD, 0x02, 0xAA, 0xBB,
        ])]);
        pkt.extend_from_slice(&[0x2E, 0x00, 0x28, 0x31, 0xD3, 0x00]);

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
    }

    #[test]
    fn server_hello_with_supported_versions_is_dtls13() {
        let mut pkt = Vec::new();
        // Record header
        pkt.push(0x16);
        pkt.extend_from_slice(&[0xFE, 0xFD]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]);

        // Handshake header: msg_type=2 (ServerHello)
        pkt.push(2);
        let hs_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder
        pkt.extend_from_slice(&[0x00, 0x00]); // message_seq
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // fragment_offset
        let frag_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // fragment_length placeholder

        let body_start = pkt.len();

        // ServerHello body: version(2) + random(32) + session_id
        pkt.extend_from_slice(&[0xFE, 0xFD]); // legacy version DTLS 1.2
        pkt.extend_from_slice(&[0u8; 32]); // random
        pkt.push(0x00); // session_id length = 0
        pkt.extend_from_slice(&[0x13, 0x01]); // cipher_suite AES_128_GCM_SHA256
        pkt.push(0x00); // compression_method = null

        // Extensions
        let ext_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]); // extensions length placeholder

        let ext_start = pkt.len();

        // supported_versions extension: type=0x002B, data=0xFEFC (DTLS 1.3)
        pkt.extend_from_slice(&[0x00, 0x2B]); // type
        pkt.extend_from_slice(&[0x00, 0x02]); // length
        pkt.extend_from_slice(&[0xFE, 0xFC]); // DTLS 1.3

        let ext_total = pkt.len() - ext_start;
        pkt[ext_len_pos] = (ext_total >> 8) as u8;
        pkt[ext_len_pos + 1] = ext_total as u8;

        let body_len = pkt.len() - body_start;
        // Fill handshake length and fragment length
        pkt[hs_len_pos] = 0;
        pkt[hs_len_pos + 1] = (body_len >> 8) as u8;
        pkt[hs_len_pos + 2] = body_len as u8;
        pkt[frag_len_pos] = 0;
        pkt[frag_len_pos + 1] = (body_len >> 8) as u8;
        pkt[frag_len_pos + 2] = body_len as u8;

        // Fill record length
        let record_len = (pkt.len() - 13) as u16;
        pkt[len_pos] = (record_len >> 8) as u8;
        pkt[len_pos + 1] = record_len as u8;

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Dtls13);
    }

    #[test]
    fn server_hello_accepts_opaque_dtls13_tail_after_version_evidence() {
        let mut pkt = server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]);
        pkt.extend_from_slice(&[0x2E, 0x00, 0x28, 0x00, 0x01, 0x00]);

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Dtls13);
    }

    #[test]
    fn server_hello_rejects_non_ciphertext_opaque_tail_after_version_evidence() {
        for tail in [&[0x15][..], &[0xFF, 0x00][..]] {
            let mut pkt =
                server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]);
            pkt.extend_from_slice(tail);

            assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
        }
    }

    #[test]
    fn server_hello_rejects_malformed_record_header() {
        let pkt = server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]);

        assert_record_header_variants_are_unknown(pkt);
    }

    #[test]
    fn server_hello_without_supported_versions_rejects_opaque_tail() {
        let mut pkt = server_hello_packet_with_extensions(&[]);
        pkt.extend_from_slice(&[0x2E, 0x00, 0x28, 0x31, 0xD3, 0x00]);

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
    }

    #[test]
    fn server_hello_rejects_truncated_supported_versions_extension() {
        let pkt = server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x02]);

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
    }

    #[test]
    fn server_hello_rejects_short_supported_versions_extension() {
        for ext_body in [&[][..], &[0xFE][..]] {
            let mut extensions = Vec::new();
            extensions.extend_from_slice(&[0x00, 0x2B]);
            extensions.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
            extensions.extend_from_slice(ext_body);

            assert_eq!(
                server_hello_version(&server_hello_packet_with_extensions(&extensions)),
                DetectedVersion::Unknown
            );
        }
    }

    #[test]
    fn server_hello_rejects_long_supported_versions_extension() {
        let pkt = server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x03, 0xFE, 0xFC, 0x00]);

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
    }

    #[test]
    fn server_hello_rejects_unsupported_selected_versions() {
        for selected in [[0xFE, 0xFD], [0xFE, 0xFB], [0x03, 0x04]] {
            let pkt = server_hello_packet_with_extensions(&[
                0x00,
                0x2B,
                0x00,
                0x02,
                selected[0],
                selected[1],
            ]);

            assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
        }
    }

    #[test]
    fn server_hello_rejects_duplicate_supported_versions() {
        let pkt = server_hello_packet_with_extensions(&[
            0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC, 0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC,
        ]);

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
    }

    #[test]
    fn server_hello_rejects_truncated_fixed_body_fields() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0xFE, 0xFD]); // legacy version DTLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random

        assert_eq!(
            server_hello_version(&server_hello_packet_with_body(&body)),
            DetectedVersion::Unknown
        );

        body.push(0x04); // session_id length, but no session id
        assert_eq!(
            server_hello_version(&server_hello_packet_with_body(&body)),
            DetectedVersion::Unknown
        );

        body[34] = 0x00; // empty session id, but no cipher suite
        assert_eq!(
            server_hello_version(&server_hello_packet_with_body(&body)),
            DetectedVersion::Unknown
        );

        body.push(0x13); // partial cipher suite
        assert_eq!(
            server_hello_version(&server_hello_packet_with_body(&body)),
            DetectedVersion::Unknown
        );

        body.push(0x01); // complete cipher suite, missing compression method
        assert_eq!(
            server_hello_version(&server_hello_packet_with_body(&body)),
            DetectedVersion::Unknown
        );
    }

    #[test]
    fn server_hello_rejects_invalid_legacy_version() {
        for extensions in [&[][..], &[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC][..]] {
            let mut body = server_hello_body_with_extensions(extensions);
            body[0..2].copy_from_slice(&[0xFE, 0xFC]);

            assert_eq!(
                server_hello_version(&server_hello_packet_with_body(&body)),
                DetectedVersion::Unknown
            );
        }
    }

    #[test]
    fn server_hello_rejects_non_null_compression() {
        for extensions in [&[][..], &[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC][..]] {
            let mut body = server_hello_body_with_extensions(extensions);
            let compression_pos = 2 + 32 + 1 + 2;
            body[compression_pos] = 1;

            assert_eq!(
                server_hello_version(&server_hello_packet_with_body(&body)),
                DetectedVersion::Unknown
            );
        }
    }

    #[test]
    fn server_hello_rejects_incomplete_handshake_fragments() {
        let pkt = server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]);
        assert_eq!(server_hello_version(&pkt), DetectedVersion::Dtls13);

        let body = pkt[25..].to_vec();
        let nonzero_offset = fragmented_server_hello_packet(&body, 1, body.len() - 1);
        assert_eq!(
            server_hello_version(&nonzero_offset),
            DetectedVersion::Incomplete
        );

        let mut partial_fragment = pkt;
        partial_fragment[16] += 1; // handshake length declares one byte beyond this fragment
        assert_eq!(
            server_hello_version(&partial_fragment),
            DetectedVersion::Incomplete
        );
    }

    #[test]
    fn server_hello_partial_first_fragment_waits_for_full_validation() {
        let mut pkt = server_hello_packet_with_extensions(&[
            0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC, // supported_versions
            0x00, 0x15, 0x00, 0x00, // padding extension header
        ]);
        let full_body_len =
            ((pkt[14] as usize) << 16) | ((pkt[15] as usize) << 8) | pkt[16] as usize;
        let partial_body_len = full_body_len - 4;
        let record_len = 12 + partial_body_len;

        pkt[11..13].copy_from_slice(&(record_len as u16).to_be_bytes());
        pkt[22] = 0;
        pkt[23] = (partial_body_len >> 8) as u8;
        pkt[24] = partial_body_len as u8;
        pkt.truncate(13 + record_len);

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Incomplete);
    }

    #[test]
    fn server_hello_rejects_malformed_tail_after_reassembled_partial_version_evidence() {
        let full = server_hello_packet_with_extensions(&[
            0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC, // supported_versions
            0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC, // duplicate supported_versions
        ]);
        let body = full[25..].to_vec();
        let split = body.len() - 6;

        let first = fragmented_server_hello_packet(&body, 0, split);
        let second = fragmented_server_hello_packet(&body, split, body.len() - split);
        assert_eq!(
            server_hello_version_from_fragments([first.as_slice(), second.as_slice()]),
            DetectedVersion::Unknown
        );

        let datagram = handshake_record(&[
            fragmented_server_hello_handshake(&body, 0, split),
            fragmented_server_hello_handshake(&body, split, body.len() - split),
        ]);
        assert_eq!(server_hello_version(&datagram), DetectedVersion::Unknown);
    }

    #[test]
    fn server_hello_conflicting_queued_fragment_blocks_fast_path() {
        let full = server_hello_packet_with_extensions(&[
            0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC, // supported_versions
            0x00, 0x15, 0x00, 0x00, // padding extension header
        ]);
        let body = full[25..].to_vec();
        let first = fragmented_server_hello_packet(&body, 0, body.len() - 4);
        let mut conflicting_body = body.clone();
        conflicting_body[0] ^= 1;
        let conflicting = fragmented_server_hello_packet(&conflicting_body, 0, body.len());

        assert_eq!(
            server_hello_version_from_fragments([first.as_slice(), conflicting.as_slice()]),
            DetectedVersion::Unknown
        );
    }

    #[test]
    fn server_hello_mismatched_queued_length_blocks_fast_path() {
        let full = server_hello_packet_with_extensions(&[
            0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC, // supported_versions
            0x00, 0x15, 0x00, 0x00, // padding extension header
        ]);
        let body = full[25..].to_vec();
        let first = fragmented_server_hello_packet(&body, 0, body.len() - 4);
        let mut mismatched = fragmented_server_hello_packet(&body, 0, body.len());
        let mismatched_len = body.len() + 1;
        mismatched[14..17].copy_from_slice(&(mismatched_len as u32).to_be_bytes()[1..]);

        assert_eq!(
            server_hello_version_from_fragments([first.as_slice(), mismatched.as_slice()]),
            DetectedVersion::Unknown
        );
    }

    #[test]
    fn server_hello_partial_first_fragment_without_version_is_incomplete() {
        let mut pkt = server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]);
        let partial_body_len = 34;
        let record_len = 12 + partial_body_len;

        pkt[11..13].copy_from_slice(&(record_len as u16).to_be_bytes());
        pkt[22] = 0;
        pkt[23] = (partial_body_len >> 8) as u8;
        pkt[24] = partial_body_len as u8;
        pkt.truncate(13 + record_len);

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Incomplete);
    }

    #[test]
    fn server_hello_multirecord_fragments_can_select_dtls13() {
        let full = server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]);
        let body = full[25..].to_vec();
        let split = 34;
        let mut datagram = fragmented_server_hello_packet(&body, 0, split);
        datagram.extend_from_slice(&fragmented_server_hello_packet(
            &body,
            split,
            body.len() - split,
        ));

        assert_eq!(server_hello_version(&datagram), DetectedVersion::Dtls13);
    }

    #[test]
    fn server_hello_single_record_multiple_fragments_can_select_dtls13() {
        let full = server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]);
        let body = full[25..].to_vec();
        let split = 34;
        let datagram = handshake_record(&[
            fragmented_server_hello_handshake(&body, 0, split),
            fragmented_server_hello_handshake(&body, split, body.len() - split),
        ]);

        assert_eq!(server_hello_version(&datagram), DetectedVersion::Dtls13);
    }

    #[test]
    fn server_hello_malformed_hvr_tail_does_not_force_dtls12() {
        let full = server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]);
        let body = full[25..].to_vec();
        let mut malformed_hvr = Vec::new();
        malformed_hvr.push(3);
        malformed_hvr.extend_from_slice(&[0x00, 0x00, 0x05]);
        malformed_hvr.extend_from_slice(&[0x00, 0x00]);
        malformed_hvr.extend_from_slice(&[0x00, 0x00, 0x00]);
        malformed_hvr.extend_from_slice(&[0x00, 0x00, 0x05]);

        let datagram = handshake_record(&[
            fragmented_server_hello_handshake(&body, 0, body.len()),
            malformed_hvr,
        ]);

        assert_eq!(server_hello_version(&datagram), DetectedVersion::Unknown);
    }

    #[test]
    fn server_hello_valid_hvr_tail_is_unknown() {
        let full = server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]);
        let body = full[25..].to_vec();
        let datagram = handshake_record(&[
            fragmented_server_hello_handshake(&body, 0, body.len()),
            hello_verify_request_handshake(&[0xFE, 0xFD, 0x02, 0xAA, 0xBB]),
        ]);

        assert_eq!(server_hello_version(&datagram), DetectedVersion::Unknown);
    }

    #[test]
    fn server_hello_valid_hvr_prefix_is_unknown() {
        let full = server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]);
        let body = full[25..].to_vec();
        let datagram = handshake_record(&[
            hello_verify_request_handshake(&[0xFE, 0xFD, 0x02, 0xAA, 0xBB]),
            fragmented_server_hello_handshake(&body, 0, body.len()),
        ]);

        assert_eq!(server_hello_version(&datagram), DetectedVersion::Unknown);
    }

    #[test]
    fn server_hello_valid_hvr_prefix_across_records_is_unknown() {
        let full = server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]);
        let body = full[25..].to_vec();
        let mut datagram = handshake_record(&[hello_verify_request_handshake(&[
            0xFE, 0xFD, 0x02, 0xAA, 0xBB,
        ])]);
        datagram.extend_from_slice(&fragmented_server_hello_packet(&body, 0, body.len()));

        assert_eq!(server_hello_version(&datagram), DetectedVersion::Unknown);
    }

    #[test]
    fn server_hello_rejects_too_many_records() {
        let mut datagram = Vec::new();
        for _ in 0..=MAX_SERVER_HELLO_RECORDS_PER_PACKET {
            datagram.extend_from_slice(&ignored_handshake_record());
        }

        assert_eq!(server_hello_version(&datagram), DetectedVersion::Unknown);
    }

    #[test]
    fn server_hello_rejects_too_many_fragments() {
        let mut body = vec![0u8; MAX_SERVER_HELLO_FRAGMENTS + 1];
        body[0..2].copy_from_slice(&[0xFE, 0xFD]);

        let packets: Vec<_> = (0..=MAX_SERVER_HELLO_FRAGMENTS)
            .map(|offset| fragmented_server_hello_packet(&body, offset, 1))
            .collect();

        assert_eq!(
            server_hello_version_from_fragments(packets.iter().map(Vec::as_slice)),
            DetectedVersion::Unknown
        );
    }

    #[test]
    fn pending_server_response_rejects_oversized_incomplete_packet() {
        let config = Arc::new(Config::builder().build().expect("config"));
        let certificate = DtlsCertificate {
            certificate: vec![1],
            private_key: vec![1],
        };
        let mut pending =
            ClientPending::new(config, certificate, Instant::now()).expect("pending client");

        let full = server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]);
        let body = full[25..].to_vec();
        let mut packet = fragmented_server_hello_packet(&body, 0, 34);
        packet.extend_from_slice(&{
            let mut tail = Vec::new();
            tail.push(0x17);
            tail.extend_from_slice(&[0xFE, 0xFD]);
            tail.extend_from_slice(&[0x00, 0x00]);
            tail.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            tail.extend_from_slice(&(MAX_PENDING_SERVER_RESPONSE_BYTES as u16).to_be_bytes());
            tail.resize(13 + MAX_PENDING_SERVER_RESPONSE_BYTES, 0);
            tail
        });

        assert_eq!(server_hello_version(&packet), DetectedVersion::Unknown);
        assert!(matches!(
            pending.push_server_response_fragment(&packet),
            Err(Error::TooManyServerHelloFragments)
        ));
        assert!(pending.server_response_fragments.is_empty());
    }

    #[test]
    fn duplicate_retransmitted_fragment_does_not_consume_buffer_slot() {
        let full = server_hello_packet_with_extensions(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]);
        let body = full[25..].to_vec();
        let fragment = fragmented_server_hello_packet(&body, 0, 34);
        let mut retransmit = fragment.clone();
        retransmit[10] ^= 1; // record sequence differs, handshake fragment does not

        let mut queued = ArrayVec::<Buf, MAX_PENDING_SERVER_RESPONSE_PACKETS>::new();
        let mut buf = Buf::new();
        buf.extend_from_slice(&fragment);
        queued.push(buf);

        assert!(!packet_has_new_server_hello_fragment(&queued, &retransmit));
    }

    #[test]
    fn server_hello_rejects_overlong_session_id() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0xFE, 0xFD]); // legacy version DTLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(33); // session_id length exceeds protocol maximum
        body.extend_from_slice(&[0u8; 33]);
        body.extend_from_slice(&[0x13, 0x01]); // cipher_suite AES_128_GCM_SHA256
        body.push(0x00); // compression_method = null
        body.extend_from_slice(&6u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]);

        assert_eq!(
            server_hello_version(&server_hello_packet_with_body(&body)),
            DetectedVersion::Unknown
        );
    }

    #[test]
    fn server_hello_rejects_one_byte_extensions_length() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0xFE, 0xFD]); // legacy version DTLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id length = 0
        body.extend_from_slice(&[0x13, 0x01]); // cipher_suite AES_128_GCM_SHA256
        body.push(0x00); // compression_method = null
        body.push(0x00); // truncated extensions length

        assert_eq!(
            server_hello_version(&server_hello_packet_with_body(&body)),
            DetectedVersion::Unknown
        );
    }

    #[test]
    fn server_hello_rejects_trailing_bytes_after_extensions_vector() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0xFE, 0xFD]); // legacy version DTLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id length = 0
        body.extend_from_slice(&[0x13, 0x01]); // cipher_suite AES_128_GCM_SHA256
        body.push(0x00); // compression_method = null
        body.extend_from_slice(&0u16.to_be_bytes()); // extensions length = 0
        body.extend_from_slice(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]); // trailing bytes

        assert_eq!(
            server_hello_version(&server_hello_packet_with_body(&body)),
            DetectedVersion::Unknown
        );
    }

    #[test]
    fn server_hello_rejects_trailing_bytes_after_valid_supported_versions_vector() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0xFE, 0xFD]); // legacy version DTLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id length = 0
        body.extend_from_slice(&[0x13, 0x01]); // cipher_suite AES_128_GCM_SHA256
        body.push(0x00); // compression_method = null
        body.extend_from_slice(&6u16.to_be_bytes()); // declared extensions length
        body.extend_from_slice(&[0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC]); // supported_versions
        body.push(0x00); // trailing byte outside declared vector

        assert_eq!(
            server_hello_version(&server_hello_packet_with_body(&body)),
            DetectedVersion::Unknown
        );
    }

    #[test]
    fn server_hello_rejects_oversized_extensions_vector() {
        let mut pkt = server_hello_packet_with_extensions(&[]);
        let ext_len_pos = pkt.len() - 2;

        pkt[ext_len_pos..].copy_from_slice(&4u16.to_be_bytes());

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
    }

    #[test]
    fn server_hello_rejects_trailing_partial_extension_header() {
        for trailing in [&[0x00][..], &[0x00, 0x2B][..], &[0x00, 0x2B, 0x00][..]] {
            assert_eq!(
                server_hello_version(&server_hello_packet_with_extensions(trailing)),
                DetectedVersion::Unknown
            );
        }
    }

    #[test]
    fn server_hello_rejects_malformed_tail_after_supported_versions() {
        for trailing in [&[0x00][..], &[0x00, 0x2B][..], &[0x00, 0x2B, 0x00][..]] {
            let mut extensions = vec![0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC];
            extensions.extend_from_slice(trailing);

            assert_eq!(
                server_hello_version(&server_hello_packet_with_extensions(&extensions)),
                DetectedVersion::Unknown
            );
        }
    }

    #[test]
    fn server_hello_rejects_oversized_extension_after_supported_versions() {
        let pkt = server_hello_packet_with_extensions(&[
            0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC, 0x00, 0x0A, 0x00, 0x04, 0x01, 0x02,
        ]);

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
    }

    #[test]
    fn server_hello_without_supported_versions_is_dtls12() {
        let mut pkt = Vec::new();
        // Record header
        pkt.push(0x16);
        pkt.extend_from_slice(&[0xFE, 0xFD]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]);

        // Handshake header: msg_type=2 (ServerHello)
        pkt.push(2);
        let hs_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        let frag_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);

        let body_start = pkt.len();

        // ServerHello body without extensions
        pkt.extend_from_slice(&[0xFE, 0xFD]); // version
        pkt.extend_from_slice(&[0u8; 32]); // random
        pkt.push(0x00); // session_id length
        pkt.extend_from_slice(&[0xC0, 0x2B]); // cipher_suite (1.2 ECDHE)
        pkt.push(0x00); // compression

        let body_len = pkt.len() - body_start;
        pkt[hs_len_pos] = 0;
        pkt[hs_len_pos + 1] = (body_len >> 8) as u8;
        pkt[hs_len_pos + 2] = body_len as u8;
        pkt[frag_len_pos] = 0;
        pkt[frag_len_pos + 1] = (body_len >> 8) as u8;
        pkt[frag_len_pos + 2] = body_len as u8;

        let record_len = (pkt.len() - 13) as u16;
        pkt[len_pos] = (record_len >> 8) as u8;
        pkt[len_pos + 1] = record_len as u8;

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Dtls12);
    }

    #[test]
    fn garbage_packet_is_unknown() {
        assert_eq!(
            server_hello_version(&[0xFF, 0x00]),
            DetectedVersion::Unknown
        );
        assert_eq!(server_hello_version(&[]), DetectedVersion::Unknown);
    }

    #[test]
    fn too_short_is_unknown() {
        // Non-handshake content type
        let pkt = [
            0x17, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF,
        ];
        assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
    }

    #[test]
    fn hybrid_client_hello_excludes_psk_dtls12_suites() {
        let config = Arc::new(
            Config::builder()
                .with_psk_client(b"identity".to_vec(), Arc::new(DummyResolver))
                .build()
                .expect("config with PSK should build"),
        );

        assert!(
            config.dtls12_cipher_suites().any(|cs| cs.suite().is_psk()),
            "precondition: PSK-enabled config should expose a PSK DTLS 1.2 suite"
        );

        let hybrid = HybridClientHello::new(&config).expect("hybrid ClientHello should build");
        let offered = offered_cipher_suites(&hybrid);

        assert!(
            !offered.contains(&Dtls12CipherSuite::PSK_AES128_CCM_8.as_u16()),
            "auto client must not advertise PSK DTLS 1.2 suites it cannot use after fallback"
        );
    }
}
