use std::collections::VecDeque;
use std::mem;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use arrayvec::ArrayVec;

use super::queue::{QueueRx, QueueTx};
use crate::buffer::{Buf, BufferPool, TmpBuf};
use crate::crypto::{Aad, Iv, Nonce};
use crate::dtls12::context::{AuthMode, CryptoContext};
use crate::dtls12::incoming::{Incoming, Record, RecordHandler};
use crate::dtls12::message::{Body, HashAlgorithm, Header, MessageType, ProtocolVersion, Sequence};
use crate::dtls12::message::{ContentType, DTLSRecord, Dtls12CipherSuite, Handshake};
use crate::timer::ExponentialBackoff;
use crate::window::ReplayWindow;
use crate::{Config, Error, Output, SeededRng};

const MAX_DEFRAGMENT_PACKETS: usize = 50;
const MAX_PRE_KEY_CANDIDATES_PER_SEQUENCE: usize = 2;

enum PollBuffer<'a> {
    Ready(&'a [u8]),
    Empty(&'a mut [u8]),
    TooSmall { needed: usize },
}

// Using debug_ignore_primary since CryptoContext doesn't implement Debug
pub struct Engine {
    config: Arc<Config>,

    /// Seedable random number generator for deterministic testing
    pub(crate) rng: SeededRng,

    /// Pool of buffers
    buffers_free: BufferPool,

    /// Counters for sending DTLSRecord during epoch 0.
    ///
    /// This is kept separate since resends might force us to
    /// "go back" to these sequence number even if we technically
    /// progressed to epoch 1.
    sequence_epoch_0: Sequence,

    /// Counters for epoch 1 and beyond.
    sequence_epoch_n: Sequence,

    /// Queue of incoming packets.
    queue_rx: QueueRx,

    /// Queue of outgoing packets.
    queue_tx: QueueTx,

    /// The cipher suite in use. Set by ServerHello.
    cipher_suite: Option<Dtls12CipherSuite>,

    /// Per-record explicit nonce length (from provider). 0 for ChaCha20, 8 for AES-GCM.
    explicit_nonce_len: usize,

    /// AEAD tag length (from provider).
    tag_len: usize,

    /// Cryptographic context for handling encryption/decryption
    pub(crate) crypto_context: CryptoContext,

    /// Whether the remote peer has enabled encryption
    peer_encryption_enabled: bool,

    /// Whether this engine is for a client (true) or server (false)
    is_client: bool,

    /// Expected peer handshake sequence number
    peer_handshake_seq_no: u16,

    /// Next handshake message sequence number for sending
    next_handshake_seq_no: u16,

    /// Handshakes collected for hash computation.
    ///
    /// NB: pub(crate) because we need to sign it in client.rs
    pub(crate) transcript: Buf,

    /// Anti-replay window state (per current epoch)
    replay: ReplayWindow,

    /// The records that have been sent in the current flight.
    flight_saved_records: Vec<Entry>,

    /// Flight backoff
    flight_backoff: ExponentialBackoff,

    /// Timeout for the current flight
    flight_timeout: Timeout,

    /// Global timeout for the entire connect operation.
    connect_timeout: Timeout,

    /// Whether we are ready to release application data from poll_output.
    release_app_data: bool,

    /// Whether a close_notify alert has been received from the peer.
    close_notify_received: bool,

    /// Whether [`Output::CloseNotify`] has already been emitted.
    close_notify_reported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Timeout {
    Disabled,
    Unarmed,
    Armed(Instant),
}

#[derive(Debug)]
struct Entry {
    content_type: ContentType,
    epoch: u16,
    fragment: Buf,
}

impl Engine {
    pub fn new(config: Arc<Config>, auth: AuthMode) -> Self {
        let mut rng = SeededRng::new(config.rng_seed());

        let flight_backoff =
            ExponentialBackoff::new(config.flight_start_rto(), config.flight_retries(), &mut rng);

        let crypto_context = CryptoContext::new(auth, Arc::clone(&config));

        Self {
            config,
            rng,
            buffers_free: BufferPool::default(),
            sequence_epoch_0: Sequence::new(0),
            sequence_epoch_n: Sequence::new(1),
            queue_rx: QueueRx::new(),
            queue_tx: QueueTx::new(),
            cipher_suite: None,
            explicit_nonce_len: 0,
            tag_len: 0,
            crypto_context,
            peer_encryption_enabled: false,
            is_client: false,
            peer_handshake_seq_no: 0,
            next_handshake_seq_no: 0,
            transcript: Buf::new(),
            replay: ReplayWindow::new(),
            flight_saved_records: Vec::new(),
            flight_backoff,
            flight_timeout: Timeout::Unarmed,
            connect_timeout: Timeout::Unarmed,
            release_app_data: false,
            close_notify_received: false,
            close_notify_reported: false,
        }
    }

    pub fn set_client(&mut self, is_client: bool) {
        self.is_client = is_client;
    }

    /// Set the next outgoing handshake message sequence number.
    ///
    /// Used by `Client::new_from_hybrid` to account for the hybrid
    /// ClientHello (message_seq=0) that was already sent outside this engine.
    pub fn set_next_handshake_seq_no(&mut self, seq: u16) {
        self.next_handshake_seq_no = seq;
    }

    /// Advance the epoch-0 record sequence number by one.
    ///
    /// Used by `Client::new_from_hybrid` so subsequent epoch-0 records
    /// don't reuse the sequence number of the hybrid ClientHello record.
    pub fn advance_epoch_0_sequence(&mut self) {
        self.sequence_epoch_0.sequence_number += 1;
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get a reference to the cipher suite
    pub fn cipher_suite(&self) -> Option<Dtls12CipherSuite> {
        self.cipher_suite
    }

    /// Total per-record AEAD overhead: explicit_nonce_len + tag_len.
    pub fn aead_overhead(&self) -> usize {
        self.explicit_nonce_len + self.tag_len
    }

    /// Is the given cipher suite allowed by configuration
    pub fn is_cipher_suite_allowed(&self, suite: Dtls12CipherSuite) -> bool {
        self.config
            .dtls12_cipher_suites()
            .any(|cs| cs.suite() == suite)
    }

    /// Get a reference to the crypto context
    pub fn crypto_context(&self) -> &CryptoContext {
        &self.crypto_context
    }

    /// Get a mutable reference to the crypto context
    pub fn crypto_context_mut(&mut self) -> &mut CryptoContext {
        &mut self.crypto_context
    }

    pub fn parse_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        let cs = self.cipher_suite;
        let incoming = Incoming::parse_packet(packet, self, cs)?;
        if let Some(incoming) = incoming {
            self.insert_incoming(incoming)?;
        }

        Ok(())
    }

    pub(crate) fn parse_packet_filtering_records(
        &mut self,
        packet: &[u8],
        keep_record: impl FnMut(&Record) -> bool,
    ) -> Result<(), Error> {
        let cs = self.cipher_suite;
        let incoming = Incoming::parse_packet_filtering_records(packet, self, cs, keep_record)?;
        if let Some(incoming) = incoming {
            self.insert_incoming(incoming)?;
        }

        Ok(())
    }

    /// Insert a parsed datagram into the receive queue.
    fn insert_incoming(&mut self, incoming: Incoming) -> Result<(), Error> {
        if self.queue_rx.len() >= self.config.max_queue_rx()
            && (incoming.first().first_handshake().is_some() || self.peer_encryption_enabled)
        {
            if self.can_merge_incoming_record_count(incoming.records().len()) {
                self.merge_incoming_into_existing(incoming, false)?;
                return Ok(());
            }

            warn!(
                "Receive queue full (max {}): {:?}",
                self.config.max_queue_rx(),
                self.queue_rx
            );
            return Err(Error::ReceiveQueueFull);
        }

        // Dispatch to specialized handlers
        if incoming.first().first_handshake().is_some() {
            self.insert_incoming_handshake(incoming)
        } else {
            self.insert_incoming_non_handshake(incoming)
        }
    }

    fn insert_incoming_handshake(&mut self, incoming: Incoming) -> Result<(), Error> {
        let first_record = incoming.first();
        let handshake = first_record
            .first_handshake()
            .expect("caller ensures handshake");

        let key_current = (
            handshake.header.message_seq,
            handshake.header.fragment_offset,
        );

        let maybe_dupe_seq = incoming
            .records()
            .iter()
            .filter_map(|r| r.first_handshake())
            .filter_map(|h| h.dupe_triggers_resend())
            .next();

        // Some MessageType when resent, means we must trigger
        // an immediate resend of the entire flight.
        if let Some(dupe_seq) = maybe_dupe_seq {
            if dupe_seq < self.peer_handshake_seq_no {
                self.flight_resend("dupe triggers resend")?;
            }
        }

        // Drop old duplicates we've already processed - don't let them block newer messages.
        if handshake.header.message_seq < self.peer_handshake_seq_no {
            return Ok(());
        }

        if self.peer_encryption_enabled && first_record.record().sequence.epoch == 0 {
            // Keep old plaintext handshake records available long enough to
            // trigger flight resends above, but never queue or process them as
            // new messages after peer encryption is enabled.
            return Ok(());
        }

        // Reject new handshakes after initial handshake is complete (renegotiation not supported).
        if self.release_app_data && handshake.header.message_seq >= self.peer_handshake_seq_no {
            return Err(Error::RenegotiationAttempt);
        }

        let search_result = self.queue_rx.binary_search_by(|item| {
            let key_other = item
                .first()
                .first_handshake()
                .as_ref()
                .map(|h| (h.header.message_seq, h.header.fragment_offset))
                .unwrap_or((u16::MAX, u32::MAX));
            key_other.cmp(&key_current)
        });

        match search_result {
            Err(index) => {
                // Insert in order of handshake key
                self.queue_rx.insert(index, incoming);
            }
            Ok(_) => {
                // Exact duplicate handshake fragment
            }
        }

        Ok(())
    }

    fn insert_incoming_non_handshake(&mut self, incoming: Incoming) -> Result<(), Error> {
        let first = incoming.first();
        let seq_current = first.record().sequence;

        if self.peer_encryption_enabled
            && seq_current.epoch == 0
            && first.record().content_type == ContentType::Handshake
        {
            return Ok(());
        }

        if self.queue_rx.len() >= self.config.max_queue_rx()
            && self.is_full_queue_priority_non_handshake(first)
            && self.can_merge_incoming_record_count(incoming.records().len())
        {
            self.merge_incoming_into_existing(incoming, true)?;
            return Ok(());
        }

        if self.peer_encryption_enabled {
            for record in incoming.records().iter() {
                if record.record().sequence.epoch == 0
                    && record.record().content_type == ContentType::Handshake
                {
                    if record.handshakes().is_empty() {
                        record.set_handled();
                    } else {
                        for handshake in record.handshakes() {
                            handshake.set_handled();
                        }
                    }
                }
            }
        }

        if self
            .queue_rx
            .iter()
            .any(|queued| incoming_records_equal(queued, &incoming))
        {
            return Ok(());
        }

        if self.queue_rx.len() >= self.config.max_queue_rx() {
            self.ensure_full_queue_can_accept_non_handshake(&incoming)?;
        }

        let mut pending = ArrayVec::new();
        for record in incoming.into_records() {
            self.insert_or_stage_non_handshake_record(record, &mut pending)?;
        }

        if let Some(incoming) = Incoming::from_records(pending) {
            if self.queue_rx.len() >= self.config.max_queue_rx() {
                warn!(
                    "Receive queue full (max {}): {:?}",
                    self.config.max_queue_rx(),
                    self.queue_rx
                );
                return Err(Error::ReceiveQueueFull);
            }

            self.insert_non_handshake_sorted(incoming);
        }

        Ok(())
    }

    fn can_merge_incoming_record_count(&self, count: usize) -> bool {
        self.queue_rx
            .iter()
            .any(|queued| queued.records().len() + count <= queued.records().capacity())
    }

    fn is_full_queue_priority_non_handshake(&self, record: &Record) -> bool {
        let dtls = record.record();
        dtls.content_type == ContentType::ChangeCipherSpec
            || (!self.peer_encryption_enabled
                && dtls.content_type == ContentType::Handshake
                && dtls.sequence.epoch == 1)
    }

    fn merge_incoming_into_existing(
        &mut self,
        incoming: Incoming,
        prepend: bool,
    ) -> Result<(), Error> {
        let count = incoming.records().len();
        let Some(index) = self
            .queue_rx
            .iter()
            .position(|queued| queued.records().len() + count <= queued.records().capacity())
        else {
            warn!(
                "Receive queue full (max {}): cannot merge priority record",
                self.config.max_queue_rx()
            );
            return Err(Error::ReceiveQueueFull);
        };

        let queued = self
            .queue_rx
            .remove(index)
            .expect("merge index was selected from queue_rx");
        let mut records = ArrayVec::new();

        if prepend {
            for record in incoming.into_records() {
                records
                    .try_push(record)
                    .map_err(|_| Error::TooManyRecords)?;
            }
            for record in queued.into_records() {
                records
                    .try_push(record)
                    .map_err(|_| Error::TooManyRecords)?;
            }
        } else {
            for record in queued.into_records() {
                records
                    .try_push(record)
                    .map_err(|_| Error::TooManyRecords)?;
            }
            for record in incoming.into_records() {
                records
                    .try_push(record)
                    .map_err(|_| Error::TooManyRecords)?;
            }
        }

        let merged = Incoming::from_records(records).expect("incoming contributes records");
        self.insert_non_handshake_sorted(merged);
        Ok(())
    }

    fn ensure_full_queue_can_accept_non_handshake(&self, incoming: &Incoming) -> Result<(), Error> {
        let mut counts: Vec<(Sequence, usize)> = Vec::new();
        let mut remaining_capacity: Vec<usize> = self
            .queue_rx
            .iter()
            .map(|queued| queued.records().capacity() - queued.records().len())
            .collect();

        for (record_index, record) in incoming.records().iter().enumerate() {
            if record.first_handshake().is_some() {
                continue;
            }

            if self.queued_record_equal(record)
                || incoming.records()[..record_index]
                    .iter()
                    .any(|candidate| candidate.buffer() == record.buffer())
            {
                continue;
            }

            let sequence = record.record().sequence;
            let count_index = match counts.iter().position(|(seq, _)| *seq == sequence) {
                Some(index) => index,
                None => {
                    counts.push((sequence, self.non_handshake_sequence_count(sequence)));
                    counts.len() - 1
                }
            };
            let count = &mut counts[count_index].1;

            if *count == 0 {
                warn!(
                    "Receive queue full (max {}): {:?}",
                    self.config.max_queue_rx(),
                    self.queue_rx
                );
                return Err(Error::ReceiveQueueFull);
            }

            if *count < MAX_PRE_KEY_CANDIDATES_PER_SEQUENCE {
                let Some(index) = self
                    .queue_rx
                    .iter()
                    .enumerate()
                    .position(|(index, queued)| {
                        remaining_capacity[index] > 0
                            && incoming_has_non_handshake_sequence(queued, sequence)
                    })
                else {
                    warn!(
                        "Receive queue full (max {}): cannot merge same-sequence candidate",
                        self.config.max_queue_rx()
                    );
                    return Err(Error::ReceiveQueueFull);
                };
                remaining_capacity[index] -= 1;
                *count += 1;
            }
        }

        Ok(())
    }

    fn insert_or_stage_non_handshake_record(
        &mut self,
        record: Record,
        pending: &mut ArrayVec<Record, 8>,
    ) -> Result<(), Error> {
        if self.queued_or_pending_record_equal(&record, pending) {
            self.buffers_free.push(record.into_buffer());
            return Ok(());
        }

        let sequence = record.record().sequence;
        let queued_count = self.non_handshake_sequence_count(sequence);
        let pending_count = pending
            .iter()
            .filter(|candidate| non_handshake_sequence_matches(candidate, sequence))
            .count();

        if queued_count + pending_count >= MAX_PRE_KEY_CANDIDATES_PER_SEQUENCE {
            if let Some(index) = pending
                .iter()
                .rposition(|candidate| non_handshake_sequence_matches(candidate, sequence))
            {
                let removed = pending.remove(index);
                self.buffers_free.push(removed.into_buffer());
                pending
                    .try_push(record)
                    .map_err(|_| Error::TooManyRecords)?;
            } else {
                self.replace_newest_non_handshake_sequence_candidate(sequence, record)?;
            }
            return Ok(());
        }

        if queued_count > 0 && self.non_handshake_sequence_merge_index(sequence).is_some() {
            self.merge_non_handshake_record(sequence, record)?;
            return Ok(());
        }

        if self.queue_rx.len() >= self.config.max_queue_rx() {
            warn!(
                "Receive queue full (max {}): {:?}",
                self.config.max_queue_rx(),
                self.queue_rx
            );
            return Err(Error::ReceiveQueueFull);
        }

        pending
            .try_push(record)
            .map_err(|_| Error::TooManyRecords)?;
        Ok(())
    }

    fn queued_or_pending_record_equal(
        &self,
        record: &Record,
        pending: &ArrayVec<Record, 8>,
    ) -> bool {
        self.queued_record_equal(record)
            || pending
                .iter()
                .any(|queued| queued.buffer() == record.buffer())
    }

    fn queued_record_equal(&self, record: &Record) -> bool {
        self.queue_rx
            .iter()
            .flat_map(|queued| queued.records().iter())
            .any(|queued| queued.buffer() == record.buffer())
    }

    fn non_handshake_sequence_count(&self, sequence: Sequence) -> usize {
        self.queue_rx
            .iter()
            .flat_map(|incoming| incoming.records().iter())
            .filter(|record| non_handshake_sequence_matches(record, sequence))
            .count()
    }

    fn replace_newest_non_handshake_sequence_candidate(
        &mut self,
        sequence: Sequence,
        record: Record,
    ) -> Result<(), Error> {
        let Some((incoming_index, record_index)) =
            self.newest_non_handshake_sequence_record_index(sequence)
        else {
            return Err(Error::ReceiveQueueFull);
        };

        let queued = self
            .queue_rx
            .remove(incoming_index)
            .expect("replacement index was selected from queue_rx");
        let mut replacement = Some(record);
        let mut records = ArrayVec::new();

        for (index, queued_record) in queued.into_records().enumerate() {
            if index == record_index {
                self.buffers_free.push(queued_record.into_buffer());
                records
                    .try_push(replacement.take().expect("replacement used once"))
                    .map_err(|_| Error::TooManyRecords)?;
            } else {
                records
                    .try_push(queued_record)
                    .map_err(|_| Error::TooManyRecords)?;
            }
        }

        let merged = Incoming::from_records(records).expect("incoming contributes records");
        self.insert_non_handshake_sorted(merged);
        Ok(())
    }

    fn merge_non_handshake_record(
        &mut self,
        sequence: Sequence,
        record: Record,
    ) -> Result<(), Error> {
        let Some(index) = self.non_handshake_sequence_merge_index(sequence) else {
            warn!(
                "Receive queue full (max {}): cannot merge same-sequence candidate",
                self.config.max_queue_rx()
            );
            return Err(Error::ReceiveQueueFull);
        };

        let queued = self
            .queue_rx
            .remove(index)
            .expect("merge index was selected from queue_rx");
        let mut records = ArrayVec::new();

        for queued_record in queued.into_records() {
            records
                .try_push(queued_record)
                .map_err(|_| Error::TooManyRecords)?;
        }
        records
            .try_push(record)
            .map_err(|_| Error::TooManyRecords)?;

        let merged = Incoming::from_records(records).expect("incoming contributes records");
        self.insert_non_handshake_sorted(merged);
        Ok(())
    }

    fn non_handshake_sequence_merge_index(&self, sequence: Sequence) -> Option<usize> {
        self.queue_rx.iter().position(|queued| {
            queued.records().len() < queued.records().capacity()
                && incoming_has_non_handshake_sequence(queued, sequence)
        })
    }

    fn newest_non_handshake_sequence_record_index(
        &self,
        sequence: Sequence,
    ) -> Option<(usize, usize)> {
        self.newest_non_handshake_sequence_record_index_with_first_sequence(sequence)
            .or_else(|| {
                self.queue_rx
                    .iter()
                    .enumerate()
                    .rev()
                    .find_map(|(incoming_index, incoming)| {
                        incoming
                            .records()
                            .iter()
                            .rposition(|record| non_handshake_sequence_matches(record, sequence))
                            .map(|record_index| (incoming_index, record_index))
                    })
            })
    }

    fn newest_non_handshake_sequence_record_index_with_first_sequence(
        &self,
        sequence: Sequence,
    ) -> Option<(usize, usize)> {
        self.queue_rx
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, incoming)| incoming.first().record().sequence == sequence)
            .find_map(|(incoming_index, incoming)| {
                incoming
                    .records()
                    .iter()
                    .rposition(|record| non_handshake_sequence_matches(record, sequence))
                    .map(|record_index| (incoming_index, record_index))
            })
    }

    fn insert_non_handshake_sorted(&mut self, incoming: Incoming) {
        let seq_current = incoming.first().record().sequence;
        let index = self
            .queue_rx
            .binary_search_by_key(&seq_current, |item| item.first().record().sequence)
            .map(|mut index| {
                while index < self.queue_rx.len()
                    && self.queue_rx[index].first().record().sequence == seq_current
                {
                    index += 1;
                }
                index
            })
            .unwrap_or_else(|index| index);
        self.queue_rx.insert(index, incoming);
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        if self.connect_timeout == Timeout::Unarmed {
            debug!(
                "Connect timeout in: {:.03}s",
                self.config.handshake_timeout().as_secs_f32()
            );
            let timeout = now + self.config.handshake_timeout();
            self.connect_timeout = Timeout::Armed(timeout);
        }
        if self.flight_timeout == Timeout::Unarmed {
            debug!(
                "Flight timeout in: {:.03}s",
                self.flight_backoff.rto().as_secs_f32()
            );
            let timeout = now + self.flight_backoff.rto();
            self.flight_timeout = Timeout::Armed(timeout);
        }

        // The connect timeout is the overall timeout for establishing the connection
        if let Timeout::Armed(connect_timeout) = self.connect_timeout {
            if now >= connect_timeout {
                return Err(Error::Timeout("connect"));
            }
        }

        // If there is no flight timeout, we have already checked the global connect timeout.
        let Timeout::Armed(flight_timeout) = self.flight_timeout else {
            return Ok(());
        };

        if now >= flight_timeout {
            if self.flight_backoff.can_retry() {
                self.flight_backoff.attempt(&mut self.rng);
                debug!(
                    "Re-arm flight timeout due to resend in {}",
                    self.flight_backoff.rto().as_secs_f32()
                );
                let timeout = now + self.flight_backoff.rto();
                self.flight_timeout = Timeout::Armed(timeout);
                self.flight_resend("flight timeout")?;
            } else {
                return Err(Error::Timeout("handshake"));
            }
        }

        Ok(())
    }

    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8], now: Instant) -> Output<'a> {
        // Drain incoming queue of processed records.
        self.purge_handled_queue_rx();

        // First check if we have any decrypted app data.
        let buf = match self.poll_app_data(buf) {
            PollBuffer::Ready(p) => return Output::ApplicationData(p),
            PollBuffer::Empty(b) => b,
            PollBuffer::TooSmall { needed } => return Output::BufferTooSmall { needed },
        };

        match self.poll_packet_tx(buf) {
            PollBuffer::Ready(p) => return Output::Packet(p),
            PollBuffer::Empty(_) => {}
            PollBuffer::TooSmall { needed } => return Output::BufferTooSmall { needed },
        }

        if self.close_notify_received && !self.close_notify_reported {
            self.close_notify_reported = true;
            return Output::CloseNotify;
        }

        let next_timeout = self.poll_timeout(now);

        Output::Timeout(next_timeout)
    }

    fn poll_app_data<'a>(&mut self, buf: &'a mut [u8]) -> PollBuffer<'a> {
        if !self.release_app_data {
            return PollBuffer::Empty(buf);
        }

        let unhandled = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .filter(|r| r.record().content_type == ContentType::ApplicationData)
            .filter(|r| !r.is_handled());

        for next in unhandled {
            if !self.peer_encryption_enabled || next.record().sequence.epoch != 1 {
                next.set_handled();
                continue;
            }

            let record_buffer = next.buffer();
            let fragment = next.record().fragment(record_buffer);
            let len = fragment.len();

            if len > buf.len() {
                return PollBuffer::TooSmall { needed: len };
            }

            buf[..len].copy_from_slice(fragment);
            next.set_handled();

            return PollBuffer::Ready(&buf[..len]);
        }

        PollBuffer::Empty(buf)
    }

    fn purge_handled_queue_rx(&mut self) {
        while let Some(peek) = self.queue_rx.front() {
            let fully_handled = peek.records().iter().all(|r| r.is_handled());

            if fully_handled {
                let incoming = self.queue_rx.pop_front().unwrap();
                incoming
                    .into_records()
                    .for_each(|r| self.buffers_free.push(r.into_buffer()));
            } else {
                break;
            }
        }
    }

    fn poll_packet_tx<'a>(&mut self, buf: &'a mut [u8]) -> PollBuffer<'a> {
        let Some(p) = self.queue_tx.front() else {
            return PollBuffer::Empty(buf);
        };

        let len = p.len();
        if len > buf.len() {
            return PollBuffer::TooSmall { needed: len };
        }

        buf[..len].copy_from_slice(p);
        self.queue_tx.pop_front();

        PollBuffer::Ready(&buf[..len])
    }

    fn poll_timeout(&self, now: Instant) -> Instant {
        // No timeouts, return a distant future
        if self.connect_timeout == Timeout::Disabled && self.flight_timeout == Timeout::Disabled {
            const DISTANT_FUTURE: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);
            return now + DISTANT_FUTURE;
        }

        match (self.connect_timeout, self.flight_timeout) {
            (Timeout::Armed(c), Timeout::Armed(f)) => {
                if c < f {
                    c
                } else {
                    f
                }
            }
            (Timeout::Armed(c), _) => c,
            (_, Timeout::Armed(f)) => f,
            // Both Unarmed or mixed Unarmed/Disabled: return current time
            // to trigger handle_timeout on the next cycle.
            _ => now,
        }
    }

    pub fn flight_begin(&mut self, flight_no: u8) {
        debug!("Begin flight {}", flight_no);
        self.flight_backoff.reset(&mut self.rng);
        self.flight_clear_resends();
        self.flight_timeout = Timeout::Unarmed;
    }

    pub fn flight_stop_resend_timers(&mut self) {
        debug!("Stop connect and flight timeouts");
        self.flight_timeout = Timeout::Disabled;
        self.connect_timeout = Timeout::Disabled;
    }

    fn flight_clear_resends(&mut self) {
        for entry in self.flight_saved_records.drain(..) {
            self.buffers_free.push(entry.fragment);
        }
    }

    fn flight_resend(&mut self, reason: &str) -> Result<(), Error> {
        debug!("Resending flight due to {}", reason);

        let replace_pending_handshake_output = !self.release_app_data;

        if replace_pending_handshake_output {
            self.queue_tx.clear();
        }

        // For lifetime issues, we take the entries out of self
        let records = mem::take(&mut self.flight_saved_records);

        let mut result = Ok(());
        for (index, entry) in records.iter().enumerate() {
            result = self.create_record_inner(
                entry.content_type,
                entry.epoch,
                false,
                replace_pending_handshake_output && index == 0,
                |fragment| {
                    fragment.extend_from_slice(&entry.fragment);
                },
            );
            if result.is_err() {
                break;
            }
        }

        // Put the entries back into self
        self.flight_saved_records = records;

        result
    }

    pub fn has_complete_handshake(&mut self, wanted: MessageType) -> bool {
        self.has_complete_handshake_with_seq(wanted, self.peer_handshake_seq_no)
    }

    fn has_complete_handshake_with_seq(&mut self, wanted: MessageType, expected_seq: u16) -> bool {
        let mut skip_handled = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .skip_while(|r| r.is_handled())
            // Cap to MAX_DEFRAGMENT_PACKETS to avoid misbehaving peers
            .take(MAX_DEFRAGMENT_PACKETS)
            .flat_map(|r| r.handshakes().iter())
            .skip_while(|h| h.is_handled())
            .peekable();

        let maybe_first_handshake = skip_handled.peek();

        let Some(first) = maybe_first_handshake else {
            return false;
        };

        if first.header.message_seq != expected_seq {
            return false;
        }

        if first.header.msg_type != wanted {
            return false;
        }

        let wanted_seq = first.header.message_seq;
        let wanted_length = first.header.length;
        let mut last_fragment_end = 0;

        for h in skip_handled {
            // A different seq means we're looking at a different handshake
            if wanted_seq != h.header.message_seq {
                continue;
            }

            // Check fragment contiguity
            if h.header.fragment_offset != last_fragment_end {
                return false;
            }
            last_fragment_end = h.header.fragment_offset + h.header.fragment_length;

            // Found the last fragment to complete the wanted handshake.
            if last_fragment_end == wanted_length {
                return true;
            }
        }

        false
    }

    pub fn next_handshake(
        &mut self,
        wanted: MessageType,
        defragment_buffer: &mut Buf,
    ) -> Result<Option<Handshake>, Error> {
        if !self.has_complete_handshake(wanted) {
            return Ok(None);
        }

        let iter = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .skip_while(|r| r.is_handled())
            .flat_map(|r| r.handshakes().iter().map(move |h| (h, r.buffer())))
            .skip_while(|(h, _)| h.is_handled());

        // This sets the handled flag on the handshake.
        // Passing Some(&mut self.transcript) to have defragment write to transcript
        // before creating the handshake, avoiding borrow conflicts.
        let handshake = Handshake::defragment(
            iter,
            defragment_buffer,
            self.cipher_suite,
            Some(&mut self.transcript),
        )?;

        // Move the expected seq_no along
        self.peer_handshake_seq_no = handshake.header.message_seq + 1;

        Ok(Some(handshake))
    }

    pub(crate) fn next_record(&mut self, ctype: ContentType) -> Option<&Record> {
        let record = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .find(|r| !r.is_handled())?;

        if record.record().content_type != ctype {
            return None;
        }

        record.set_handled();

        Some(record)
    }

    /// Mark any pending ChangeCipherSpec records as handled and purge them.
    /// We can accumulate multiple ChangeCipherSpec due to resends. Since they
    /// don't have any Handshake message_seq and each resend gives a new DTLSRecord
    /// sequence number, we might have multiple.
    pub fn drop_pending_ccs(&mut self) {
        for incoming in self.queue_rx.iter() {
            for record in incoming.records().iter() {
                if record.record().content_type == ContentType::ChangeCipherSpec {
                    record.set_handled();
                }
            }
        }
    }

    /// Create a DTLS record and serialize it into a buffer
    pub fn create_record<F>(
        &mut self,
        content_type: ContentType,
        epoch: u16,
        save_fragment: bool,
        f: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf),
    {
        self.create_record_inner(content_type, epoch, save_fragment, false, f)
    }

    fn create_record_inner<F>(
        &mut self,
        content_type: ContentType,
        epoch: u16,
        save_fragment: bool,
        force_new_datagram: bool,
        f: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf),
    {
        let maybe_suite =
            if epoch >= 1 {
                Some(self.cipher_suite().ok_or_else(|| {
                    Error::UnexpectedMessage("No cipher suite selected".to_string())
                })?)
            } else {
                None
            };

        // Prepare the plaintext fragment
        let mut fragment = self.buffers_free.pop();

        // Let the caller fill the fragment (plaintext)
        f(&mut fragment);

        // Use this as a marker to know whether we are to record fragments for resends.
        if save_fragment {
            let mut clone = self.buffers_free.pop();
            clone.extend_from_slice(&fragment);
            self.flight_saved_records.push(Entry {
                content_type,
                epoch,
                fragment: clone,
            });
        }

        // Compute wire length of the record if serialized into a datagram
        // Record header (13) + handshake/change/app data bytes + AEAD overhead (if epoch >= 1)
        let overhead = if maybe_suite.is_some() {
            self.aead_overhead()
        } else {
            0
        };
        let record_wire_len = DTLSRecord::HEADER_LEN + fragment.len() + overhead;

        // Decide whether to append to the existing last datagram or create a new one
        let can_append = self
            .queue_tx
            .back()
            .map(|b| !force_new_datagram && b.len() + record_wire_len <= self.config.mtu())
            .unwrap_or(false);

        // If we cannot append, ensure we have space for a new datagram
        if !can_append && self.queue_tx.len() >= self.config.max_queue_tx() {
            warn!(
                "Transmit queue full (max {}): {:?}",
                self.config.max_queue_tx(),
                self.queue_tx
            );
            return Err(Error::TransmitQueueFull);
        }

        // Sequence number to use for this record
        let sequence = if epoch == 0 {
            self.sequence_epoch_0
        } else {
            self.sequence_epoch_n
        };
        let length = fragment.len() as u16;

        // Handle encryption for epochs >= 1
        if epoch >= 1 {
            let suite = maybe_suite.expect("cipher suite must be set for encrypted epochs");

            // Get the fixed part of the IV
            let iv = if self.is_client {
                self.crypto_context.get_client_write_iv()
            } else {
                self.crypto_context.get_server_write_iv()
            };

            let Some(iv) = iv else {
                return Err(Error::CryptoError(format!(
                    "{} write IV not available",
                    if self.is_client { "Client" } else { "Server" }
                )));
            };

            let explicit_nonce_len = self.explicit_nonce_len;
            let mut explicit_nonce = [0u8; DTLSRecord::EXPLICIT_NONCE_LEN];
            let seq64 = ((sequence.epoch as u64) << 48) | sequence.sequence_number;
            let nonce = match explicit_nonce_len {
                0 => Nonce::xor(iv.as_12_bytes(), seq64),
                DTLSRecord::EXPLICIT_NONCE_LEN => {
                    explicit_nonce = self.rng.random();
                    Nonce::new(iv, &explicit_nonce)
                }
                _ => {
                    return Err(Error::CryptoError(format!(
                        "Unsupported DTLS 1.2 record_iv_len={} for {:?}",
                        explicit_nonce_len, suite
                    )));
                }
            };

            // DTLS 1.2 AEAD: AAD uses the plaintext length (DTLSCompressed.length).
            let aad = Aad::new_dtls12(content_type, sequence, length);

            // Encrypt the fragment in-place
            self.encrypt_data(&mut fragment, aad, nonce)?;
            let ctext_len = fragment.len();

            // For suites with a per-record nonce (e.g. AES-GCM), prefix it on the wire.
            if explicit_nonce_len > 0 {
                fragment.resize(explicit_nonce_len + ctext_len, 0);
                fragment.copy_within(0..ctext_len, explicit_nonce_len);
                fragment[..explicit_nonce_len]
                    .copy_from_slice(&explicit_nonce[..explicit_nonce_len]);
            }
        }

        // Build the record structure referencing the (possibly encrypted) fragment
        let record = DTLSRecord {
            content_type,
            version: ProtocolVersion::DTLS1_2,
            sequence,
            length: fragment.len() as u16,
            fragment_range: 0..fragment.len(),
        };

        // Increment the sequence number for the next transmission
        if epoch == 0 {
            self.sequence_epoch_0.sequence_number += 1;
        } else {
            self.sequence_epoch_n.sequence_number += 1;
        }

        // Serialize the record into the chosen datagram buffer
        if can_append {
            let last = self.queue_tx.back_mut().unwrap();
            record.serialize(&fragment, last);
        } else {
            let mut buffer = self.buffers_free.pop();
            buffer.clear();
            record.serialize(&fragment, &mut buffer);
            self.queue_tx.push_back(buffer);
        }

        // Return the fragment buffer to the pool
        self.buffers_free.push(fragment);

        Ok(())
    }

    /// Create a handshake message and wrap it in a DTLS record
    pub fn create_handshake<F>(&mut self, msg_type: MessageType, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf, &mut Self) -> Result<(), Error>,
    {
        // Get a buffer for the handshake body
        let mut body_buffer = self.buffers_free.pop();

        // Let the callback fill the handshake body
        f(&mut body_buffer, self)?;

        // Create the handshake header with the next sequence number
        let handshake_header = Header {
            msg_type,
            length: body_buffer.len() as u32,
            message_seq: self.next_handshake_seq_no,
            fragment_offset: 0,
            fragment_length: body_buffer.len() as u32,
        };

        let mut buffer_full = self.buffers_free.pop();
        {
            let handshake = Handshake {
                header: handshake_header,
                body: Body::Fragment(0..body_buffer.len()),
                handled: AtomicBool::new(false),
            };
            // Serialize with body_buffer as source
            handshake.serialize(&body_buffer, &mut buffer_full);
        }
        self.transcript.extend_from_slice(&buffer_full);
        self.buffers_free.push(buffer_full);

        // Increment the sequence number for the next handshake message
        self.next_handshake_seq_no += 1;

        // We want to pack as much as possible into the outgoing datagram and
        // remain within the MTU. Fragment the handshake across records as needed.

        let epoch = msg_type.epoch();
        let total_len = body_buffer.len();
        let mut offset: usize = 0;

        // Handshake header is 12 bytes
        let handshake_header_len = 12usize;
        let aead_overhead = if epoch >= 1 {
            self.cipher_suite()
                .ok_or_else(|| Error::UnexpectedMessage("No cipher suite selected".to_string()))?;
            self.aead_overhead()
        } else {
            0
        };

        // At least one record must be created even if total_len == 0
        while offset < total_len || (total_len == 0 && offset == 0) {
            // How many bytes are already used in the current datagram (if any)?
            let already_used_in_current = self.queue_tx.back().map(|b| b.len()).unwrap_or(0);
            let available_in_current = self.config.mtu().saturating_sub(already_used_in_current);

            // Fixed overhead per handshake record on the wire:
            // DTLS record header + handshake header + AEAD overhead (if epoch >= 1)
            let fixed_overhead = DTLSRecord::HEADER_LEN + handshake_header_len + aead_overhead;

            // Prefer to pack into the current datagram. If the current one cannot fit even
            // the fixed overhead, we will start a fresh datagram and compute space again.
            let available_for_body = if available_in_current > fixed_overhead {
                // There is room for at least 1 byte of handshake body in the current datagram
                available_in_current - fixed_overhead
            } else {
                // Not enough space in the current datagram for any body bytes; start a fresh datagram
                self.config.mtu().saturating_sub(fixed_overhead)
            };

            // Remaining bytes from the handshake body we still need to send.
            let remaining_body_bytes = total_len.saturating_sub(offset);

            // For empty-body handshakes (e.g., ServerHelloDone), we still send a header-only record.
            let chunk_len = if total_len == 0 {
                0
            } else {
                remaining_body_bytes.min(available_for_body)
            };

            let frag_range = if chunk_len == 0 {
                0..0
            } else {
                offset..offset + chunk_len
            };

            let frag_handshake = Handshake {
                header: Header {
                    msg_type,
                    length: handshake_header.length,
                    message_seq: handshake_header.message_seq,
                    fragment_offset: offset as u32,
                    fragment_length: chunk_len as u32,
                },
                body: Body::Fragment(frag_range),
                handled: AtomicBool::new(false),
            };

            // Emit the record; packing into current datagram happens inside create_record
            self.create_record(ContentType::Handshake, epoch, true, |fragment| {
                // Serialize with body_buffer as source
                frag_handshake.serialize(&body_buffer, fragment);
            })?;

            if total_len == 0 {
                // Nothing more to send for empty-body handshake
                break;
            }

            offset += chunk_len;
        }

        // Return the buffer
        self.buffers_free.push(body_buffer);

        Ok(())
    }

    /// Release application data from the incoming queue
    pub fn release_application_data(&mut self) {
        self.release_app_data = true;
    }

    /// Whether a close_notify alert has been received from the peer.
    pub fn close_notify_received(&self) -> bool {
        self.close_notify_received
    }

    /// Discard all pending outgoing data.
    ///
    /// RFC 5246 §7.2.1: on receiving close_notify, discard any pending writes.
    pub fn discard_pending_writes(&mut self) {
        self.queue_tx.clear();
    }

    /// Abort the connection: flush all queued output, retransmission state, and
    /// disable timers so that no further packets are emitted.
    pub fn abort(&mut self) {
        self.queue_tx.clear();
        self.flight_saved_records.clear();
        self.flight_timeout = Timeout::Disabled;
        self.connect_timeout = Timeout::Disabled;
    }

    /// Pop a buffer from the buffer pool for temporary use
    pub(crate) fn pop_buffer(&mut self) -> Buf {
        self.buffers_free.pop()
    }

    /// Return a buffer to the buffer pool
    pub(crate) fn push_buffer(&mut self, buf: Buf) {
        self.buffers_free.push(buf);
    }

    /// Encrypt data appropriate for the role (client or server)
    fn encrypt_data(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), Error> {
        if self.is_client {
            self.crypto_context
                .encrypt_client_to_server(plaintext, aad, nonce)
                .map_err(|e| Error::CryptoError(format!("Client encryption failed: {}", e)))
        } else {
            self.crypto_context
                .encrypt_server_to_client(plaintext, aad, nonce)
                .map_err(|e| Error::CryptoError(format!("Server encryption failed: {}", e)))
        }
    }

    /// Decrypt data appropriate for the role (client or server)
    pub fn decrypt_data(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), Error> {
        if self.is_client {
            self.crypto_context
                .decrypt_server_to_client(ciphertext, aad, nonce)
                .map_err(|e| Error::CryptoError(format!("Client decryption failed: {}", e)))
        } else {
            self.crypto_context
                .decrypt_client_to_server(ciphertext, aad, nonce)
                .map_err(|e| Error::CryptoError(format!("Server decryption failed: {}", e)))
        }
    }

    /// Reset server handshake state after sending HelloVerifyRequest.
    ///
    /// Per RFC 6347 §4.2.2, the HelloVerifyRequest exchange is stateless. After sending
    /// HVR, the server expects a fresh ClientHello containing the cookie with message_seq=1.
    ///
    /// The message flow per RFC 6347 §4.2.2:
    ///   ClientHello (seq=0)  ------>
    ///                    <------  HelloVerifyRequest (seq=0)
    ///   ClientHello (seq=1)  ------>  (with cookie)
    ///                    <------  ServerHello (seq=1)
    pub fn reset_server_for_hello_verify_request(&mut self) {
        self.transcript.clear();
        // Per RFC 6347 §4.2.2, the next ClientHello (with cookie) has message_seq=1.
        // We keep peer_handshake_seq_no at 1 (already incremented after first ClientHello).
        // Clear queued incoming handshakes so the next ClientHello (with cookie)
        // isn't rejected as a duplicate of the first ClientHello (without cookie).
        self.queue_rx.clear();
        // Note: Don't clear flight_saved_records here - the HelloVerifyRequest should
        // still be resendable via timeout until we receive the valid ClientHello with cookie.
        // The flight_begin(4) call when processing the cookie-bearing ClientHello will
        // clear the old records.
    }

    /// Reset client handshake state after receiving HelloVerifyRequest.
    ///
    /// Per RFC 6347 §4.2.2, the client sends the next ClientHello (with cookie) using
    /// message_seq=1. The transcript is cleared because the initial ClientHello and
    /// HelloVerifyRequest are not part of the handshake transcript per RFC 6347 §4.2.1.
    ///
    /// Note: next_handshake_seq_no is already 1 after sending the first ClientHello,
    /// so we don't reset it - the next ClientHello will correctly have message_seq=1.
    pub fn reset_client_for_hello_verify_request(&mut self) {
        self.transcript.clear();
        // Note: next_handshake_seq_no stays at 1 - the next ClientHello (with cookie)
        // will have message_seq=1 per RFC 6347 §4.2.2.
        // Note: peer_handshake_seq_no stays at 1 - the next message from server
        // (ServerHello) will have message_seq=1 per RFC 6347 §4.2.2.
    }

    pub fn transcript_hash(&self, algorithm: HashAlgorithm, out: &mut Buf) {
        let mut hash = self.crypto_context.create_hash(algorithm);
        hash.update(&self.transcript);
        hash.clone_and_finalize(out);
    }

    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }

    pub fn set_cipher_suite(&mut self, cipher_suite: Dtls12CipherSuite) {
        // Look up AEAD record parameters from the provider (single source of truth)
        let provider_suite = self
            .crypto_context
            .provider()
            .cipher_suites
            .iter()
            .find(|cs| cs.suite() == cipher_suite)
            .expect("cipher suite must be in provider");
        self.explicit_nonce_len = provider_suite.explicit_nonce_len();
        self.tag_len = provider_suite.tag_len();
        self.cipher_suite = Some(cipher_suite);
    }

    pub fn enable_peer_encryption(&mut self) -> Result<(), Error> {
        debug!("Peer encryption enabled");
        self.peer_encryption_enabled = true;

        let maybe_index_epoch1 = self
            .queue_rx
            .iter()
            .position(|i| i.records().iter().any(|r| r.record().sequence.epoch == 1));

        let Some(index_epoch1) = maybe_index_epoch1 else {
            return Ok(());
        };

        // Now decrypt all entries remaining.
        let all = self.queue_rx.split_off(index_epoch1);
        let mut records = Vec::new();

        for incoming in all {
            for record in incoming.into_records() {
                if record.is_handled() {
                    self.buffers_free.push(record.into_buffer());
                    continue;
                }

                if record.record().sequence.epoch == 1 {
                    records.push((record.record().sequence, record.into_buffer()));
                } else {
                    self.buffers_free.push(record.into_buffer());
                }
            }
        }
        records.sort_by(|(left, _), (right, _)| {
            (left.epoch, left.sequence_number).cmp(&(right.epoch, right.sequence_number))
        });
        let mut records = VecDeque::from(records);

        while let Some((sequence, _)) = records.front() {
            let sequence = *sequence;
            let mut first_crypto_error = None;
            let mut sequence_succeeded = false;

            while records
                .front()
                .is_some_and(|(candidate_sequence, _)| *candidate_sequence == sequence)
            {
                let (_, buf) = records.pop_front().expect("front checked above");

                if sequence_succeeded {
                    self.buffers_free.push(buf);
                    continue;
                }

                let queue_len_before = self.queue_rx.len();
                let close_notify_before = self.close_notify_received;
                let replay_open_before = self.replay.check(sequence.sequence_number);

                match self.parse_packet(&buf) {
                    Ok(()) => {
                        let replay_consumed =
                            replay_open_before && !self.replay.check(sequence.sequence_number);
                        sequence_succeeded = self.queue_rx.len() > queue_len_before
                            || self.close_notify_received != close_notify_before
                            || replay_consumed;
                    }
                    Err(e) => {
                        if matches!(&e, Error::CryptoError(_)) {
                            first_crypto_error.get_or_insert(e);
                        } else {
                            self.buffers_free.push(buf);
                            return Err(e);
                        }
                    }
                }

                self.buffers_free.push(buf);
            }

            if !sequence_succeeded {
                if let Some(error) = first_crypto_error {
                    return Err(error);
                }
            }
        }

        Ok(())
    }

    fn peer_iv(&self) -> Iv {
        if self.is_client {
            self.crypto_context
                .get_server_write_iv()
                .expect("Server write IV not available - keys not derived yet")
        } else {
            self.crypto_context
                .get_client_write_iv()
                .expect("Client write IV not available - keys not derived yet")
        }
    }

    pub fn decryption_aad_and_nonce(&self, dtls: &DTLSRecord, buf: &[u8]) -> (Aad, Nonce) {
        // DTLS 1.2 AEAD: AAD uses the plaintext length. Recover plaintext length
        // from the record header by subtracting this suite's wire overhead.
        let plaintext_len = dtls.length.saturating_sub(self.aead_overhead() as u16);
        let aad = Aad::new_dtls12(dtls.content_type, dtls.sequence, plaintext_len);
        let iv = self.peer_iv();
        let seq64 = ((dtls.sequence.epoch as u64) << 48) | dtls.sequence.sequence_number;
        let nonce = match self.explicit_nonce_len {
            0 => Nonce::xor(iv.as_12_bytes(), seq64),
            DTLSRecord::EXPLICIT_NONCE_LEN => Nonce::new(iv, dtls.nonce(buf)),
            len => Nonce::new(iv, dtls.nonce_with_len(buf, len)),
        };
        (aad, nonce)
    }

    pub fn generate_verify_data(&mut self, is_client: bool) -> Result<[u8; 12], Error> {
        let Some(suite) = self.cipher_suite() else {
            return Err(Error::UnexpectedMessage(
                "No cipher suite selected".to_string(),
            ));
        };
        let algorithm = suite.hash_algorithm();
        let mut handshake_hash = self.buffers_free.pop();
        self.transcript_hash(algorithm, &mut handshake_hash);

        let suite_hash = suite.hash_algorithm();
        let mut out = self.buffers_free.pop();
        let mut scratch = self.buffers_free.pop();
        let verify_data_vec = self
            .crypto_context()
            .generate_verify_data(
                &handshake_hash,
                is_client,
                suite_hash,
                &mut out,
                &mut scratch,
            )
            .map_err(|e| Error::CryptoError(format!("Failed to generate verify data: {}", e)))?;

        if verify_data_vec.len() != 12 {
            return Err(Error::CryptoError("Invalid verify data length".to_string()));
        }

        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&verify_data_vec);

        self.buffers_free.push(handshake_hash);
        self.buffers_free.push(out);
        self.buffers_free.push(scratch);

        Ok(verify_data)
    }
}

fn incoming_records_equal(left: &Incoming, right: &Incoming) -> bool {
    left.records().len() == right.records().len()
        && left
            .records()
            .iter()
            .zip(right.records().iter())
            .all(|(left, right)| left.buffer() == right.buffer())
}

fn incoming_has_non_handshake_sequence(incoming: &Incoming, sequence: Sequence) -> bool {
    incoming
        .records()
        .iter()
        .any(|record| non_handshake_sequence_matches(record, sequence))
}

fn non_handshake_sequence_matches(record: &Record, sequence: Sequence) -> bool {
    record.first_handshake().is_none() && record.record().sequence == sequence
}

impl RecordHandler for Engine {
    fn classify_record(&mut self, record: Record) -> Result<Option<Record>, Error> {
        let epoch = record.record().sequence.epoch;

        if !self.peer_encryption_enabled && epoch > 0 && (epoch != 1 || self.cipher_suite.is_none())
        {
            self.push_buffer(record.into_buffer());
            return Ok(None);
        }

        if record.record().content_type == ContentType::ChangeCipherSpec
            && epoch == 0
            && self.peer_encryption_enabled
        {
            // DTLS 1.2 peers may retransmit their last handshake flight after
            // we have already enabled peer encryption. A late plaintext CCS is
            // no longer actionable; queuing it would leave an unhandled control
            // record in queue_rx and prevent handled app-data records behind it
            // from being purged.
            self.push_buffer(record.into_buffer());
            return Ok(None);
        }

        if record.record().content_type == ContentType::Handshake
            && epoch == 0
            && self.peer_encryption_enabled
        {
            if let Some(dupe_seq) = record
                .first_handshake()
                .and_then(|handshake| handshake.dupe_triggers_resend())
            {
                if dupe_seq < self.peer_handshake_seq_no {
                    self.flight_resend("dupe triggers resend")?;
                }
            }

            // Post-encryption epoch-0 handshakes are unauthenticated and no
            // longer actionable after any duplicate-triggered resend above.
            // Dropping them here also prevents a stale plaintext prefix from
            // deciding how later encrypted records in the datagram are queued.
            self.push_buffer(record.into_buffer());
            return Ok(None);
        }

        if record.record().content_type == ContentType::Alert {
            if epoch == 0 {
                if self.peer_encryption_enabled {
                    // Post-handshake: epoch 0 alerts are unauthenticated, discard.
                    self.push_buffer(record.into_buffer());
                    return Ok(None);
                }

                let fatal_description = {
                    let fragment = record.record().fragment(record.buffer());
                    (fragment.len() >= 2 && fragment[0] == 2).then(|| fragment[1])
                };
                self.push_buffer(record.into_buffer());

                if let Some(description) = fatal_description {
                    return Err(Error::SecurityError(format!(
                        "Received fatal alert: level=2, description={}",
                        description
                    )));
                }

                return Ok(None);
            }

            if !self.peer_encryption_enabled {
                // Epoch 1 before peer encryption is enabled must stay queued
                // for re-parsing after enable_peer_encryption().
                return Ok(Some(record));
            }

            let alert = {
                let fragment = record.record().fragment(record.buffer());
                (fragment.len() >= 2).then(|| (fragment[0], fragment[1]))
            };
            self.push_buffer(record.into_buffer());

            if let Some((level, description)) = alert {
                if description == 0 {
                    self.close_notify_received = true;
                    return Ok(None);
                }

                if level == 2 {
                    return Err(Error::SecurityError(format!(
                        "Received fatal alert: level={}, description={}",
                        level, description
                    )));
                }
            }

            return Ok(None);
        }

        if self.close_notify_received
            && record.record().content_type == ContentType::ApplicationData
        {
            self.push_buffer(record.into_buffer());
            return Ok(None);
        }

        Ok(Some(record))
    }

    fn is_peer_encryption_enabled(&self) -> bool {
        self.peer_encryption_enabled
    }

    fn replay_check(&self, seq: Sequence) -> bool {
        // Only epoch 1 (encrypted) records reach here; epoch 0 records are
        // returned early by the DTLS 1.2 incoming parser.
        self.replay.check(seq.sequence_number)
    }

    fn replay_update(&mut self, seq: Sequence) {
        self.replay.update(seq.sequence_number);
    }

    fn decryption_aad_and_nonce(&self, dtls: &DTLSRecord, buf: &[u8]) -> (Aad, Nonce) {
        Engine::decryption_aad_and_nonce(self, dtls, buf)
    }

    fn explicit_nonce_len(&self) -> usize {
        self.explicit_nonce_len
    }

    fn aead_overhead(&self) -> usize {
        Engine::aead_overhead(self)
    }

    fn decrypt_data(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), Error> {
        Engine::decrypt_data(self, ciphertext, aad, nonce)
    }

    fn can_discard_bad_protected_record(&self) -> bool {
        self.release_app_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn future_epoch_app_data(seq: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(ContentType::ApplicationData.as_u8());
        out.extend_from_slice(&[0xfe, 0xfd]);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes()[2..]);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn pre_key_engine(max_queue_rx: usize) -> Engine {
        let config = Arc::new(
            Config::builder()
                .max_queue_rx(max_queue_rx)
                .build()
                .expect("build config"),
        );
        let mut engine = Engine::new(config, AuthMode::Psk);
        engine.set_cipher_suite(Dtls12CipherSuite::PSK_AES128_CCM_8);
        engine
    }

    #[test]
    fn full_receive_queue_merges_second_same_sequence_candidate_without_growing() {
        let mut engine = pre_key_engine(1);

        engine
            .parse_packet(&future_epoch_app_data(0, b"stale"))
            .expect("first future-epoch candidate should queue");
        assert_eq!(engine.queue_rx.len(), 1);

        engine
            .parse_packet(&future_epoch_app_data(0, b"latest"))
            .expect("same-sequence replacement should not exceed max_queue_rx");
        assert_eq!(engine.queue_rx.len(), 1);
        assert_eq!(engine.queue_rx[0].records().len(), 2);

        let records = engine.queue_rx[0].records();
        assert_eq!(records[0].record().sequence.sequence_number, 0);
        assert_eq!(records[0].record().fragment(records[0].buffer()), b"stale");
        assert_eq!(records[1].record().sequence.sequence_number, 0);
        assert_eq!(records[1].record().fragment(records[1].buffer()), b"latest");
    }

    #[test]
    fn full_receive_queue_merges_hidden_same_sequence_candidate() {
        let mut engine = pre_key_engine(1);

        let mut hidden_stale = future_epoch_app_data(1, b"filler");
        hidden_stale.extend_from_slice(&future_epoch_app_data(0, b"stale"));

        engine
            .parse_packet(&hidden_stale)
            .expect("multi-record future-epoch candidate should queue");
        assert_eq!(engine.queue_rx.len(), 1);

        engine
            .parse_packet(&future_epoch_app_data(0, b"latest"))
            .expect("same-sequence replacement should find non-first records");
        assert_eq!(engine.queue_rx.len(), 1);

        assert_eq!(engine.queue_rx[0].records().len(), 3);
        assert_eq!(
            engine.queue_rx[0].records()[0]
                .record()
                .sequence
                .sequence_number,
            1
        );
        assert_eq!(
            engine.queue_rx[0].records()[0]
                .record()
                .fragment(engine.queue_rx[0].records()[0].buffer()),
            b"filler"
        );
        assert_eq!(
            engine.queue_rx[0].records()[1]
                .record()
                .sequence
                .sequence_number,
            0
        );
        assert_eq!(
            engine.queue_rx[0].records()[1]
                .record()
                .fragment(engine.queue_rx[0].records()[1].buffer()),
            b"stale"
        );
        assert_eq!(
            engine.queue_rx[0].records()[2]
                .record()
                .sequence
                .sequence_number,
            0
        );
        assert_eq!(
            engine.queue_rx[0].records()[2]
                .record()
                .fragment(engine.queue_rx[0].records()[2].buffer()),
            b"latest"
        );
    }

    #[test]
    fn same_datagram_candidate_cap_is_enforced_per_record() {
        let mut engine = pre_key_engine(2);

        let mut packet = future_epoch_app_data(0, b"first");
        packet.extend_from_slice(&future_epoch_app_data(0, b"second"));
        packet.extend_from_slice(&future_epoch_app_data(0, b"third"));

        engine
            .parse_packet(&packet)
            .expect("same-sequence candidates should stay bounded per record");

        let candidates: Vec<_> = engine.queue_rx[0]
            .records()
            .iter()
            .filter(|record| record.record().sequence.sequence_number == 0)
            .map(|record| record.record().fragment(record.buffer()).to_vec())
            .collect();

        assert_eq!(candidates, vec![b"first".to_vec(), b"third".to_vec()]);
    }

    #[test]
    fn same_sequence_candidate_cap_preserves_hidden_oldest_candidate() {
        let mut engine = pre_key_engine(2);

        let mut hidden_oldest = future_epoch_app_data(1, b"filler");
        hidden_oldest.extend_from_slice(&future_epoch_app_data(0, b"oldest"));

        engine
            .parse_packet(&hidden_oldest)
            .expect("hidden oldest same-sequence candidate should queue");
        engine
            .parse_packet(&future_epoch_app_data(0, b"poison1"))
            .expect("first alternative should queue");
        engine
            .parse_packet(&future_epoch_app_data(0, b"poison2"))
            .expect("second alternative should replace the previous alternative");

        let candidates: Vec<_> = engine
            .queue_rx
            .iter()
            .flat_map(|incoming| incoming.records().iter())
            .filter(|record| record.record().sequence.sequence_number == 0)
            .map(|record| record.record().fragment(record.buffer()).to_vec())
            .collect();

        assert_eq!(candidates, vec![b"oldest".to_vec(), b"poison2".to_vec()]);
    }

    #[test]
    fn full_receive_queue_rejects_over_capacity_merge_without_mutating_queue() {
        let mut engine = pre_key_engine(1);

        let mut full_datagram = future_epoch_app_data(0, b"stale");
        for seq in 1..8 {
            full_datagram.extend_from_slice(&future_epoch_app_data(seq, b"filler"));
        }
        engine
            .parse_packet(&full_datagram)
            .expect("full multi-record future-epoch datagram should queue");

        let original_records: Vec<_> = engine.queue_rx[0]
            .records()
            .iter()
            .map(|record| {
                (
                    record.record().sequence.sequence_number,
                    record.record().fragment(record.buffer()).to_vec(),
                )
            })
            .collect();

        let mut oversized_replacement = future_epoch_app_data(0, b"latest");
        oversized_replacement.extend_from_slice(&future_epoch_app_data(8, b"extra"));
        let result = engine.parse_packet(&oversized_replacement);

        assert!(matches!(result, Err(Error::ReceiveQueueFull)));
        assert_eq!(engine.queue_rx.len(), 1);
        let current_records: Vec<_> = engine.queue_rx[0]
            .records()
            .iter()
            .map(|record| {
                (
                    record.record().sequence.sequence_number,
                    record.record().fragment(record.buffer()).to_vec(),
                )
            })
            .collect();
        assert_eq!(current_records, original_records);
    }

    #[test]
    fn full_receive_queue_accepts_duplicate_record_at_record_capacity() {
        let mut engine = pre_key_engine(1);

        let mut full_datagram = future_epoch_app_data(0, b"stale");
        for seq in 1..8 {
            full_datagram.extend_from_slice(&future_epoch_app_data(seq, b"filler"));
        }
        engine
            .parse_packet(&full_datagram)
            .expect("full multi-record future-epoch datagram should queue");

        let original_records: Vec<_> = engine.queue_rx[0]
            .records()
            .iter()
            .map(|record| {
                (
                    record.record().sequence.sequence_number,
                    record.record().fragment(record.buffer()).to_vec(),
                )
            })
            .collect();

        engine
            .parse_packet(&future_epoch_app_data(0, b"stale"))
            .expect("duplicate record should be accepted as a no-op even when full");

        assert_eq!(engine.queue_rx.len(), 1);
        let current_records: Vec<_> = engine.queue_rx[0]
            .records()
            .iter()
            .map(|record| {
                (
                    record.record().sequence.sequence_number,
                    record.record().fragment(record.buffer()).to_vec(),
                )
            })
            .collect();
        assert_eq!(current_records, original_records);
    }
}
