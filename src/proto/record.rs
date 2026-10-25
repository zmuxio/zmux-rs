//! The record layer (SPEC.md Section 3): size-prefixed records of frames on
//! byte-stream pipes, and one record per message on message-framed carriers
//! ("Records" framing, SPEC.md Section 3.4).
//!
//! [`RecordReader`] parses records incrementally from input split at any
//! byte boundary. A record's frames are released only once the whole record
//! has arrived: an incomplete record is never processed (SPEC.md Sections
//! 3.2 and 3.4), so a pipe that ends inside a record leaves nothing applied.
//! A record that is complete in the input is decoded in place, and its
//! payloads (STREAM and DATAGRAM data, reasons, parameter blocks) are slices
//! of the input. A record that spans reads is either copied into a reusable
//! buffer bounded by `max_record_size` ([`RecordReader::read`]) or left in
//! the caller's buffer until it is complete
//! ([`RecordReader::read_complete`]), which keeps every payload zero-copy.

use super::codec::Writer;
use super::error::{EncodeError, Error, TransportErrorCode};
use super::frame::{Frame, Gates};
use super::varint;

pub use super::params::{DEFAULT_MAX_RECORD_SIZE, ZMUX_MAX_RECORD_SIZE};

/// Length of the shortest Size field for a record of `body_len` bytes.
pub const fn size_len(body_len: u64) -> usize {
    varint::len(body_len)
}

/// The number of bytes a record with `body_len` bytes of frames counts for
/// in pipe positions, with the shortest Size encoding (SPEC.md Section 3.4).
pub const fn wire_len(body_len: u64) -> u64 {
    body_len + varint::len(body_len) as u64
}

/// Writes the shortest Size field for a record of `body_len` bytes.
pub fn encode_size(body_len: u64, buf: &mut [u8]) -> Result<usize, EncodeError> {
    varint::encode(body_len, buf)
}

/// How a pipe delimits records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Framing {
    /// Records are concatenated, each with its Size field (SPEC.md Section
    /// 3.1).
    ByteStream,
    /// Each carrier message is one record's Frames field and the message
    /// length is the Size (SPEC.md Section 3.4).
    Records,
}

/// An item produced by [`RecordReader::read`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// A frame of a complete record, in record order.
    Frame(Frame<'a>),
    /// The last frame of a record has been yielded. `len` is the number of
    /// bytes the record occupied on the pipe; positions advance by it once
    /// the record's frames are applied (MULTIPATH.md Section 6.1).
    RecordEnd {
        /// Bytes of the record, Size field included (with the shortest Size
        /// encoding on message-framed pipes).
        len: u64,
    },
}

#[derive(Debug, Clone, Copy)]
enum State {
    /// Reading a Size field; `have` bytes of it are in `buf`.
    Size { buf: [u8; 8], have: u8 },
    /// Decoding a complete record from the input: the caller's input holds
    /// at least `rest` more bytes of it.
    Direct { rest: u64, wire_len: u64 },
    /// Copying an incomplete record into the scratch buffer until it holds
    /// `need` bytes.
    Buffer { need: u64, wire_len: u64 },
    /// Decoding a complete record from the scratch buffer.
    Scratch { pos: usize, wire_len: u64 },
    /// A previous error; the pipe is unusable.
    Failed(Error),
}

impl State {
    const SIZE: Self = Self::Size {
        buf: [0; 8],
        have: 0,
    };
}

/// Incremental record parser for one inbound pipe.
///
/// Feed the bytes read from the pipe to [`RecordReader::read`] until it
/// returns `Ok(None)`; input may be split anywhere. Frames are decoded one
/// at a time with the gates passed to each call, so a caller can apply
/// transport parameters before the frames that follow them in the same
/// record are decoded. After an error the reader stays failed.
///
/// The reader does not apply the first-record check of SPEC.md Section 6.2;
/// see [`crate::proto::ident::Classifier`].
#[derive(Debug, Clone)]
pub struct RecordReader {
    max_record_size: u64,
    framing: Framing,
    state: State,
    scratch: Vec<u8>,
    position: u64,
}

impl RecordReader {
    /// A reader for byte-stream framing that accepts records of up to
    /// `max_record_size` bytes (the local endpoint's advertised limit).
    pub fn new(max_record_size: u64) -> Self {
        Self::with_framing(max_record_size, Framing::ByteStream)
    }

    /// A reader for the given framing.
    #[must_use]
    pub fn with_framing(max_record_size: u64, framing: Framing) -> Self {
        Self {
            max_record_size,
            framing,
            state: State::SIZE,
            scratch: Vec::new(),
            position: 0,
        }
    }

    /// The framing this reader parses.
    pub const fn framing(&self) -> Framing {
        self.framing
    }

    /// The pipe position: bytes of the records whose
    /// [`Event::RecordEnd`] has been yielded.
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Whether every record received so far has been yielded completely,
    /// [`Event::RecordEnd`] included. Check it after `read` returned
    /// `Ok(None)`. A pipe that ends while this is false ended inside a
    /// record: it has failed and the incomplete record is never processed
    /// (SPEC.md Section 3.2). That is a pipe failure, not a protocol error.
    pub const fn at_record_boundary(&self) -> bool {
        matches!(self.state, State::Size { have: 0, .. })
    }

    /// Frees the buffer used for records that span reads, if the reader
    /// is not using it. The buffer grows up to `max_record_size`.
    pub fn release_buffer(&mut self) {
        if !matches!(self.state, State::Buffer { .. } | State::Scratch { .. }) {
            self.scratch = Vec::new();
        }
    }

    /// Heap bytes held by the buffer for records that span reads.
    pub(crate) fn buffer_capacity(&self) -> usize {
        self.scratch.capacity()
    }

    /// Starts a record from a message of `len` bytes on a message-framed
    /// pipe. The message's bytes are then passed to
    /// [`RecordReader::read`]; the record ends with the message.
    pub fn begin_message(&mut self, len: usize) -> Result<(), Error> {
        if let State::Failed(e) = self.state {
            return Err(e);
        }
        if self.framing != Framing::Records || !self.at_record_boundary() {
            return Err(Error::new(
                TransportErrorCode::INTERNAL_ERROR,
                0,
                "message started inside a record",
            ));
        }
        let len = len as u64;
        // An empty message is a record without frames, a no-op (SPEC.md
        // Section 3.4); on a byte stream a Size of 0 stays an error.
        if len > 0
            && let Err(e) = self.check_size(len)
        {
            return Err(self.fail(e));
        }
        self.state = State::Direct {
            rest: len,
            wire_len: wire_len(len),
        };
        Ok(())
    }

    fn check_size(&self, size: u64) -> Result<(), Error> {
        if size == 0 {
            Err(Error::frame_encoding(0, "empty record"))
        } else if size > self.max_record_size {
            Err(Error::frame_encoding(
                0,
                "record larger than max_record_size",
            ))
        } else {
            Ok(())
        }
    }

    fn fail(&mut self, e: Error) -> Error {
        self.state = State::Failed(e);
        e
    }

    /// Decodes the next item from `input`, advancing it past the consumed
    /// bytes. Returns `Ok(None)` when `input` is exhausted and more bytes are
    /// needed. A record that is incomplete in `input` is copied into the
    /// reader's buffer and decoded once it is complete.
    pub fn read<'s, 'i: 's>(
        &'s mut self,
        input: &mut &'i [u8],
        gates: &Gates,
    ) -> Result<Option<Event<'s>>, Error> {
        self.read_inner(input, gates, false)
    }

    /// Like [`RecordReader::read`], but a record that is incomplete in
    /// `input` is left there, Size field included, and `Ok(None)` is
    /// returned: the caller keeps the remaining bytes and calls again with
    /// more appended. Nothing is copied, so every payload is a slice of the
    /// caller's buffer, which must be able to hold a whole record (the
    /// Size field plus `max_record_size`). A Size above the limit is still
    /// rejected as soon as it is complete.
    pub fn read_complete<'s, 'i: 's>(
        &'s mut self,
        input: &mut &'i [u8],
        gates: &Gates,
    ) -> Result<Option<Event<'s>>, Error> {
        self.read_inner(input, gates, true)
    }

    fn read_inner<'s, 'i: 's>(
        &'s mut self,
        input: &mut &'i [u8],
        gates: &Gates,
        retain: bool,
    ) -> Result<Option<Event<'s>>, Error> {
        loop {
            match self.state {
                State::Failed(e) => return Err(e),
                State::Size { mut buf, have } => {
                    let data: &'i [u8] = input;
                    if data.is_empty() {
                        return Ok(None);
                    }
                    if self.framing == Framing::Records {
                        return Err(Error::new(
                            TransportErrorCode::INTERNAL_ERROR,
                            0,
                            "input outside a message",
                        ));
                    }
                    let (size, width, body) = match (have, varint::decode(data)) {
                        (0, Some((size, width))) => {
                            if let Err(e) = self.check_size(size) {
                                return Err(self.fail(e));
                            }
                            let body = data.get(width..).unwrap_or_default();
                            if retain && (body.len() as u64) < size {
                                // Leave the incomplete record with the caller.
                                return Ok(None);
                            }
                            (size, width, body)
                        }
                        (0, None) if retain => return Ok(None),
                        _ => {
                            let have = usize::from(have);
                            let need = varint::width(if have == 0 { data[0] } else { buf[0] });
                            let take = (need - have).min(data.len());
                            buf[have..have + take].copy_from_slice(&data[..take]);
                            if have + take < need {
                                *input = &data[take..];
                                self.state = State::Size {
                                    buf,
                                    have: (have + take) as u8,
                                };
                                return Ok(None);
                            }
                            let Some((size, width)) = varint::decode(&buf[..need]) else {
                                return Err(self.fail(Error::frame_encoding(0, "bad Size")));
                            };
                            if let Err(e) = self.check_size(size) {
                                return Err(self.fail(e));
                            }
                            (size, width, &data[take..])
                        }
                    };
                    let wire_len = width as u64 + size;
                    if (body.len() as u64) >= size {
                        *input = body;
                        self.state = State::Direct {
                            rest: size,
                            wire_len,
                        };
                    } else {
                        self.scratch.clear();
                        self.scratch.extend_from_slice(body);
                        *input = &[];
                        self.state = State::Buffer {
                            need: size,
                            wire_len,
                        };
                    }
                }
                State::Direct { rest, wire_len } => {
                    if rest == 0 {
                        self.position = self.position.saturating_add(wire_len);
                        self.state = State::SIZE;
                        return Ok(Some(Event::RecordEnd { len: wire_len }));
                    }
                    let data: &'i [u8] = input;
                    let Some(record) = usize::try_from(rest).ok().and_then(|r| data.get(..r))
                    else {
                        // The rest of the record is not in this input (a
                        // message fed in pieces, or a caller that did not
                        // keep its input): finish it in the buffer.
                        self.scratch.clear();
                        self.scratch.extend_from_slice(data);
                        *input = &[];
                        self.state = State::Buffer {
                            need: rest,
                            wire_len,
                        };
                        continue;
                    };
                    return match Frame::decode(record, gates) {
                        Ok((frame, n)) => {
                            *input = &data[n..];
                            self.state = State::Direct {
                                rest: rest - n as u64,
                                wire_len,
                            };
                            Ok(Some(Event::Frame(frame)))
                        }
                        Err(e) => Err(self.fail(e)),
                    };
                }
                State::Buffer { need, wire_len } => {
                    let missing = usize::try_from(need)
                        .unwrap_or(usize::MAX)
                        .saturating_sub(self.scratch.len());
                    if missing == 0 {
                        self.state = State::Scratch { pos: 0, wire_len };
                        continue;
                    }
                    let data: &'i [u8] = input;
                    if data.is_empty() {
                        return Ok(None);
                    }
                    let take = missing.min(data.len());
                    self.scratch.extend_from_slice(&data[..take]);
                    *input = &data[take..];
                }
                State::Scratch { pos, wire_len } => {
                    if pos >= self.scratch.len() {
                        self.state = State::Direct { rest: 0, wire_len };
                        continue;
                    }
                    // Every path from this borrow returns, so it may live
                    // for 's while the state (a disjoint field) is updated.
                    let buf: &'s [u8] = self.scratch.get(pos..).unwrap_or_default();
                    return match Frame::decode(buf, gates) {
                        Ok((frame, n)) => {
                            self.state = State::Scratch {
                                pos: pos + n,
                                wire_len,
                            };
                            Ok(Some(Event::Frame(frame)))
                        }
                        Err(e) => {
                            self.state = State::Failed(e);
                            Err(e)
                        }
                    };
                }
            }
        }
    }
}

/// Builds one record in a caller-provided buffer: reserves room for the
/// Size field, appends frames, and writes the shortest Size on
/// [`RecordBuilder::finish`].
#[derive(Debug)]
pub struct RecordBuilder<'b> {
    buf: &'b mut [u8],
    reserved: usize,
    end: usize,
    limit: usize,
}

impl<'b> RecordBuilder<'b> {
    /// Starts a record whose Frames field will hold at most `max_body`
    /// bytes, for example the peer's `max_record_size`.
    pub fn new(buf: &'b mut [u8], max_body: usize) -> Result<Self, EncodeError> {
        let reserved = size_len(max_body as u64);
        if reserved > buf.len() {
            return Err(EncodeError::BufferTooShort);
        }
        let limit = buf.len().min(reserved.saturating_add(max_body));
        Ok(Self {
            buf,
            reserved,
            end: reserved,
            limit,
        })
    }

    /// Bytes of frames written so far.
    pub fn body_len(&self) -> usize {
        self.end - self.reserved
    }

    /// Room left for frames.
    pub fn remaining(&self) -> usize {
        self.limit - self.end
    }

    /// Appends a frame. A frame without a length field must be the last.
    pub fn push(&mut self, frame: &Frame<'_>) -> Result<(), EncodeError> {
        let len = frame.encoded_len();
        if len > self.remaining() {
            return Err(EncodeError::BufferTooShort);
        }
        let dst = &mut self.buf[self.end..self.limit];
        let mut w = Writer::new(dst);
        frame.write(&mut w)?;
        self.end += w.pos();
        Ok(())
    }

    /// Appends raw frame bytes, for example a STREAM header followed by
    /// its data.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let dst = self
            .buf
            .get_mut(self.end..self.limit)
            .and_then(|d| d.get_mut(..bytes.len()))
            .ok_or(EncodeError::BufferTooShort)?;
        dst.copy_from_slice(bytes);
        self.end += bytes.len();
        Ok(())
    }

    /// Writes the Size field and returns the record length. The record
    /// starts at the beginning of the buffer. An empty record is refused.
    pub fn finish(self) -> Result<usize, EncodeError> {
        let body = self.body_len();
        if body == 0 {
            return Err(EncodeError::ValueOutOfRange);
        }
        let size_len = size_len(body as u64);
        if size_len < self.reserved {
            self.buf.copy_within(self.reserved..self.end, size_len);
        }
        varint::encode(body as u64, self.buf)?;
        Ok(size_len + body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{MaxData, Padding, Stream};

    fn record(frames: &[Frame<'_>]) -> Vec<u8> {
        let mut buf = vec![0u8; 70_000];
        let mut b = RecordBuilder::new(&mut buf, 65_535).unwrap();
        for f in frames {
            b.push(f).unwrap();
        }
        let n = b.finish().unwrap();
        buf.truncate(n);
        buf
    }

    /// Collects events as text, feeding `bytes` in pieces of `chunk` bytes.
    fn collect(bytes: &[u8], chunk: usize) -> Vec<String> {
        let mut r = RecordReader::new(65_535);
        let mut out = Vec::new();
        for piece in bytes.chunks(chunk.max(1)) {
            let mut input = piece;
            while let Some(event) = r.read(&mut input, &Gates::ALL).unwrap() {
                out.push(format!("{event:?}"));
            }
        }
        assert!(r.at_record_boundary());
        out
    }

    #[test]
    fn any_split_gives_the_same_events() {
        let data: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let mut bytes = record(&[
            Frame::MaxData(MaxData { maximum: 1 << 20 }),
            Frame::Stream(Stream::new(4, 100, &data, true)),
        ]);
        bytes.extend(record(&[
            Frame::Padding(Padding { len: 3 }),
            Frame::Stream(Stream {
                explicit_len: false,
                ..Stream::new(0, 0, b"tail", false)
            }),
        ]));
        let reference = collect(&bytes, bytes.len());
        assert_eq!(reference.len(), 6);
        for chunk in [1, 2, 3, 7, 64, 1000] {
            assert_eq!(collect(&bytes, chunk), reference, "chunk {chunk}");
        }
    }

    #[test]
    fn incomplete_records_are_never_released() {
        // Size 10 with only 5 body bytes: nothing is yielded.
        let mut r = RecordReader::new(65_535);
        let mut input: &[u8] = &[0x0a, 0x1d, 0x00, 0x00, 0x10, 0x05];
        assert_eq!(r.read(&mut input, &Gates::ALL), Ok(None));
        assert!(!r.at_record_boundary());
        assert_eq!(r.position(), 0);
        // read_complete leaves the record with the caller.
        let mut r = RecordReader::new(65_535);
        let bytes = [0x06, 0x0f, 0x00, 0x03, 0x02, 0x63, 0x64];
        let mut input: &[u8] = &bytes[..6];
        assert_eq!(r.read_complete(&mut input, &Gates::ALL), Ok(None));
        assert_eq!(input.len(), 6);
        let mut input: &[u8] = &bytes;
        assert!(matches!(
            r.read_complete(&mut input, &Gates::ALL),
            Ok(Some(Event::Frame(Frame::Stream(_))))
        ));
        assert_eq!(
            r.read_complete(&mut input, &Gates::ALL),
            Ok(Some(Event::RecordEnd { len: 7 }))
        );
        assert!(r.at_record_boundary());
    }

    #[test]
    fn size_errors_are_immediate() {
        for retain in [false, true] {
            let mut r = RecordReader::new(65_535);
            let mut input: &[u8] = &[0x80, 0x01, 0x00, 0x00];
            let e = r.read_inner(&mut input, &Gates::ALL, retain).unwrap_err();
            assert_eq!(e.code(), TransportErrorCode::FRAME_ENCODING_ERROR);
            let mut r = RecordReader::new(65_535);
            let mut input: &[u8] = &[0x00];
            assert!(r.read_inner(&mut input, &Gates::ALL, retain).is_err());
        }
    }

    #[test]
    fn message_framing() {
        let body = [0x10, 0x44, 0x00];
        let mut r = RecordReader::with_framing(65_535, Framing::Records);
        r.begin_message(body.len()).unwrap();
        // A message fed in pieces is processed only once complete.
        let mut first: &[u8] = &body[..2];
        assert_eq!(r.read(&mut first, &Gates::ALL), Ok(None));
        let mut rest: &[u8] = &body[2..];
        assert!(matches!(
            r.read(&mut rest, &Gates::ALL),
            Ok(Some(Event::Frame(Frame::MaxData(_))))
        ));
        assert_eq!(
            r.read(&mut rest, &Gates::ALL),
            Ok(Some(Event::RecordEnd { len: 4 }))
        );
        assert_eq!(r.read(&mut rest, &Gates::ALL), Ok(None));
        assert_eq!(r.position(), 4);
        // An empty message is a record without frames (SPEC.md 3.4).
        r.begin_message(0).unwrap();
        let mut none: &[u8] = &[];
        assert_eq!(
            r.read(&mut none, &Gates::ALL),
            Ok(Some(Event::RecordEnd { len: 1 }))
        );
    }
}
