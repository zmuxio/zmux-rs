//! Microbenchmarks of the wire layer: STREAM frames, small control frames,
//! record parsing and variable-length integers.

#![allow(missing_docs)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use zmux::proto::frame::{
    Frame, MaxStreamData, PipeAck, PipeAckEntry, Priority, PriorityUpdate, Stream, StreamHeader,
};
use zmux::proto::record::{Event, RecordBuilder, RecordReader};
use zmux::proto::{Gates, varint};

fn stream_frames(c: &mut Criterion) {
    let mut g = c.benchmark_group("stream");
    for size in [1024usize, 16 * 1024] {
        let payload = vec![0x42u8; size];
        let frame = Frame::Stream(Stream::new(4, 1 << 20, &payload, false));
        let mut buf = vec![0u8; size + 64];
        let n = frame.encode(&mut buf).unwrap();
        let encoded = buf[..n].to_vec();
        let mut dst = vec![0u8; size];
        g.throughput(Throughput::Bytes(size as u64));

        // Header and payload copied into the batch buffer.
        g.bench_with_input(BenchmarkId::new("encode", size), &size, |b, _| {
            b.iter(|| black_box(&frame).encode(black_box(&mut buf)).unwrap())
        });
        // Header only, as a gather write sends the payload by reference.
        let header = StreamHeader {
            stream_id: 4,
            offset: 1 << 20,
            len: size as u64,
            fin: false,
            explicit_offset: false,
            explicit_len: true,
        };
        g.bench_with_input(BenchmarkId::new("encode_header", size), &size, |b, _| {
            b.iter(|| black_box(&header).encode(black_box(&mut buf)).unwrap())
        });
        // Zero-copy decode: the payload is a slice of the input.
        g.bench_with_input(BenchmarkId::new("decode", size), &size, |b, _| {
            b.iter(|| Frame::decode(black_box(&encoded), &Gates::ALL).unwrap())
        });
        // Decode and copy the payload out, as a receive buffer does.
        g.bench_with_input(BenchmarkId::new("decode_copy", size), &size, |b, _| {
            b.iter(|| {
                if let (Frame::Stream(s), _) =
                    Frame::decode(black_box(&encoded), &Gates::ALL).unwrap()
                {
                    dst[..s.data.len()].copy_from_slice(s.data);
                }
                black_box(&dst);
            })
        });
    }
    g.finish();
}

const ACK_ENTRIES: [PipeAckEntry; 3] = [
    PipeAckEntry {
        pipe_id: 0,
        lane: 0,
        position: 1_048_576,
        ack_delay: 1500,
    },
    PipeAckEntry {
        pipe_id: 2,
        lane: 0,
        position: 65_600,
        ack_delay: 250,
    },
    PipeAckEntry {
        pipe_id: 5,
        lane: 0,
        position: 7,
        ack_delay: 1,
    },
];

fn control_frames(c: &mut Criterion) {
    let mut g = c.benchmark_group("control");
    g.throughput(Throughput::Elements(1));
    let frames = [
        (
            "max_stream_data",
            Frame::MaxStreamData(MaxStreamData {
                stream_id: 1028,
                maximum: 5 << 20,
            }),
        ),
        ("pipe_ack", Frame::PipeAck(PipeAck::new(&ACK_ENTRIES))),
        (
            "priority_update",
            Frame::PriorityUpdate(PriorityUpdate {
                stream_id: 1028,
                sequence: 7,
                priority: Priority::new(2, true).unwrap(),
            }),
        ),
    ];
    let mut buf = [0u8; 64];
    for (name, frame) in &frames {
        let n = frame.encode(&mut buf).unwrap();
        let encoded = buf[..n].to_vec();
        g.bench_function(BenchmarkId::new("encode", name), |b| {
            b.iter(|| black_box(frame).encode(black_box(&mut buf)).unwrap())
        });
        g.bench_function(BenchmarkId::new("decode", name), |b| {
            b.iter(|| {
                let (f, n) = Frame::decode(black_box(&encoded), &Gates::ALL).unwrap();
                if let Frame::PipeAck(ack) = f {
                    black_box(ack.entries().map(|e| e.position).sum::<u64>());
                }
                n
            })
        });
    }
    g.finish();
}

/// A batch of about 256 KiB of records, each with a MAX_STREAM_DATA and a
/// STREAM frame of `chunk` bytes.
fn batch(chunk: usize) -> Vec<u8> {
    let payload = vec![0x42u8; chunk];
    let mut out = vec![0u8; 300 * 1024];
    let (mut at, mut offset) = (0, 0u64);
    while at < 256 * 1024 {
        let mut record = RecordBuilder::new(&mut out[at..], 65_535).unwrap();
        record
            .push(&Frame::MaxStreamData(MaxStreamData {
                stream_id: 0,
                maximum: offset + (1 << 22),
            }))
            .unwrap();
        record
            .push(&Frame::Stream(Stream::new(0, offset, &payload, false)))
            .unwrap();
        at += record.finish().unwrap();
        offset += chunk as u64;
    }
    out.truncate(at);
    out
}

fn take(event: Event<'_>, dst: &mut Option<&mut [u8]>, data: &mut u64) {
    if let Event::Frame(Frame::Stream(s)) = event {
        if let Some(d) = dst.as_deref_mut() {
            let at = (s.offset as usize) % (d.len() - s.data.len());
            d[at..at + s.data.len()].copy_from_slice(s.data);
        }
        *data += s.data.len() as u64;
    }
}

/// `read`: records that span reads are copied into the reader's buffer.
fn parse(reader: &mut RecordReader, bytes: &[u8], read: usize, dst: Option<&mut [u8]>) -> u64 {
    let mut data = 0u64;
    let mut dst = dst;
    for chunk in bytes.chunks(read) {
        let mut input = chunk;
        while let Some(event) = reader.read(&mut input, &Gates::ALL).unwrap() {
            take(event, &mut dst, &mut data);
        }
    }
    data
}

/// `read_complete` over a 128 KiB driver buffer that keeps incomplete
/// records and moves them to the front before the next read.
fn parse_in_place(
    reader: &mut RecordReader,
    bytes: &[u8],
    read: usize,
    buf: &mut [u8],
    dst: Option<&mut [u8]>,
) -> u64 {
    let mut data = 0u64;
    let mut dst = dst;
    let (mut filled, mut src) = (0, bytes);
    loop {
        let n = read.min(src.len()).min(buf.len() - filled);
        buf[filled..filled + n].copy_from_slice(&src[..n]);
        src = &src[n..];
        filled += n;
        let mut input = &buf[..filled];
        while let Some(event) = reader.read_complete(&mut input, &Gates::ALL).unwrap() {
            take(event, &mut dst, &mut data);
        }
        let left = input.len();
        buf.copy_within(filled - left..filled, 0);
        filled = left;
        if n == 0 {
            return data;
        }
    }
}

fn records(c: &mut Criterion) {
    let mut g = c.benchmark_group("records");
    for chunk in [16 * 1024usize, 1024] {
        let bytes = batch(chunk);
        g.throughput(Throughput::Bytes(bytes.len() as u64));
        let mut reader = RecordReader::new(65_535);
        let mut dst = vec![0u8; 1 << 20];
        let mut buf = vec![0u8; 128 * 1024];
        let reads = [
            ("whole", bytes.len()),
            ("reads_64k", 64 * 1024),
            ("reads_1500", 1500),
        ];
        for (label, read) in reads {
            g.bench_function(
                BenchmarkId::new(format!("read_{chunk}B_frames"), label),
                |b| b.iter(|| parse(&mut reader, black_box(&bytes), read, None)),
            );
            g.bench_function(
                BenchmarkId::new(format!("in_place_{chunk}B_frames"), label),
                |b| b.iter(|| parse_in_place(&mut reader, black_box(&bytes), read, &mut buf, None)),
            );
        }
        g.bench_function(
            BenchmarkId::new(format!("read_copy_{chunk}B_frames"), "reads_64k"),
            |b| b.iter(|| parse(&mut reader, black_box(&bytes), 64 * 1024, Some(&mut dst))),
        );
        g.bench_function(
            BenchmarkId::new(format!("in_place_copy_{chunk}B_frames"), "reads_64k"),
            |b| {
                b.iter(|| {
                    parse_in_place(
                        &mut reader,
                        black_box(&bytes),
                        64 * 1024,
                        &mut buf,
                        Some(&mut dst),
                    )
                })
            },
        );
    }
    g.finish();
}

fn varints(c: &mut Criterion) {
    let mut g = c.benchmark_group("varint");
    let values: Vec<u64> = (0..1024u64)
        .map(|i| match i % 4 {
            0 => i % 64,
            1 => 64 + i * 7,
            2 => 16_384 + i * 1_000,
            _ => (1 << 30) + i * 1_000_003,
        })
        .collect();
    let mut buf = vec![0u8; values.len() * 8];
    let mut at = 0;
    for &v in &values {
        at += varint::encode(v, &mut buf[at..]).unwrap();
    }
    let encoded = buf[..at].to_vec();
    g.throughput(Throughput::Elements(values.len() as u64));
    g.bench_function("encode_1024_mixed", |b| {
        b.iter(|| {
            let mut at = 0;
            for &v in black_box(&values) {
                at += varint::encode(v, &mut buf[at..]).unwrap();
            }
            at
        })
    });
    g.bench_function("decode_1024_mixed", |b| {
        b.iter(|| {
            let mut rest = black_box(&encoded[..]);
            let mut sum = 0u64;
            while let Some((v, n)) = varint::decode(rest) {
                sum = sum.wrapping_add(v);
                rest = &rest[n..];
            }
            sum
        })
    });
    g.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    targets = stream_frames, control_frames, records, varints
}
criterion_main!(benches);
