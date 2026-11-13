//! Sealed records: a record sealed and opened with the allocating AEAD
//! calls against the in-place ones the drivers use.

#![allow(missing_docs)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use zmux::proto::seal::{Opener, Sealer, aes_256_gcm, chacha20_poly1305};

fn records(c: &mut Criterion) {
    let mut g = c.benchmark_group("sealed_record");
    let key = vec![0x11; 32];
    for size in [1024usize, 16 * 1024, 65_519] {
        let plain = vec![0x42u8; size];
        g.throughput(Throughput::Bytes(size as u64));
        // A record as a Vec each way, as the drivers did before.
        g.bench_with_input(BenchmarkId::new("allocating", size), &size, |b, _| {
            let (mut s, mut o) = (
                Sealer::new(aes_256_gcm(), key.clone()),
                Opener::new(aes_256_gcm(), key.clone()),
            );
            b.iter(|| {
                let sealed = s.seal(black_box(&plain)).unwrap();
                black_box(o.open(&sealed).unwrap());
            });
        });
        // In the caller's buffers.
        g.bench_with_input(BenchmarkId::new("in_place", size), &size, |b, _| {
            let (mut s, mut o) = (
                Sealer::new(aes_256_gcm(), key.clone()),
                Opener::new(aes_256_gcm(), key.clone()),
            );
            let mut unit = Vec::with_capacity(size + 16);
            b.iter(|| {
                unit.clear();
                s.seal_into(black_box(&plain), &mut unit).unwrap();
                black_box(o.open_in_place(&mut unit).unwrap());
            });
        });
    }
    // ChaCha20-Poly1305 in place.
    for size in [1024usize, 16 * 1024] {
        let plain = vec![0x42u8; size];
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::new("chacha_in_place", size), &size, |b, _| {
            let (mut s, mut o) = (
                Sealer::new(chacha20_poly1305(), key.clone()),
                Opener::new(chacha20_poly1305(), key.clone()),
            );
            let mut unit = Vec::with_capacity(size + 16);
            b.iter(|| {
                unit.clear();
                s.seal_into(black_box(&plain), &mut unit).unwrap();
                black_box(o.open_in_place(&mut unit).unwrap());
            });
        });
    }
    g.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(2)).warm_up_time(Duration::from_millis(500));
    targets = records
}
criterion_main!(benches);
