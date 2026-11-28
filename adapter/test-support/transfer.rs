use zmux::Session;

/// Sends `n` streams of `len` bytes each from `from` to `to` at once and
/// checks every byte.
pub(crate) async fn transfer(from: &Session, to: &Session, n: usize, len: usize) {
    let transfer = async {
        let receiver = {
            let to = to.clone();
            tokio::spawn(async move {
                let mut readers = Vec::new();
                for _ in 0..n {
                    let mut recv = to.accept_uni().await.unwrap();
                    readers.push(tokio::spawn(async move {
                        recv.read_to_end(len + 1).await.unwrap()
                    }));
                }
                for r in readers {
                    let data = r.await.unwrap();
                    assert_eq!(data.len(), len);
                    assert!(
                        data.iter()
                            .enumerate()
                            .all(|(i, &b)| b == u8::try_from(i % 251).unwrap())
                    );
                }
            })
        };
        let data = zmux::Chunk::from(
            (0..len)
                .map(|i| u8::try_from(i % 251).unwrap())
                .collect::<Vec<_>>(),
        );
        let mut writers = Vec::new();
        for _ in 0..n {
            let mut send = from.open_uni().await.unwrap();
            let data = data.clone();
            writers.push(tokio::spawn(async move {
                send.write_chunk(data).await.unwrap();
                send.finish().unwrap();
                send
            }));
        }
        for w in writers {
            drop(w.await.unwrap());
        }
        receiver.await.unwrap();
    };
    if tokio::time::timeout(std::time::Duration::from_secs(60), transfer)
        .await
        .is_err()
    {
        for (side, session) in [("sender", from), ("receiver", to)] {
            eprintln!(
                "{side}: {:?}, pipes {:?}",
                session.stats(),
                session.pipe_stats()
            );
        }
        panic!("transfer of {n} x {len} bytes did not finish");
    }
}
