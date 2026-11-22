//! A carrier reader with a temporary pre-handoff cancellation observer.
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::task::{Context, Poll, Wake, Waker};

#[derive(Default)]
struct ReadWakes(Mutex<[Option<Waker>; 2]>);

impl Wake for ReadWakes {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let waiters = std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner));
        for w in waiters.into_iter().flatten() {
            w.wake();
        }
    }
}

struct Shared<R> {
    reader: Mutex<Option<R>>,
    wakes: Arc<ReadWakes>,
}

impl<R> Shared<R> {
    fn with_reader<T>(&self, f: impl FnOnce(&mut R) -> T) -> T {
        let mut reader = self.reader.lock().unwrap_or_else(PoisonError::into_inner);
        // Only the unique owner can move the reader out, after all observers exit.
        f(reader.as_mut().expect("watched reader"))
    }

    fn poll<T>(
        &self,
        cx: &Context<'_>,
        i: usize,
        f: impl FnOnce(&mut R, &mut Context<'_>) -> Poll<T>,
    ) -> Poll<T> {
        self.wakes.0.lock().unwrap_or_else(PoisonError::into_inner)[i] = Some(cx.waker().clone());
        let waker = Waker::from(self.wakes.clone());
        let result = self.with_reader(|reader| f(reader, &mut Context::from_waker(&waker)));
        if result.is_ready() {
            self.wakes.0.lock().unwrap_or_else(PoisonError::into_inner)[i] = None;
        }
        result
    }
}

enum State<R> {
    Watched(Arc<Shared<R>>),
    Owned(R),
}

/// The carrier owner. Once setup ends it reads the stream directly.
pub struct SetupRead<R>(State<R>);
/// Observes an error independently while setup is pending. Never owns the reader.
pub struct ReadProbe<R>(Weak<Shared<R>>);

impl<R> std::fmt::Debug for SetupRead<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupRead").finish_non_exhaustive()
    }
}

impl<R> SetupRead<R> {
    /// A new reader and its single setup observer.
    pub fn new(reader: R) -> (Self, ReadProbe<R>) {
        let shared = Arc::new(Shared {
            reader: Mutex::new(Some(reader)),
            wakes: Arc::default(),
        });
        let probe = ReadProbe(Arc::downgrade(&shared));
        (Self(State::Watched(shared)), probe)
    }

    fn state(&mut self) -> &mut State<R> {
        if let State::Watched(shared) = &mut self.0
            && let Some(only) = Arc::get_mut(shared)
        {
            self.0 = State::Owned(
                only.reader
                    .get_mut()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take()
                    .expect("watched reader"),
            );
        }
        &mut self.0
    }

    /// Poll the reader from the carrier.
    pub fn poll<T>(
        &mut self,
        cx: &mut Context<'_>,
        f: impl FnOnce(&mut R, &mut Context<'_>) -> Poll<T>,
    ) -> Poll<T> {
        match self.state() {
            State::Owned(reader) => f(reader, cx),
            State::Watched(shared) => shared.poll(cx, 0, f),
        }
    }

    /// Perform a synchronous operation such as stopping the read direction.
    pub fn with<T>(&mut self, f: impl FnOnce(&mut R) -> T) -> T {
        match self.state() {
            State::Owned(reader) => f(reader),
            State::Watched(shared) => shared.with_reader(f),
        }
    }

    /// Whether subsequent reads require a setup observer.
    pub fn observing(&mut self) -> bool {
        matches!(self.state(), State::Watched(_))
    }
}

impl<R> std::fmt::Debug for ReadProbe<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadProbe").finish_non_exhaustive()
    }
}

impl<R> ReadProbe<R> {
    /// Poll the setup observation. A carrier already released has no reader.
    pub fn poll<T>(
        &self,
        cx: &Context<'_>,
        f: impl FnOnce(&mut R, &mut Context<'_>) -> Poll<T>,
    ) -> Option<Poll<T>> {
        Some(self.0.upgrade()?.poll(cx, 1, f))
    }
}

impl<R> Drop for ReadProbe<R> {
    fn drop(&mut self) {
        if let Some(shared) = self.0.upgrade() {
            shared
                .wakes
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)[1] = None;
        }
    }
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for SetupRead<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll(cx, |reader, cx| {
            std::pin::Pin::new(reader).poll_read(cx, buf)
        })
    }
}
