use std::collections::VecDeque;
use std::io::IoSliceMut;

const SHRINK_MIN_RETAINED_BYTES: usize = 256 << 10;
const SHRINK_MAX_TAIL_BYTES: usize = 64 << 10;
const RELEASE_EMPTY_CHUNK_DEQUE_MIN_CAPACITY: usize = 1024;

#[derive(Debug, Default)]
pub(super) struct RecvBuffer {
    chunks: VecDeque<RecvChunk>,
    len: usize,
    retained_bytes: usize,
    removed_chunks_since_deque_reset: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct RecvBufferRead {
    pub(super) bytes: usize,
    pub(super) released_retained_bytes: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct RecvBufferClear {
    pub(super) bytes: usize,
    pub(super) released_retained_bytes: usize,
}

#[derive(Debug)]
struct RecvChunk {
    bytes: Vec<u8>,
    offset: usize,
}

impl RecvChunk {
    #[inline]
    fn remaining(&self) -> usize {
        debug_assert!(self.offset <= self.bytes.len());
        self.bytes.len() - self.offset
    }

    #[inline]
    fn is_consumed(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

impl RecvBuffer {
    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub(super) fn push_chunk_with_offset(&mut self, bytes: Vec<u8>, offset: usize) -> usize {
        if bytes.is_empty() {
            return 0;
        }
        let offset = offset.min(bytes.len());
        let len = bytes.len() - offset;
        if len == 0 {
            return 0;
        }
        let mut chunk = RecvChunk { bytes, offset };
        if offset != 0 {
            let _ = tighten_chunk_after_consume(&mut chunk);
        }
        let retained = chunk.bytes.capacity();
        self.len = self.len.saturating_add(len);
        self.retained_bytes = self.retained_bytes.saturating_add(retained);
        self.chunks.push_back(chunk);
        retained
    }

    #[cfg(test)]
    fn read(&mut self, dst: &mut [u8]) -> usize {
        self.read_detailed(dst).bytes
    }

    pub(super) fn read_detailed(&mut self, dst: &mut [u8]) -> RecvBufferRead {
        let mut copied = 0;
        let mut released_retained_bytes = 0usize;
        while copied < dst.len() {
            let mut released_front = None;
            {
                let Some(front) = self.chunks.front_mut() else {
                    break;
                };
                let n = (dst.len() - copied).min(front.remaining());
                dst[copied..copied + n]
                    .copy_from_slice(&front.bytes[front.offset..front.offset + n]);
                copied += n;
                self.len -= n;
                front.offset += n;

                if front.is_consumed() {
                    released_front = Some(front.bytes.capacity());
                } else if let Some((old_capacity, new_capacity)) =
                    tighten_chunk_after_consume(front)
                {
                    update_retained_capacity(&mut self.retained_bytes, old_capacity, new_capacity);
                    released_retained_bytes = released_retained_bytes
                        .saturating_add(old_capacity.saturating_sub(new_capacity));
                }
            }

            if let Some(released) = released_front {
                self.release_front_chunk(released, &mut released_retained_bytes);
            }
        }
        RecvBufferRead {
            bytes: copied,
            released_retained_bytes,
        }
    }

    pub(super) fn read_vectored_detailed(&mut self, dsts: &mut [IoSliceMut<'_>]) -> RecvBufferRead {
        if let Some(index) = single_non_empty_slice_index(dsts) {
            return self.read_detailed(&mut dsts[index]);
        }

        let mut copied = 0;
        let mut released_retained_bytes = 0usize;
        let mut dst_index = 0usize;
        let mut dst_offset = 0usize;

        loop {
            while dst_index < dsts.len() && dst_offset == dsts[dst_index].len() {
                dst_index += 1;
                dst_offset = 0;
            }
            if dst_index == dsts.len() {
                break;
            }

            let mut released_front = None;
            {
                let Some(front) = self.chunks.front_mut() else {
                    break;
                };
                let dst = &mut *dsts[dst_index];
                let room = dst.len() - dst_offset;
                let n = room.min(front.remaining());
                dst[dst_offset..dst_offset + n]
                    .copy_from_slice(&front.bytes[front.offset..front.offset + n]);
                copied += n;
                self.len -= n;
                front.offset += n;
                dst_offset += n;

                if front.is_consumed() {
                    released_front = Some(front.bytes.capacity());
                } else if let Some((old_capacity, new_capacity)) =
                    tighten_chunk_after_consume(front)
                {
                    update_retained_capacity(&mut self.retained_bytes, old_capacity, new_capacity);
                    released_retained_bytes = released_retained_bytes
                        .saturating_add(old_capacity.saturating_sub(new_capacity));
                }
            }

            if let Some(released) = released_front {
                self.release_front_chunk(released, &mut released_retained_bytes);
            }
        }

        RecvBufferRead {
            bytes: copied,
            released_retained_bytes,
        }
    }

    #[cfg(test)]
    fn clear(&mut self) -> usize {
        self.clear_detailed().bytes
    }

    pub(super) fn clear_detailed(&mut self) -> RecvBufferClear {
        let removed_chunks = self.chunks.len();
        let released = RecvBufferClear {
            bytes: self.len,
            released_retained_bytes: self.retained_bytes,
        };
        self.chunks.clear();
        self.len = 0;
        self.retained_bytes = 0;
        self.release_empty_chunk_deque_storage(removed_chunks);
        released
    }

    #[inline]
    fn release_front_chunk(&mut self, released: usize, released_retained_bytes: &mut usize) {
        self.retained_bytes = self.retained_bytes.saturating_sub(released);
        *released_retained_bytes = (*released_retained_bytes).saturating_add(released);
        let _ = self.chunks.pop_front();
        if self.chunks.is_empty() {
            self.len = 0;
            self.retained_bytes = 0;
        }
        self.release_empty_chunk_deque_storage(1);
    }

    #[inline]
    fn release_empty_chunk_deque_storage(&mut self, removed_chunks: usize) {
        self.removed_chunks_since_deque_reset = self
            .removed_chunks_since_deque_reset
            .saturating_add(removed_chunks);
        if self.chunks.is_empty()
            && self.chunks.capacity() >= RELEASE_EMPTY_CHUNK_DEQUE_MIN_CAPACITY
            && self.removed_chunks_since_deque_reset >= RELEASE_EMPTY_CHUNK_DEQUE_MIN_CAPACITY
        {
            self.chunks = VecDeque::new();
            self.removed_chunks_since_deque_reset = 0;
        }
    }
}

#[inline]
fn tighten_tail_len_after_consume(chunk: &RecvChunk) -> Option<usize> {
    let tail_len = chunk.remaining();
    if tail_len == 0
        || chunk.bytes.capacity() < SHRINK_MIN_RETAINED_BYTES
        || tail_len > SHRINK_MAX_TAIL_BYTES
    {
        None
    } else {
        Some(tail_len)
    }
}

#[inline]
fn tighten_chunk_after_consume(chunk: &mut RecvChunk) -> Option<(usize, usize)> {
    let tail_len = tighten_tail_len_after_consume(chunk)?;
    let mut tail = Vec::new();
    if tail.try_reserve_exact(tail_len).is_err() {
        return None;
    }
    tail.extend_from_slice(&chunk.bytes[chunk.offset..]);

    let old_capacity = chunk.bytes.capacity();
    chunk.bytes = tail;
    chunk.offset = 0;
    Some((old_capacity, chunk.bytes.capacity()))
}

#[inline]
fn update_retained_capacity(retained_bytes: &mut usize, old_capacity: usize, new_capacity: usize) {
    let diff = old_capacity.abs_diff(new_capacity);
    if old_capacity >= new_capacity {
        *retained_bytes = (*retained_bytes).saturating_sub(diff);
    } else {
        *retained_bytes = (*retained_bytes).saturating_add(diff);
    }
}

#[inline]
fn single_non_empty_slice_index(dsts: &[IoSliceMut<'_>]) -> Option<usize> {
    let mut found = None;
    for (index, dst) in dsts.iter().enumerate() {
        if dst.is_empty() {
            continue;
        }
        if found.replace(index).is_some() {
            return None;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::RecvBuffer;
    use std::collections::VecDeque;
    use std::io::IoSliceMut;

    #[test]
    fn partial_reads_advance_without_losing_chunk_tail() {
        let mut buffer = RecvBuffer::default();
        buffer.push_chunk_with_offset(b"abcdef".to_vec(), 0);

        let mut first = [0u8; 2];
        assert_eq!(buffer.read(&mut first), 2);
        assert_eq!(&first, b"ab");
        assert_eq!(buffer.len(), 4);

        let mut second = [0u8; 4];
        assert_eq!(buffer.read(&mut second), 4);
        assert_eq!(&second, b"cdef");
        assert!(buffer.is_empty());
    }

    #[test]
    fn reads_across_chunks() {
        let mut buffer = RecvBuffer::default();
        buffer.push_chunk_with_offset(b"ab".to_vec(), 0);
        buffer.push_chunk_with_offset(b"cd".to_vec(), 0);

        let mut out = [0u8; 3];
        assert_eq!(buffer.read(&mut out), 3);
        assert_eq!(&out, b"abc");
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn vectored_reads_across_chunks_and_empty_slices() {
        let mut first_backing = Vec::with_capacity(16);
        first_backing.extend_from_slice(b"abc");
        let mut second_backing = Vec::with_capacity(8);
        second_backing.extend_from_slice(b"def");

        let mut buffer = RecvBuffer::default();
        buffer.push_chunk_with_offset(first_backing, 0);
        buffer.push_chunk_with_offset(second_backing, 0);

        let mut empty = [0u8; 0];
        let mut first = [0u8; 2];
        let mut second = [0u8; 4];
        let read = buffer.read_vectored_detailed(&mut [
            IoSliceMut::new(&mut empty),
            IoSliceMut::new(&mut first),
            IoSliceMut::new(&mut second),
        ]);

        assert_eq!(read.bytes, 6);
        assert_eq!(read.released_retained_bytes, 24);
        assert_eq!(&first, b"ab");
        assert_eq!(&second, b"cdef");
        assert!(buffer.is_empty());
        assert_eq!(buffer.retained_bytes(), 0);
    }

    #[test]
    fn reads_across_queued_slices_without_repacking() {
        let source = b"0123456789";
        let mut buffer = RecvBuffer::default();
        buffer.push_chunk_with_offset(source[2..7].to_vec(), 0);
        buffer.push_chunk_with_offset(source[8..10].to_vec(), 0);

        let mut first = [0u8; 3];
        assert_eq!(buffer.read(&mut first), 3);
        assert_eq!(&first, b"234");

        let mut second = [0u8; 4];
        assert_eq!(buffer.read(&mut second), 4);
        assert_eq!(&second, b"5689");
        assert!(buffer.is_empty());
    }

    #[test]
    fn offset_chunk_skips_prefix_without_compacting() {
        let mut buffer = RecvBuffer::default();
        buffer.push_chunk_with_offset(b"metadata-app".to_vec(), 9);

        let mut out = [0u8; 3];
        assert_eq!(buffer.read(&mut out), 3);
        assert_eq!(&out, b"app");
        assert!(buffer.is_empty());
    }

    #[test]
    fn retained_bytes_track_backing_capacity_separately_from_readable_len() {
        let mut backing = Vec::with_capacity(32);
        backing.extend_from_slice(b"metadata-app");

        let mut buffer = RecvBuffer::default();
        buffer.push_chunk_with_offset(backing, 9);

        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.retained_bytes(), 32);

        let mut partial = [0u8; 2];
        assert_eq!(buffer.read(&mut partial), 2);
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.retained_bytes(), 32);

        let mut rest = [0u8; 1];
        assert_eq!(buffer.read(&mut rest), 1);
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.retained_bytes(), 0);
    }

    #[test]
    fn detailed_read_reports_released_backing_capacity() {
        let mut backing = Vec::with_capacity(32);
        backing.extend_from_slice(b"metadata-app");

        let mut buffer = RecvBuffer::default();
        buffer.push_chunk_with_offset(backing, 9);

        let mut partial = [0u8; 2];
        let first = buffer.read_detailed(&mut partial);
        assert_eq!(first.bytes, 2);
        assert_eq!(first.released_retained_bytes, 0);

        let mut rest = [0u8; 1];
        let second = buffer.read_detailed(&mut rest);
        assert_eq!(second.bytes, 1);
        assert_eq!(second.released_retained_bytes, 32);
        assert_eq!(buffer.retained_bytes(), 0);
    }

    #[test]
    fn clear_releases_readable_bytes_and_retained_capacity() {
        let mut backing = Vec::with_capacity(16);
        backing.extend_from_slice(b"abcdef");

        let mut buffer = RecvBuffer::default();
        buffer.push_chunk_with_offset(backing, 2);
        buffer.push_chunk_with_offset(b"xy".to_vec(), 0);

        assert_eq!(buffer.clear(), 6);
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.retained_bytes(), 0);
    }

    #[test]
    fn detailed_clear_reports_readable_and_backing_bytes() {
        let mut backing = Vec::with_capacity(16);
        backing.extend_from_slice(b"abcdef");

        let mut buffer = RecvBuffer::default();
        buffer.push_chunk_with_offset(backing, 2);
        buffer.push_chunk_with_offset(b"xy".to_vec(), 0);

        let released = buffer.clear_detailed();
        assert_eq!(released.bytes, 6);
        assert_eq!(released.released_retained_bytes, 18);
        assert!(buffer.is_empty());
        assert_eq!(buffer.retained_bytes(), 0);
    }

    #[test]
    fn fully_read_payload_chunks_do_not_leave_retained_storage() {
        let mut buffer = RecvBuffer::default();
        for len in [8, 7, 6] {
            let mut chunk = Vec::with_capacity(len);
            chunk.resize(len, b'x');
            buffer.push_chunk_with_offset(chunk, 0);
        }
        assert_eq!(buffer.retained_bytes(), 21);

        let mut out = [0u8; 21];
        assert_eq!(buffer.read(&mut out), out.len());

        assert!(buffer.is_empty());
        assert_eq!(buffer.retained_bytes(), 0);
    }

    #[test]
    fn clear_releases_same_length_payload_chunks_without_retained_pooling() {
        let mut buffer = RecvBuffer::default();
        for _ in 0..2 {
            let mut chunk = Vec::with_capacity(4);
            chunk.resize(4, b'x');
            buffer.push_chunk_with_offset(chunk, 0);
        }
        assert_eq!(buffer.retained_bytes(), 8);

        assert_eq!(buffer.clear(), 8);

        assert!(buffer.is_empty());
        assert_eq!(buffer.retained_bytes(), 0);
    }

    #[test]
    fn large_partially_consumed_chunk_tightens_small_tail_storage() {
        let mut backing = Vec::with_capacity(512 << 10);
        backing.resize((512 << 10) - 1, b'a');
        backing.push(b'z');

        let mut buffer = RecvBuffer::default();
        buffer.push_chunk_with_offset(backing, 0);
        assert!(buffer.retained_bytes() >= 512 << 10);

        let mut consumed = vec![0u8; (512 << 10) - 1];
        assert_eq!(buffer.read(&mut consumed), consumed.len());

        assert_eq!(buffer.len(), 1);
        assert!(buffer.retained_bytes() <= 64 << 10);

        let mut rest = [0u8; 1];
        assert_eq!(buffer.read(&mut rest), 1);
        assert_eq!(rest[0], b'z');
        assert_eq!(buffer.retained_bytes(), 0);
    }

    #[test]
    fn offset_push_tightens_large_metadata_prefix_for_small_app_tail() {
        let mut backing = Vec::with_capacity(512 << 10);
        backing.resize((512 << 10) - 3, b'm');
        backing.extend_from_slice(b"app");

        let mut buffer = RecvBuffer::default();
        let retained = buffer.push_chunk_with_offset(backing, (512 << 10) - 3);

        assert_eq!(buffer.len(), 3);
        assert!(retained <= 64 << 10);
        assert_eq!(buffer.retained_bytes(), retained);

        let mut out = [0u8; 3];
        assert_eq!(buffer.read(&mut out), 3);
        assert_eq!(&out, b"app");
        assert!(buffer.is_empty());
    }

    #[test]
    fn empty_buffer_releases_large_chunk_deque_storage() {
        let mut buffer = RecvBuffer::default();
        for _ in 0..2048 {
            buffer.push_chunk_with_offset(vec![1], 0);
        }
        assert!(buffer.chunks.capacity() >= 1024);

        let mut out = vec![0u8; 2048];
        assert_eq!(buffer.read(&mut out), 2048);

        assert!(buffer.is_empty());
        assert_eq!(buffer.retained_bytes(), 0);
        assert!(buffer.chunks.capacity() < 1024);
    }

    #[test]
    fn small_drain_after_large_burst_retains_chunk_deque_storage() {
        let mut buffer = RecvBuffer {
            chunks: VecDeque::with_capacity(2048),
            len: 0,
            retained_bytes: 0,
            removed_chunks_since_deque_reset: 0,
        };
        buffer.push_chunk_with_offset(vec![1], 0);
        assert!(buffer.chunks.capacity() >= 1024);

        let mut out = [0u8; 1];
        assert_eq!(buffer.read(&mut out), 1);

        assert!(buffer.is_empty());
        assert_eq!(buffer.retained_bytes(), 0);
        assert!(buffer.chunks.capacity() >= 1024);
    }

    #[test]
    fn gradual_drain_releases_large_chunk_deque_storage() {
        let mut buffer = RecvBuffer::default();
        for _ in 0..2048 {
            buffer.push_chunk_with_offset(vec![1], 0);
        }
        assert!(buffer.chunks.capacity() >= 1024);

        let mut out = [0u8; 1];
        for _ in 0..2048 {
            assert_eq!(buffer.read(&mut out), 1);
        }

        assert!(buffer.is_empty());
        assert_eq!(buffer.retained_bytes(), 0);
        assert!(buffer.chunks.capacity() < 1024);
    }

    #[test]
    fn clear_releases_large_chunk_deque_storage() {
        let mut buffer = RecvBuffer::default();
        for _ in 0..2048 {
            buffer.push_chunk_with_offset(vec![1], 0);
        }
        assert!(buffer.chunks.capacity() >= 1024);

        assert_eq!(buffer.clear(), 2048);

        assert!(buffer.is_empty());
        assert_eq!(buffer.retained_bytes(), 0);
        assert!(buffer.chunks.capacity() < 1024);
    }

    #[test]
    fn accounting_uses_saturation_instead_of_wrapping() {
        let mut buffer = RecvBuffer {
            chunks: VecDeque::new(),
            len: usize::MAX - 1,
            retained_bytes: usize::MAX - 1,
            removed_chunks_since_deque_reset: 0,
        };

        buffer.push_chunk_with_offset(vec![1, 2, 3, 4], 0);

        assert_eq!(buffer.len(), usize::MAX);
        assert_eq!(buffer.retained_bytes(), usize::MAX);
    }

    #[test]
    fn saturated_accounting_resets_after_last_chunk_is_released() {
        let mut buffer = RecvBuffer {
            chunks: VecDeque::new(),
            len: usize::MAX - 1,
            retained_bytes: usize::MAX - 1,
            removed_chunks_since_deque_reset: 0,
        };
        buffer.push_chunk_with_offset(vec![1, 2, 3, 4], 0);

        let mut out = [0u8; 4];
        assert_eq!(buffer.read(&mut out), 4);

        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.retained_bytes(), 0);
    }
}
