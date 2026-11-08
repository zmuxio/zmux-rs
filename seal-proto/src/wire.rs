//! The Establish Hello.

use zmux::proto::seal::{Error, Framing, Mode, cut_frame, frame, put_varint, read_shortest};

use crate::Profile;

const ESCAPE: u8 = 8;
/// The length of a Handle.
pub const HANDLE_LEN: usize = 16;
const MAX_UNIT: usize = u16::MAX as usize;

/// A parsed Hello: Noise message 1 has not been read yet.
#[derive(Clone, Copy, Debug)]
pub struct Hello<'a> {
    pub(crate) profile: Profile,
    pub(crate) mode: Mode,
    pub(crate) handle: &'a [u8],
    pub(crate) noise: &'a [u8],
    pub(crate) framing: Framing,
    consumed: usize,
}

impl<'a> Hello<'a> {
    /// Parses a Hello in wire order; the first failure is the result. A byte
    /// past it is `trailing_bytes`.
    pub fn parse(framing: Framing, input: &'a [u8]) -> Result<Hello<'a>, Error> {
        let stream = framing == Framing::ByteStream;
        let cut = |need| {
            if stream {
                Error::Incomplete { need }
            } else {
                Error::Malformed
            }
        };
        let first = *input.first().ok_or(cut(1))?;
        let mut at = 1;
        let value = match first {
            ESCAPE => {
                let rest = &input[1..];
                let Some((value, used, shortest)) = read_shortest(rest) else {
                    let width = rest.first().map_or(1, |b| 1usize << (b >> 6));
                    return Err(cut(1 + width));
                };
                if !shortest {
                    return Err(Error::Malformed);
                }
                if value <= u64::from(ESCAPE) {
                    return Err(Error::UnknownProfile);
                }
                at += used;
                value
            }
            direct => u64::from(direct),
        };
        if first > ESCAPE {
            return Err(Error::UnknownProfile);
        }
        let profile = Profile::from_value(value).ok_or(Error::UnknownProfile)?;
        let mode = Mode::from_byte(*input.get(at).ok_or(cut(at + 1))?)?;
        at += 1;
        let mut handle: &[u8] = &[];
        if profile.has_handle() {
            handle = input.get(at..at + HANDLE_LEN).ok_or(cut(at + HANDLE_LEN))?;
            at += HANDLE_LEN;
        }
        let (noise, consumed) = if stream {
            let (unit, total) = cut_frame(input, at)?;
            if total != input.len() {
                return Err(Error::TrailingBytes);
            }
            (unit, total)
        } else {
            if input.len() - at > MAX_UNIT {
                return Err(Error::TooLarge);
            }
            (&input[at..], input.len())
        };
        Ok(Hello {
            profile,
            mode,
            handle,
            noise,
            framing,
            consumed,
        })
    }

    /// The Profile the client chose.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// The record mode the client chose.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The Handle, empty for a Profile without one.
    pub fn handle(&self) -> &'a [u8] {
        self.handle
    }

    /// The bytes of the Hello.
    pub fn consumed(&self) -> usize {
        self.consumed
    }
}

pub(crate) fn handle_fits(profile: Profile, handle: &[u8]) -> bool {
    if profile.has_handle() {
        handle.len() == HANDLE_LEN
    } else {
        handle.is_empty()
    }
}

pub(crate) fn write_hello(
    framing: Framing,
    profile: Profile,
    mode: Mode,
    handle: &[u8],
    noise: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(noise.len() + handle.len() + 8);
    let value = profile.value();
    if value < u64::from(ESCAPE) {
        out.push(value as u8);
    } else {
        out.push(ESCAPE);
        put_varint(&mut out, value);
    }
    out.push(mode.byte());
    if profile.has_handle() {
        out.extend_from_slice(handle);
    }
    frame(framing, &mut out, noise)?;
    Ok(out)
}
