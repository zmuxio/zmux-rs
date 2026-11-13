use super::{Error, Hash, SHA256};

const BOUND_LEN: usize = 32;

/// `Export(label, context, n)` from an exporter secret.
pub fn export(
    hash: &Hash,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Vec<u8>, Error> {
    let label_len = u8::try_from(label.len()).map_err(|_| Error::InvalidConfig)?;
    let context_len = u16::try_from(context.len()).map_err(|_| Error::InvalidConfig)?;
    // HKDF bounds `len` by 255 hash lengths, at most 16320 bytes, within a u16.
    let out_len = match u16::try_from(len) {
        Ok(n) if n != 0 && len <= 255 * hash.out_len() => n,
        _ => return Err(Error::InvalidConfig),
    };
    let mut info = Vec::with_capacity(5 + label.len() + context.len());
    info.push(label_len);
    info.extend_from_slice(label);
    info.extend_from_slice(&context_len.to_be_bytes());
    info.extend_from_slice(context);
    info.extend_from_slice(&out_len.to_be_bytes());
    hash.expand(secret, &info, len)
}

/// The Binding from the carrier exporters of the two halves, in role order.
/// Fails if either half has no exporter.
pub fn bound_exporter(up: Option<&[u8]>, down: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    let (Some(up), Some(down)) = (up, down) else {
        return Err(Error::InvalidConfig);
    };
    if up.len() != BOUND_LEN || down.len() != BOUND_LEN {
        return Err(Error::InvalidConfig);
    }
    if up == down {
        return Ok(up.to_vec());
    }
    let prk = SHA256.extract(b"", &[up, down].concat());
    SHA256.expand(&prk, b"zmux-seal bound", BOUND_LEN)
}
