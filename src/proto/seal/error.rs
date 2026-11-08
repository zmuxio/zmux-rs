use std::fmt;

/// Why a step failed. Everything except [`Error::Incomplete`] and a refused
/// oversized plaintext is permanent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// More stream bytes are needed.
    Incomplete {
        /// The smallest total length that can make progress.
        need: usize,
    },
    /// A message is shorter than its form, or an encoding is invalid.
    Malformed,
    /// Bytes follow a complete Hello.
    TrailingBytes,
    /// The Profile is not supported or reserved.
    UnknownProfile,
    /// The Join Suite is not available.
    UnknownSuite,
    /// A reserved Mode or reserved Flags bit is set.
    BadFlags,
    /// A Handle or Locator length is out of range.
    BadHandle,
    /// AEAD or Confirm failure.
    Auth,
    /// An invalid key exchange input: a DH public key with an all-zero output,
    /// or a KEM encapsulation key that fails its check.
    Kex,
    /// The peer's static key equals this end's.
    PeerIsSelf,
    /// A message or plaintext is over its limit.
    TooLarge,
    /// The nonce space is used up.
    Exhausted,
    /// An item or entry runs past the end, or bytes trail it.
    TlvTruncated,
    /// A varint in a payload is not shortest.
    TlvNonMinimal,
    /// Payload types are not strictly increasing.
    TlvOrder,
    /// An unknown payload type with low bit 1.
    TlvUnknownCritical,
    /// An empty credential value, or CredType 0.
    TlvCredentials,
    /// A required Join item is absent.
    MissingField,
    /// A Join item value is out of range.
    BadField,
    /// A Sealed confirmation record is not empty.
    BadConfirm,
    /// The verifier failed the peer, a proof the verdict requires failed, or PQ
    /// authentication is required and does not hold.
    CredentialsFailed,
    /// Local parameters are invalid; nothing was sent.
    InvalidConfig,
    /// The random source failed; a Join does not fall back.
    RandomFailed,
}

impl Error {
    /// The class name of the error.
    pub fn class(self) -> &'static str {
        match self {
            Error::Incomplete { .. } => "incomplete",
            Error::Malformed => "malformed",
            Error::TrailingBytes => "trailing_bytes",
            Error::UnknownProfile => "unknown_profile",
            Error::UnknownSuite => "unknown_suite",
            Error::BadFlags => "bad_flags",
            Error::BadHandle => "bad_handle",
            Error::Auth => "auth",
            Error::Kex => "kex",
            Error::PeerIsSelf => "peer_is_self",
            Error::TooLarge => "too_large",
            Error::Exhausted => "exhausted",
            Error::TlvTruncated => "tlv_truncated",
            Error::TlvNonMinimal => "tlv_non_minimal",
            Error::TlvOrder => "tlv_order",
            Error::TlvUnknownCritical => "tlv_unknown_critical",
            Error::TlvCredentials => "tlv_credentials",
            Error::MissingField => "missing_field",
            Error::BadField => "bad_field",
            Error::BadConfirm => "bad_confirm",
            Error::CredentialsFailed => "credentials_failed",
            Error::InvalidConfig => "invalid_config",
            Error::RandomFailed => "random_failed",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class())
    }
}

impl std::error::Error for Error {}
