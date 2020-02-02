//! Error type.

use std::fmt;
use std::io;

/// The various errors that can be returned during the decryption process.
#[derive(Debug)]
pub enum Error {
    /// Seeking was attempted on an ASCII-armored encrypted message, which is unsupported.
    ArmoredWhenSeeking,
    /// The message failed to decrypt.
    DecryptionFailed,
    /// The message used an excessive work factor for passphrase encryption.
    ExcessiveWork {
        /// The work factor required to decrypt.
        required: u8,
        /// The target work factor for this device (around 1 second of work).
        target: u8,
    },
    /// The MAC in the message header was invalid.
    InvalidMac,
    /// A recipient was invalid.
    InvalidRecipient,
    /// An I/O error occurred during decryption.
    Io(io::Error),
    /// Failed to decrypt an encrypted key.
    KeyDecryptionFailed,
    /// A YubiKey stub did not match the YubiKey. Either the stub is malformed, or the key
    /// in the slot has been altered.
    KeyMismatch,
    /// The provided message requires keys to decrypt.
    MessageRequiresKeys,
    /// The provided message requires a passphrase to decrypt.
    MessageRequiresPassphrase,
    /// None of the provided keys could be used to decrypt the message.
    NoMatchingKeys,
    /// An unknown age format, probably from a newer version.
    UnknownFormat,
    /// YubiKey error.
    #[cfg(feature = "yubikey")]
    YubiKey(yubikey_piv::error::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ArmoredWhenSeeking => write!(f, "Armored messages not supported for seeking"),
            Error::DecryptionFailed => write!(f, "Decryption failed"),
            Error::ExcessiveWork { required, target } => {
                writeln!(f, "Excessive work parameter for passphrase.")?;
                write!(
                    f,
                    "Decryption would take around {} seconds.",
                    1 << (required - target)
                )
            }
            Error::InvalidMac => write!(f, "Header MAC is invalid"),
            Error::InvalidRecipient => write!(f, "Recipient is invalid"),
            Error::Io(e) => e.fmt(f),
            Error::KeyDecryptionFailed => write!(f, "Failed to decrypt an encrypted key"),
            Error::KeyMismatch => write!(f, "A YubiKey stub did not match the YubiKey"),
            Error::MessageRequiresKeys => write!(f, "This message requires keys to decrypt"),
            Error::MessageRequiresPassphrase => {
                write!(f, "This message requires a passphrase to decrypt")
            }
            Error::NoMatchingKeys => write!(f, "No matching keys found"),
            Error::UnknownFormat => {
                writeln!(f, "Unknown age format.")?;
                write!(f, "Have you tried upgrading to the latest version?")
            }
            #[cfg(feature = "yubikey")]
            Error::YubiKey(e) => e.fmt(f),
        }
    }
}

impl From<chacha20poly1305::aead::Error> for Error {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        Error::DecryptionFailed
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<hmac::crypto_mac::MacError> for Error {
    fn from(_: hmac::crypto_mac::MacError) -> Self {
        Error::InvalidMac
    }
}

#[cfg(feature = "unstable")]
impl From<rsa::errors::Error> for Error {
    fn from(_: rsa::errors::Error) -> Self {
        Error::DecryptionFailed
    }
}

#[cfg(feature = "yubikey")]
impl From<yubikey_piv::error::Error> for Error {
    fn from(e: yubikey_piv::error::Error) -> Self {
        Error::YubiKey(e)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(inner) => Some(inner),
            #[cfg(feature = "yubikey")]
            Error::YubiKey(inner) => Some(inner),
            _ => None,
        }
    }
}
