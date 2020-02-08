//! Encryption and decryption routines for age.

use age_core::primitives::hkdf;
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::io::{self, Read, Seek, Write};
use std::iter;

use crate::{
    error::Error,
    format::{oil_the_joint, scrypt, Header, RecipientLine},
    keys::{FileKey, Identity, IdentityKey, RecipientKey},
    plugin,
    primitives::{
        armor::{ArmoredReader, ArmoredWriter},
        stream::{Stream, StreamReader, StreamWriter},
    },
    Format,
};

const HEADER_KEY_LABEL: &[u8] = b"header";
const PAYLOAD_KEY_LABEL: &[u8] = b"payload";

/// Callbacks that might be triggered during decryption.
pub trait Callbacks {
    /// Shows a prompt.
    fn prompt(&self, message: &str);

    /// Requests a passphrase to decrypt a key.
    fn request_passphrase(&self, description: &str) -> Option<SecretString>;
}

struct NoCallbacks;

impl Callbacks for NoCallbacks {
    fn prompt(&self, _message: &str) {}

    fn request_passphrase(&self, _description: &str) -> Option<SecretString> {
        None
    }
}

/// Handles the various types of age encryption.
pub enum Encryptor {
    /// Encryption to a list of recipients identified by keys.
    Keys(Vec<RecipientKey>),
    /// Encryption to a passphrase.
    Passphrase(SecretString),
}

impl Encryptor {
    fn wrap_file_key(&self, file_key: &FileKey) -> Vec<RecipientLine> {
        match self {
            Encryptor::Keys(recipients) => {
                // Collect the names of the required plugins.
                let mut plugin_names: Vec<_> = recipients
                    .iter()
                    .filter_map(|key| match key {
                        RecipientKey::Plugin { name, .. } => Some(name),
                        _ => None,
                    })
                    .collect();
                plugin_names.sort();
                plugin_names.dedup();

                // Connect to the required plugins.
                let mut plugins = plugin_names
                    .into_iter()
                    .map(|name| {
                        plugin::KeyWrapper::for_plugin(name).map(|conn| (name.clone(), conn))
                    })
                    .collect::<Result<_, _>>()
                    .expect("TODO: errors");

                // Now we can go ahead and wrap the file key to each recipient.
                recipients
                    .iter()
                    .map(|key| key.wrap_file_key(file_key, &mut plugins))
                    // Keep the joint well oiled!
                    .chain(iter::once(oil_the_joint()))
                    .collect()
            }
            Encryptor::Passphrase(passphrase) => {
                vec![scrypt::RecipientLine::wrap_file_key(file_key, passphrase).into()]
            }
        }
    }

    /// Creates a wrapper around a writer that will encrypt its input, and optionally
    /// ASCII armor the output.
    ///
    /// Returns errors from the underlying writer while writing the header.
    ///
    /// You **MUST** call `finish()` when you are done writing, in order to finish the
    /// encryption process. Failing to call `finish()` will result in a truncated message
    /// that will fail to decrypt.
    pub fn wrap_output<W: Write>(&self, output: W, format: Format) -> io::Result<StreamWriter<W>> {
        let mut output = ArmoredWriter::wrap_output(output, format)?;

        let file_key = FileKey::generate();

        let header = Header::new(
            self.wrap_file_key(&file_key),
            hkdf(&[], HEADER_KEY_LABEL, file_key.0.expose_secret()),
        );
        header.write(&mut output)?;

        let mut nonce = [0; 16];
        OsRng.fill_bytes(&mut nonce);
        output.write_all(&nonce)?;

        let payload_key = hkdf(&nonce, PAYLOAD_KEY_LABEL, file_key.0.expose_secret());
        Ok(Stream::encrypt(&payload_key, output))
    }
}

/// Handles the various types of age decryption.
pub enum Decryptor {
    /// Trial decryption against a list of identities.
    Identities {
        /// Identities that can be handled directly.
        identities: Vec<Identity>,
        /// Identities that require a plugin.
        plugin_identities: HashMap<String, Vec<String>>,
        /// A handler for any callbacks triggered by an `Identity`.
        callbacks: Box<dyn Callbacks>,
    },
    /// Decryption with a passphrase.
    Passphrase {
        /// The passphrase to decrypt with.
        passphrase: SecretString,
        /// The maximum accepted work factor. If `None`, the default maximum is adjusted
        /// to around 16 seconds of work.
        max_work_factor: Option<u8>,
    },
}

impl Decryptor {
    /// Creates a decryptor with a list of identities.
    ///
    /// The decryptor will have no callbacks registered, so it will be unable to use
    /// identities that require e.g. a passphrase to decrypt.
    pub fn with_identities(identities: Vec<Identity>) -> Self {
        Self::with_identities_and_callbacks(identities, Box::new(NoCallbacks))
    }

    /// Creates a decryptor with a list of identities and a callback handler.
    ///
    /// The decryptor will have no callbacks registered, so it will be unable to use
    /// identities that require e.g. a passphrase to decrypt.
    pub fn with_identities_and_callbacks(
        identities: Vec<Identity>,
        callbacks: Box<dyn Callbacks>,
    ) -> Self {
        // Partition identities by plugin name
        let mut plugin_identities: HashMap<String, Vec<String>> = HashMap::new();
        let identities = identities
            .into_iter()
            .filter(|i| match i.key() {
                IdentityKey::Plugin { name, identity } => {
                    plugin_identities
                        .entry(name.clone())
                        .or_default()
                        .push(identity.clone());
                    false
                }
                _ => true,
            })
            .collect();

        Decryptor::Identities {
            identities,
            plugin_identities,
            callbacks,
        }
    }

    /// Creates a decryptor with a passphrase and the default max work factor.
    pub fn with_passphrase(passphrase: SecretString) -> Self {
        Decryptor::Passphrase {
            passphrase,
            max_work_factor: None,
        }
    }

    fn unwrap_file_key(&self, line: &RecipientLine) -> Result<Option<FileKey>, Error> {
        match (self, line) {
            (Decryptor::Identities { .. }, RecipientLine::Scrypt(_)) => {
                Err(Error::MessageRequiresPassphrase)
            }
            (
                Decryptor::Identities {
                    plugin_identities,
                    callbacks,
                    ..
                },
                RecipientLine::Plugin(r),
            ) => plugin_identities
                .get(&r.tag)
                .and_then(|identities| {
                    plugin::KeyUnwrapper::for_plugin(&r.tag, identities)
                        .and_then(|mut conn| conn.unwrap_file_key(r, callbacks.as_ref()))
                        .transpose()
                })
                .transpose(),
            (
                Decryptor::Identities {
                    identities,
                    callbacks,
                    ..
                },
                _,
            ) => identities
                .iter()
                .find_map(|key| key.unwrap_file_key(line, callbacks.as_ref()))
                .transpose(),
            (
                Decryptor::Passphrase {
                    passphrase,
                    max_work_factor,
                },
                RecipientLine::Scrypt(s),
            ) => s.unwrap_file_key(passphrase, *max_work_factor),
            (Decryptor::Passphrase { .. }, _) => Err(Error::MessageRequiresKeys),
        }
    }

    /// Attempts to decrypt a message from the given reader.
    ///
    /// `request_passphrase` is a closure that will be called when an underlying key needs
    /// to be decrypted before it can be used to decrypt the message.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn trial_decrypt<R: Read>(&self, input: R) -> Result<impl Read, Error> {
        let mut input = ArmoredReader::from_reader(input);

        match Header::read(&mut input)? {
            Header::V1(header) => {
                let mut nonce = [0; 16];
                input.read_exact(&mut nonce)?;

                header
                    .recipients
                    .iter()
                    .find_map(|r| {
                        self.unwrap_file_key(r).transpose().map(|res| {
                            res.and_then(|file_key| {
                                // Verify the MAC
                                header.verify_mac(hkdf(
                                    &[],
                                    HEADER_KEY_LABEL,
                                    file_key.0.expose_secret(),
                                ))?;

                                // Return the payload key
                                Ok(hkdf(&nonce, PAYLOAD_KEY_LABEL, file_key.0.expose_secret()))
                            })
                        })
                    })
                    .unwrap_or(Err(Error::NoMatchingKeys))
                    .map(|payload_key| Stream::decrypt(&payload_key, input))
            }
            Header::Unknown(_) => Err(Error::UnknownFormat),
        }
    }

    /// Attempts to decrypt a message from the given seekable reader.
    ///
    /// `request_passphrase` is a closure that will be called when an underlying key needs
    /// to be decrypted before it can be used to decrypt the message.
    ///
    /// If successful, returns a seekable reader that will provide the plaintext.
    pub fn trial_decrypt_seekable<R: Read + Seek>(
        &self,
        mut input: R,
    ) -> Result<StreamReader<R>, Error> {
        match Header::read(&mut input)? {
            Header::V1(header) => {
                let mut nonce = [0; 16];
                input.read_exact(&mut nonce)?;

                header
                    .recipients
                    .iter()
                    .find_map(|r| {
                        self.unwrap_file_key(r).transpose().map(|res| {
                            res.and_then(|file_key| {
                                // Verify the MAC
                                header.verify_mac(hkdf(
                                    &[],
                                    HEADER_KEY_LABEL,
                                    file_key.0.expose_secret(),
                                ))?;

                                // Return the payload key
                                Ok(hkdf(&nonce, PAYLOAD_KEY_LABEL, file_key.0.expose_secret()))
                            })
                        })
                    })
                    .unwrap_or(Err(Error::NoMatchingKeys))
                    .and_then(|payload_key| {
                        Stream::decrypt_seekable(&payload_key, input).map_err(Error::from)
                    })
            }
            Header::Unknown(_) => Err(Error::UnknownFormat),
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use std::io::{BufReader, Read, Write};

    use super::{Decryptor, Encryptor};
    use crate::keys::{Identity, RecipientKey};
    use crate::Format;

    #[test]
    fn x25519_round_trip() {
        let buf = BufReader::new(crate::keys::tests::TEST_SK.as_bytes());
        let sk = Identity::from_buffer(buf).unwrap();
        let pk: RecipientKey = crate::keys::tests::TEST_PK.parse().unwrap();

        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::Keys(vec![pk]);
        {
            let mut w = e.wrap_output(&mut encrypted, Format::Binary).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = Decryptor::with_identities(sk);
        let mut r = d.trial_decrypt(&encrypted[..]).unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[test]
    fn scrypt_round_trip() {
        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::Passphrase(SecretString::new("passphrase".to_string()));
        {
            let mut w = e.wrap_output(&mut encrypted, Format::Binary).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = Decryptor::with_passphrase(SecretString::new("passphrase".to_string()));
        let mut r = d.trial_decrypt(&encrypted[..]).unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn ssh_rsa_round_trip() {
        let buf = BufReader::new(crate::keys::tests::TEST_SSH_RSA_SK.as_bytes());
        let sk = Identity::from_buffer(buf).unwrap();
        let pk: RecipientKey = crate::keys::tests::TEST_SSH_RSA_PK.parse().unwrap();

        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::Keys(vec![pk]);
        {
            let mut w = e.wrap_output(&mut encrypted, Format::Binary).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = Decryptor::with_identities(sk);
        let mut r = d.trial_decrypt(&encrypted[..]).unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[test]
    fn ssh_ed25519_round_trip() {
        let buf = BufReader::new(crate::keys::tests::TEST_SSH_ED25519_SK.as_bytes());
        let sk = Identity::from_buffer(buf).unwrap();
        let pk: RecipientKey = crate::keys::tests::TEST_SSH_ED25519_PK.parse().unwrap();

        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::Keys(vec![pk]);
        {
            let mut w = e.wrap_output(&mut encrypted, Format::Binary).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = Decryptor::with_identities(sk);
        let mut r = d.trial_decrypt(&encrypted[..]).unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }
}
