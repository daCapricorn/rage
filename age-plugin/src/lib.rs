//! Plugin system for age.
//!
//! # Draft design
//!
//! age plugins are identified by an arbitrary string `NAME`. Recipient addresses for a
//! particular plugin are encoded using Bech32 with the HRP "age1NAME", and key material
//! is encoded using Bech32 with the HRP "AGE-PLUGIN-NAME-". Recipient stanzas generated
//! by a plugin use the plugin name as their tag.
//!
//! TODO: Something about how age implementations find plugins.
//! - For testing, just assume one name.
//!
//! TODO: How can a plugin handle multiple recipient types?
//! - Have multiple names! Use symlinks from other names to the canonical one.
//!   - This is another "equivalent" to filesystem configuration, but without age config
//! - Most(?) Unix OSs support "alternatives"
//!
//! The IPC protocol is based around an age stanza (the same format used in the header):
//! - The tag field is used for command and response types.
//! - The arguments array is used for command-specific metadata.
//! - The body contains data associated with the command, if any.
//!
//! In particular, we leverage the fact that the first line of an age stanza consists of
//! SP-separated arbitary strings, in order to send recipient stanzas directly between the
//! age implementation and plugin by simply prepending with an appropriate command or
//! response type.
//!
//! ## Commands
//!
//! The following command stanzas are defined:
//!
//! - TODO: Explicit `set-version` command, or `version` arbitrary string argument on
//!   `wrap-file-key` and `unwrap-file-key`? Or pass version arbitrary string argument
//!   when starting the plugin?
//! - `add-identity\nBase64(IDENTITY)\n\n` - adds an identity that the plugin should use
//!   for trial decryption.
//! - `secret\nBase64(SECRET)\n\n` - a secret requested by the plugin and provided
//!   by the user.
//! - `wrap-file-key RECIPIENT\nBase64(FILE_KEY)\n\n` - encrypt the provided file key to
//!   the given recipient.
//! - `unwrap-file-key RECIPIENT_STANZA\n\n` - trial-decrypt the given recipient stanza.
//!
//! The following response stanzas are defined:
//!
//! - `prompt\nBase64(MESSAGE)\n\n` - a message that should be displayed to the user.
//! - `request-secret\nBase64(MESSAGE)\n\n` - the plugin requires a secret or PIN from the
//!   user in order to progress.
//! - `ok STANZA\n\n` - a command executed successfully; the stanza contains the response.
//! - `error CODE\nBase64(MESSAGE)\n\n` - an error occurred. Currently-defined error codes:
//!   - 1 - No identities were configured.
//!   - 2 - Decryption failed with all configured identities.
//!   - 3 - No configured identity matched the given recipient stanza.
//!   - 4 - The plugin timed out waiting for some user action.
//!
//! ## Encryption
//!
//! The file key is encrypted to recipients individually, to simplify associating a
//! particular ciphertext with a recipient. On successful encryption, the response stanza
//! contains the entire recipient stanza.
//!
//! ## Decryption
//!
//! The plugin is placed into decryption mode with a `set-identities` command, with
//! arguments set to the identities that the plugin should use for trial decryption.
//! Following this, a recipient stanza is sent in the `decrypt` command. The plugin may
//! make zero or more requests for the age implementation to either display a prompt to
//! the user, or request a secret from the user. Finally, on successful decryption, the
//! response stanza's body contains the decrypted file key.
//!
//! ## State machine
//!
//! ```text
//! wrap-file-key ---> ok
//!                '-> error
//!  ,-<----------.                           .->--------------------------<-.
//! add-identity ---> ok --> unwrap-file-key -|-> prompt --------------------|---> ok
//!               '-> error                   '-> request-secret --> secret -' '-> error
//! ```
//!
//! # Example interactions
//!
//! - `A`: age implementation
//! - `P`: plugin
//!
//! ## Key wrapping
//!
//! ```text
//! A --> P | wrap-file-key RECIPIENT_1
//!         | Base64(FILE_KEY)
//!         |
//! A <-- P | ok some-tag CJM36AHmTbdHSuOQL+NESqyVQE75f2e610iRdLPEN20
//!         | C3ZAeY64NXS4QFrksLm3EGz+uPRyI0eQsWw7LWbbYig
//!         |
//! A --> P | wrap-file-key RECIPIENT_2
//!         | Base64(FILE_KEY)
//!         |
//! A <-- P | ok some-tag ytazqsbmUnPwVWMVx0c1X9iUtGdY4yAB08UQTY2hNCI
//!         | N3pgrXkbIn/RrVt0T0G3sQr1wGWuclqKxTSWHSqGdkc
//!         |
//! ```
//!
//! ## Key unwrapping
//!
//! ```text
//! A --> P | add-identity YUBIKEY_ID_NO_PIN
//!         | Base64(YUBIKEY_ID_PIN_REQUIRED)
//!         |
//! A <-- P | ok
//!         |
//! A --> P | add-identity
//!         | Base64(YUBIKEY_ID_NO_PIN)
//!         |
//! A <-- P | ok
//!         |
//! A --> P | unwrap-file-key yubikey BjH7FA RO+wV4kbbl4NtSmp56lQcfRdRp3dEFpdQmWkaoiw6lY
//!         | 51eEu5Oo2JYAG7OU4oamH03FDRP18/GnzeCrY7Z+sa8
//!         |
//! A <-- P | prompt
//!         | Base64("Please insert YubiKey with serial 65227134")
//!         |
//! A <-- P | ok
//!         | Base64(FILE_KEY)
//!         |
//! A --> P | unwrap-file-key yubikey mhir0Q ZV/AhotwSGqaPCU43cepl4WYUouAa17a3xpu4G2yi5k
//!         | fgMiVLJHMlg9fW7CVG/hPS5EAU4Zeg19LyCP7SoH5nA
//!         |
//! A <-- P | request-secret
//!         | Base64("Please enter PIN for YubiKey with serial 65227134")
//!         |
//! A --> P | secret
//!         | Base64(123456)
//!         |
//! A <-- P | ok
//!         | Base64(FILE_KEY)
//!         |
//! A --> P | yubikey BjH7FA ZV/AhotwSGqaPCU43cepl4WYUouAa17a3xpu4G2yi5k
//!         | fgMiVLJHMlg9fW7CVG/hPS5EAU4Zeg19LyCP7SoH5nA
//!         |
//! P <-- A | error 1
//!         | Base64("Decryption failed")
//!         |
//! ```
//!
//! # Rationale
//!
//! The two driving goals behind the design are:
//! - No configuration.
//! - Simplest user experience possible.
//!
//! In order to have no configuration, age implementations need to be able to efficiently
//! detect which plugins support which recipient types. The simplest way to do this is to
//! have a 1:1 relationship between plugins and recipient types.
//!
//! ## Considered Alternatives
//!
//! - An age plugin could be queried for supported recipient types. This was discounted
//!   because it requires starting every installed plugin when only a subset of them might
//!   actually be able to encrypt or decrypt a given message.
//!
//! - An age plugin could, at install time, store a file containing the recipient types
//!   that it supports. This was discounted because it requires significantly more complex
//!   configuration support; instead of only needing one per-user folder, we would also
//!   need to handle system configuration folders across various platforms, as well as be
//!   safe across OS upgrades.

use cookie_factory::SerializeFn;
use secrecy::SecretString;
use std::fmt;
use std::io::{self, BufReader, Write};

mod format;

#[derive(Debug)]
pub struct RecipientLine {
    pub tag: String,
    pub args: Vec<String>,
    pub body: Vec<u8>,
}

pub trait AgeError: fmt::Display {
    fn code(&self) -> u16;
}

pub trait AgeCallbacks {
    fn prompt(&mut self, message: &str) -> io::Result<()>;

    fn request_secret(&mut self, message: &str) -> io::Result<SecretString>;
}

pub trait AgePlugin {
    type Error: AgeError;

    fn add_identity(&mut self, identity: String) -> Result<(), Self::Error>;

    fn wrap_file_key(
        &mut self,
        file_key: &[u8],
        recipient: &str,
    ) -> Result<RecipientLine, Self::Error>;

    fn unwrap_file_key(
        &mut self,
        tag: &str,
        args: &[String],
        body: &[u8],
        callbacks: impl AgeCallbacks,
    ) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug)]
pub enum Error<P: AgePlugin> {
    Io(io::Error),
    Plugin(P::Error),
}

impl<P: AgePlugin> From<io::Error> for Error<P> {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

fn write_reply<'a, F: SerializeFn<&'a mut io::Stdout>>(
    output: &'a mut io::Stdout,
    f: F,
) -> io::Result<()> {
    cookie_factory::gen_simple(f, output)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to write response: {}", e),
            )
        })?
        .flush()
}

struct Callbacks<'a> {
    input: &'a mut io::BufReader<io::Stdin>,
    output: &'a mut io::Stdout,
}

impl<'a> Callbacks<'a> {
    fn new(input: &'a mut io::BufReader<io::Stdin>, output: &'a mut io::Stdout) -> Self {
        Callbacks { input, output }
    }
}

impl<'a> AgeCallbacks for Callbacks<'a> {
    fn prompt(&mut self, message: &str) -> io::Result<()> {
        write_reply(self.output, format::write::prompt(message))
    }

    fn request_secret(&mut self, message: &str) -> io::Result<SecretString> {
        use crate::format::{write, Command};

        write_reply(self.output, write::request_secret(message))?;
        match Command::read(&mut self.input)? {
            Command::Secret(secret) => Ok(secret),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Did not receive command 'secret' from client",
            )),
        }
    }
}

pub fn run_plugin<P: AgePlugin>(mut plugin: P) -> io::Result<()> {
    use crate::format::{write, Command};
    use age_core::format::AgeStanza;

    let mut input = BufReader::new(io::stdin());
    let mut output = io::stdout();

    loop {
        // TODO: Handle "UnexpectedEof"
        match Command::read(&mut input)? {
            Command::AddIdentity(identity) => match plugin.add_identity(identity) {
                Ok(_) => {
                    let stanza = AgeStanza {
                        tag: "add-identity",
                        args: vec![],
                        body: vec![0],
                    };
                    write_reply(&mut output, write::ok(&stanza))?;
                }
                Err(e) => write_reply(&mut output, write::error(e.code(), &format!("{}", e)))?,
            },
            Command::WrapFileKey {
                recipient,
                file_key,
            } => match plugin.wrap_file_key(&file_key, &recipient) {
                Ok(r) => {
                    let args: Vec<_> = r.args.iter().map(|s| s.as_str()).collect();
                    let stanza = AgeStanza {
                        tag: &r.tag,
                        args,
                        body: r.body,
                    };
                    write_reply(&mut output, write::ok(&stanza))?;
                }
                Err(e) => write_reply(&mut output, write::error(e.code(), &format!("{}", e)))?,
            },
            Command::UnwrapFileKey { tag, args, body } => {
                match plugin.unwrap_file_key(
                    &tag,
                    &args,
                    &body,
                    Callbacks::new(&mut input, &mut output),
                ) {
                    Ok(file_key) => {
                        let stanza = AgeStanza {
                            tag: "file-key",
                            args: vec![],
                            body: file_key,
                        };
                        write_reply(&mut output, write::ok(&stanza))?;
                    }
                    Err(e) => write_reply(&mut output, write::error(e.code(), &format!("{}", e)))?,
                }
            }
            _ => write_reply(
                &mut output,
                write::error(20, "Command invalid at this time"),
            )?,
        }
    }
}
