use age_plugin::{run_plugin, AgeCallbacks, AgeError, AgePlugin, RecipientLine};
use gumdrop::Options;
use std::fmt;
use std::io;

const IDENTITY_PREFIX: &str = "age-plugin-unencrypted-";
const RECIPIENT_PREFIX: &str = "age1unencrypted";
const RECIPIENT_TAG: &str = "unencrypted";

#[derive(Debug)]
enum Error {
    InvalidIdentity,
    InvalidRecipient,
    UnsupportedRecipientLine,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidIdentity => write!(f, "Invalid identity"),
            Error::InvalidRecipient => write!(f, "Invalid recipient"),
            Error::UnsupportedRecipientLine => write!(f, "Unsupported recipient line"),
        }
    }
}

impl AgeError for Error {
    fn code(&self) -> u16 {
        // TODO
        1
    }
}

#[derive(Debug)]
struct Plugin;

impl AgePlugin for Plugin {
    type Error = Error;

    fn add_identity(&mut self, identity: String) -> Result<(), Self::Error> {
        bech32::decode(&identity)
            .map_err(|_| Error::InvalidIdentity)
            .and_then(|(hrp, data)| {
                if hrp == IDENTITY_PREFIX && data.is_empty() {
                    // A real plugin would store the identity.
                    Ok(())
                } else {
                    Err(Error::InvalidIdentity)
                }
            })
    }

    fn wrap_file_key(
        &mut self,
        file_key: &[u8],
        recipient: &str,
    ) -> Result<RecipientLine, Self::Error> {
        let (hrp, data) = bech32::decode(recipient).map_err(|_| Error::InvalidRecipient)?;
        if hrp == RECIPIENT_PREFIX && data.is_empty() {
            Ok(RecipientLine {
                tag: RECIPIENT_TAG.to_owned(),
                args: vec![
                    recipient.to_owned(),
                    "does".to_owned(),
                    "nothing".to_owned(),
                ],
                body: file_key.to_vec(),
            })
        } else {
            Err(Error::InvalidRecipient)
        }
    }

    fn unwrap_file_key(
        &mut self,
        tag: &str,
        _args: &[String],
        body: &[u8],
        mut callbacks: impl AgeCallbacks,
    ) -> Result<Vec<u8>, Self::Error> {
        if tag == RECIPIENT_TAG {
            let _ = callbacks.prompt("This identity does nothing!");
            Ok(body.to_vec())
        } else {
            Err(Error::UnsupportedRecipientLine)
        }
    }
}

#[derive(Debug, Options)]
struct PluginOptions {
    #[options(help = "print help message")]
    help: bool,

    #[options(help = "run as an age plugin", no_short)]
    run_plugin: bool,
}

fn main() -> io::Result<()> {
    let opts = PluginOptions::parse_args_default_or_exit();

    if opts.run_plugin {
        run_plugin(Plugin)
    } else {
        println!(
            "# public key: {}",
            bech32::encode(RECIPIENT_PREFIX, &[]).expect("HRP is valid")
        );
        println!(
            "{}",
            bech32::encode(IDENTITY_PREFIX, &[]).expect("HRP is valid")
        );
        Ok(())
    }
}
