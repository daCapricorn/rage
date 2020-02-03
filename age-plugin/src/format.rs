use std::io::{self, BufRead};

#[derive(Debug)]
pub(crate) enum Command {
    WrapFileKey {
        recipient: String,
        file_key: Vec<u8>,
    },
}

impl Command {
    pub(crate) fn read<R: BufRead>(mut input: R) -> io::Result<Self> {
        let mut buf = String::new();

        loop {
            match read::client_command(buf.as_bytes()) {
                // We can't return the response here, because we need to be able to mutate
                // self.buffer inside the loop.
                Ok(_) => break,
                Err(nom::Err::Incomplete(_)) => {
                    if input.read_line(&mut buf)? == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "incomplete command",
                        ));
                    };
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid command",
                    ));
                }
            }
        }

        // Now that we know the buffer contains a valid response, we re-parse so that we
        // can return an immutable lifetime.
        Ok(read::client_command(buf.as_bytes())
            .map(|(_, r)| r)
            .expect("Is valid"))
    }
}

mod read {
    use age_core::format::read::age_stanza;
    use nom::{
        character::streaming::newline,
        combinator::map_opt,
        sequence::{pair, terminated},
        IResult,
    };

    use super::Command;

    pub(super) fn client_command(input: &[u8]) -> IResult<&[u8], Command> {
        terminated(
            map_opt(age_stanza, |command| match command.tag {
                "wrap-file-key" => {
                    if command.args.len() == 1 {
                        Some(Command::WrapFileKey {
                            recipient: command.args[0].to_owned(),
                            file_key: command.body,
                        })
                    } else {
                        None
                    }
                }
                _ => None,
            }),
            pair(newline, newline),
        )(input)
    }
}

pub(crate) mod write {
    use age_core::format::{write::age_stanza, AgeStanza};
    use cookie_factory::{combinator::string, sequence::tuple, SerializeFn, WriteContext};
    use std::io::Write;
    use std::iter;

    pub(crate) fn ok<'a, W: 'a + Write>(stanza: &'a AgeStanza<'a>) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let args: Vec<_> = iter::once(stanza.tag)
                .chain(stanza.args.iter().cloned())
                .collect();
            let writer = tuple((age_stanza("ok", &args, &stanza.body), string("\n\n")));
            writer(w)
        }
    }

    pub(crate) fn error<'a, W: 'a + Write>(
        code: u16,
        description: &'a str,
    ) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let code = format!("{}", code);
            let args = &[code.as_str()];
            let writer = tuple((
                age_stanza("error", args, description.as_bytes()),
                string("\n\n"),
            ));
            writer(w)
        }
    }
}
