use compact_all_payments_v3::engine;
use compact_proof_v1::{
    codec::MODULUS,
    types::{Cap, Challenge, Val},
};
use p3_field::BasedVectorSpace;
use std::{env, fs::OpenOptions, io::Write, path::Path, process::ExitCode};

mod transcript;
mod transport;

#[derive(Debug, PartialEq, Eq)]
enum Error {
    Argument,
    Io,
    Shape,
    Statement,
    Identity,
    Truncated,
    Trailing,
    NonCanonical,
    FixedSetup,
    Transcript,
    DuplicateMismatch,
    FixedMismatch,
    RoundTrip,
    Receipt,
    LegacyDecode,
    Crypto,
    Control,
}

type Result<T> = std::result::Result<T, Error>;

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or(Error::Shape)?;
        let bytes = self.bytes.get(self.at..end).ok_or(Error::Truncated)?;
        self.at = end;
        Ok(bytes)
    }

    fn peek_u32(&self) -> Result<u32> {
        let bytes = self
            .bytes
            .get(self.at..self.at + 4)
            .ok_or(Error::Truncated)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn base(&mut self) -> Result<Val> {
        let word = self.u64()?;
        if word >= MODULUS {
            return Err(Error::NonCanonical);
        }
        Ok(Val::new(word))
    }

    fn zero(&mut self) -> Result<Val> {
        if self.u64()? != 0 {
            return Err(Error::NonCanonical);
        }
        Ok(Val::new(0))
    }

    fn efs(&mut self, count: usize) -> Result<Vec<Challenge>> {
        (0..count)
            .map(|_| {
                let mut coefficients = [Val::new(0); 5];
                for coefficient in &mut coefficients {
                    *coefficient = self.base()?;
                }
                Challenge::from_basis_coefficients_slice(&coefficients).ok_or(Error::Shape)
            })
            .collect()
    }

    fn cap(&mut self) -> Result<Cap> {
        let mut root = [0; 8];
        for word in &mut root {
            *word = self.u64()?;
        }
        Ok(Cap::new(vec![root]))
    }

    fn finish(&self) -> Result<()> {
        if self.at != self.bytes.len() {
            return Err(Error::Trailing);
        }
        Ok(())
    }
}

fn run() -> Result<()> {
    let args = env::args_os().collect::<Vec<_>>();
    if let [_, command, input] = args.as_slice()
        && command == "controls"
    {
        let body =
            engine::bounded(Path::new(input), cp03_history::BODY_MAX).map_err(|_| Error::Io)?;
        println!("{}", transport::controls(&body)?);
        return Ok(());
    }
    let (pack, input, output) = match args.as_slice() {
        [_, command, input, output] if command == "pack" => (true, input, Some(output)),
        [_, command, input, output] if command == "expand" => (false, input, Some(output)),
        [_, command, input] if command == "verify" => (false, input, None),
        _ => return Err(Error::Argument),
    };
    let body = engine::bounded(Path::new(input), cp03_history::BODY_MAX).map_err(|_| Error::Io)?;
    let (bytes, result) = transport::run(&body, pack)?;
    if let Some(output) = output {
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(output)
            .and_then(|mut file| file.write_all(&bytes))
            .map_err(|_| Error::Io)?;
    }
    println!("{result}");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:?}");
            ExitCode::FAILURE
        }
    }
}
