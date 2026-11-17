//! PUBLIC diagnostics plus a bounded PRIVATE stdin worker; no selectors or seeds.
use compact_all_payments_v3::{Error, engine};
use compact_arity_v3::statement::Arity;
use serde_json::Value;
use std::path::Path;
fn run(args: &[String]) -> Result<Value, Error> {
    match args {
        [mode] if mode == "inspect" => engine::inspect(),
        [mode, n, fixture, out] if mode == "prove-public" => {
            let n = n.parse::<usize>().map_err(|_| Error::Input)?;
            engine::prove_public(
                Arity::from_n(n).map_err(|_| Error::Input)?,
                Path::new(fixture),
                Path::new(out),
            )
        }
        [mode, out] if mode == "prove-private" => {
            engine::prove_private(std::io::stdin().lock(), Path::new(out))
        }
        [mode, dir] if mode == "verify-public" => engine::verify_public(Path::new(dir), true),
        [mode, dir] if mode == "valid-public" => engine::verify_public(Path::new(dir), false),
        [mode, a, b, c] if mode == "mixed-prepared" => {
            engine::mixed_prepared([Path::new(a), Path::new(b), Path::new(c)])
        }
        _ => Err(Error::Input),
    }
}
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let private = args.first().is_some_and(|m| m == "prove-private");
    // Must precede stdin lock/evaluation as well as the API's own entry guard.
    if private {
        engine::install_private_panic_hook();
    } else if args.first().is_some_and(|m| m == "prove-public") {
        std::panic::set_hook(Box::new(|_| eprintln!("PUBLIC_PROVER_PANIC")));
    }
    match run(&args) {
        Ok(value) => println!("{}", serde_json::to_string(&value).unwrap()),
        Err(error) => {
            if private {
                eprintln!("PRIVATE_CALLER_ERROR:{error:?}");
            } else {
                eprintln!("PUBLIC_CALLER_ERROR:{error:?}");
            }
            std::process::exit(1)
        }
    }
}
