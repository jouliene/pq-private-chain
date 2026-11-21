use std::{env, fs, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let upstream = manifest.join("../../../../advancing-note/proof/src");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    println!(
        "cargo:rerun-if-changed={}",
        upstream.join("public.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        upstream.join("oracle.rs").display()
    );

    let public = fs::read_to_string(upstream.join("public.rs"))
        .unwrap()
        .replacen("//!", "///", 1)
        .replace("N7P2.fixed-statement.49.v1", "C2N7.fixed-statement.49.v1")
        .replace(
            "N7P2/registered-statement/FS/v1",
            "C2N7/registered-statement/FS/v1",
        );
    fs::write(out.join("public.rs"), public).unwrap();

    let oracle = fs::read_to_string(upstream.join("oracle.rs"))
        .unwrap()
        .replacen("//!", "///", 1)
        .replace("N7P2", "C2N7");
    fs::write(out.join("oracle.rs"), oracle).unwrap();
}
