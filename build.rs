use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let version = env::var("VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let commit = env::var("COMMIT").unwrap_or_else(|_| "unknown".to_string());
    let commit_short: String = commit.chars().take(8).collect();
    let full_version = format!("{}-{}", version, commit_short);

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR missing"));
    let dest = out_dir.join("wfb_version.rs");
    fs::write(
        &dest,
        format!("pub const WFB_VERSION: &str = \"{}\";\n", full_version),
    )
    .expect("write wfb_version.rs");

    println!("cargo:rustc-link-lib=pcap");
    println!("cargo:rerun-if-env-changed=VERSION");
    println!("cargo:rerun-if-env-changed=COMMIT");
}

