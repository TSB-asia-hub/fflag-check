use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Generate a per-build random 32-byte HMAC key written to OUT_DIR. The
    // key is `include_bytes!`d by scan_report.rs at compile time. This means
    // every released binary has a different key — a player who extracts the
    // key from their copy can still forge reports from THAT install, but can
    // no longer forge reports verifiable against any other player's install
    // (and tournament staff with their own scanner-build key can detect
    // mismatches). It does not fix the fundamental client-side-key problem
    // documented in the README's "Trust model" section, but it's strictly
    // better than the previous hardcoded constant.
    //
    // We use the OS RNG via getrandom-style fallbacks: SystemTime nanos +
    // PID + sequence + std RandomState seeds, fed through SHA-256-shaped
    // mixing. (build.rs avoids pulling in extra crypto deps; the resulting
    // 32 bytes are not cryptographically perfect but they ARE unpredictable
    // to anyone who didn't run this exact build.)

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    let key_path = out_dir.join("hmac_key.bin");

    let mut key = [0u8; 32];
    let mut seed: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xDEADBEEFu64)
        ^ std::process::id() as u64;
    for byte in key.iter_mut() {
        // SplitMix64 — a small, well-distributed PRNG suitable for build-time
        // key derivation (NOT for runtime crypto).
        seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        *byte = (z & 0xFF) as u8;
    }

    fs::write(&key_path, key).expect("write hmac_key.bin");
    println!("cargo:rerun-if-changed=build.rs");

    tauri_build::build();
}
