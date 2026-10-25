//! Deterministic robustness tests: untrusted input must never panic.
//!
//! The audit asks for fuzzing of the blob parser, manifest validation and
//! extraction-path validation. Coverage-guided fuzzing (`cargo-fuzz`/libFuzzer)
//! requires a nightly toolchain; these tests provide a deterministic, seeded
//! stand-in that runs in CI on stable: random and mutated inputs are pushed
//! through every parser, and any panic fails the test.
//!
//! Not a substitute for real fuzzing, but it does catch the common classes of
//! panic (slice index, integer overflow on length maths, unwrap on None).

#![cfg(test)]

use crate::crypto::format::{self, BlobContext};
use crate::crypto::{kdf, kem};
use crate::paths;

/// Tiny deterministic xorshift PRNG — reproducible, no extra dependencies.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

fn ctx<'a>() -> BlobContext<'a> {
    BlobContext {
        vault_id: "0123456789abcdef0123456789abcdef",
        file_id: "fedcba9876543210fedcba9876543210",
    }
}

#[test]
fn blob_parser_never_panics_on_random_input() {
    let mut rng = Rng::new(0x5EED_1234);
    let c = ctx();

    for _ in 0..1500 {
        let len = rng.below(4096);
        let data = rng.bytes(len);
        // Must return an error, never panic.
        let _ = format::decrypt_file(&data, None, None, &c);
    }
}

#[test]
fn blob_parser_never_panics_on_truncation_and_mutation() {
    // Build one genuine blob, then corrupt/truncate/extend it.
    let privk = kem::generate_keypair();
    let pass_kek = kdf::derive(b"tundra velvet orbit lamplight", &[7u8; 32]).unwrap();
    let c = ctx();
    let valid = format::encrypt_file(
        b"representative plaintext payload",
        &privk.public(),
        &pass_kek,
        &c,
    )
    .unwrap();

    // Sanity: the unmodified blob decrypts.
    assert!(format::decrypt_file(&valid, Some(&privk), Some(&pass_kek), &c).is_ok());

    let mut rng = Rng::new(0xB10B_5678);

    // Truncations at every interesting boundary.
    for len in 0..valid.len().min(200) {
        let _ = format::decrypt_file(&valid[..len], Some(&privk), Some(&pass_kek), &c);
    }

    // Random bit flips.
    for _ in 0..400 {
        let mut m = valid.clone();
        let idx = rng.below(m.len());
        m[idx] ^= 1 << rng.below(8);
        // A mutation must fail authentication (or at worst yield a different
        // plaintext); it must never panic.
        let _ = format::decrypt_file(&m, Some(&privk), Some(&pass_kek), &c);
    }

    // Extensions with trailing garbage.
    for _ in 0..100 {
        let mut m = valid.clone();
        let extra = rng.below(64) + 1;
        m.extend(rng.bytes(extra));
        let _ = format::decrypt_file(&m, Some(&privk), Some(&pass_kek), &c);
    }
}

#[test]
fn path_validators_never_panic() {
    let mut rng = Rng::new(0xABCD_0001);

    // Structured nasties.
    let nasty = [
        "",
        ".",
        "..",
        "/",
        "\\",
        "//",
        "\\\\",
        "C:",
        "C:\\",
        "\\\\?\\C:\\x",
        "../../x",
        "..\\..\\x",
        "a/../../b",
        "con",
        "CON.txt",
        "nul",
        "a\u{0}b",
        "a\nb",
        "a\tb",
        "...",
        "....",
        "a.",
        "a ",
        " ",
        "\u{202e}gnp.exe",
        "\u{1F600}",
    ];
    let long = "a".repeat(10_000);
    for s in nasty.iter().copied().chain(std::iter::once(long.as_str())) {
        let _ = paths::validate_basename(s);
        let _ = paths::validate_relative(s);
        let _ = paths::validate_file_id(s);
    }

    // Random strings, including multi-byte UTF-8 and random lengths.
    let alphabet = [
        'a',
        'Z',
        '0',
        '9',
        '/',
        '\\',
        '.',
        ':',
        '*',
        '?',
        '"',
        '<',
        '>',
        '|',
        '\u{0}',
        '\u{7f}',
        'é',
        '中',
        '\u{1F600}',
        ' ',
    ];
    for _ in 0..2000 {
        let len = rng.below(48);
        let mut s = String::new();
        for _ in 0..len {
            s.push(alphabet[rng.below(alphabet.len())]);
        }
        let _ = paths::validate_basename(&s);
        let _ = paths::validate_relative(&s);
        let _ = paths::validate_file_id(&s);
    }

    // Random bytes that are not valid UTF-8, via lossy conversion.
    for _ in 0..500 {
        let n = rng.below(64);
        let raw = rng.bytes(n);
        let s = String::from_utf8_lossy(&raw).to_string();
        let _ = paths::validate_relative(&s);
        let _ = paths::validate_file_id(&s);
    }
}

#[test]
fn extraction_destination_never_escapes_on_random_names() {
    // Any name the validators accept must also resolve inside a base dir.
    let base = std::env::temp_dir().join(format!("qvault-fuzz-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();

    let mut rng = Rng::new(0xF00D_4321);
    let alphabet = ['a', 'b', '1', '2', '.', '/', '\\', '_', '-', ' '];

    for _ in 0..800 {
        let len = rng.below(12) + 1;
        let mut s = String::new();
        for _ in 0..len {
            s.push(alphabet[rng.below(alphabet.len())]);
        }
        if paths::validate_relative(&s).is_ok() {
            // Preparation must confine within base or fail; never escape.
            if let Ok(p) = paths::prepare_destination(&base, &s) {
                assert!(
                    p.starts_with(&base),
                    "prepared path escaped base: {s:?} -> {p:?}"
                );
            }
        }
    }

    let _ = std::fs::remove_dir_all(&base);
}
