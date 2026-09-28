//! FIPS 197 Appendix C test vectors, run through both implementations.
//!
//! Each test does a full encryption and decryption, so it also checks that the
//! key schedule produces round keys in the byte order the rounds expect.

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

const PLAINTEXT: &str = "00112233445566778899aabbccddeeff";

// Key, ciphertext, and the last round key of the expanded schedule
// (FIPS 197 Appendix A).
const AES128: [&str; 3] = [
    "000102030405060708090a0b0c0d0e0f",
    "69c4e0d86a7b0430d8cdb78070b4c55a",
    "13111d7fe3944a17f307a78b4d2b30c5",
];
const AES192: [&str; 3] = [
    "000102030405060708090a0b0c0d0e0f1011121314151617",
    "dda97ca4864cdfe06eaf70a0ec0d7191",
    "a4970a331a78dc09c418c271e3a41d5d",
];
const AES256: [&str; 3] = [
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "8ea2b7ca516745bfeafc49904b496089",
    "24fc79ccbf0979e9371ac23c6d68de36",
];

macro_rules! known_answer_tests {
    ($name:ident, $($path:ident)::+) => {
        mod $name {
            use super::*;
            use $($path)::+::key_schedule::*;
            use $($path)::+::{Block, SoftAes};

            fn check(vector: [&str; 3], ks: &[Block], dks: &[Block]) {
                let pt = unhex::<16>(PLAINTEXT);
                let ct = unhex::<16>(vector[1]);
                let last = ks.len() - 1;
                assert_eq!(ks[last].to_bytes(), unhex::<16>(vector[2]));

                let mut st = Block::from_bytes(&pt).xor(&ks[0]);
                for rk in &ks[1..last] {
                    st = SoftAes::block_encrypt(&st, rk);
                }
                assert_eq!(SoftAes::block_encrypt_last(&st, &ks[last]).to_bytes(), ct);

                let mut st = Block::from_bytes(&ct).xor(&dks[0]);
                for rk in &dks[1..last] {
                    st = SoftAes::block_decrypt(&st, rk);
                }
                assert_eq!(SoftAes::block_decrypt_last(&st, &dks[last]).to_bytes(), pt);
            }

            #[test]
            fn aes128() {
                let ks = key_expansion_128(&unhex(AES128[0]));
                check(AES128, &ks, &inverse_key_schedule_128(&ks));
            }

            #[test]
            fn aes192() {
                let ks = key_expansion_192(&unhex(AES192[0]));
                check(AES192, &ks, &inverse_key_schedule_192(&ks));
            }

            #[test]
            fn aes256() {
                let ks = key_expansion_256(&unhex(AES256[0]));
                check(AES256, &ks, &inverse_key_schedule_256(&ks));
            }
        }
    };
}

known_answer_tests!(protected, softaes);
known_answer_tests!(unprotected, softaes::unprotected);
