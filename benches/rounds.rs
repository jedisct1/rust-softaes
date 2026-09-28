//! Benchmark for the round functions.
//!
//! Each implementation is timed on a chained AES-128 encryption and decryption,
//! and on eight independent blocks at once, as in AEGIS-128L.

use std::hint::black_box;
use std::time::Instant;

const ITERS: u64 = 2_000_000;

/// Runs `f` repeatedly and prints the best time per round over five runs.
#[inline(always)]
fn measure(name: &str, label: &str, rounds_per_iter: u64, mut f: impl FnMut()) {
    for _ in 0..ITERS / 10 {
        f();
    }
    let mut best = f64::MAX;
    for _ in 0..5 {
        let start = Instant::now();
        for _ in 0..ITERS {
            f();
        }
        let ns = start.elapsed().as_nanos() as f64 / (ITERS * rounds_per_iter) as f64;
        best = best.min(ns);
    }
    println!("{:<12} {:<28} {:>7.3} ns/round", name, label, best);
}

macro_rules! bench_impl {
    ($name:expr, $block:ty, $aes:ty, $ks:path) => {{
        use $ks as ks;
        type B = $block;
        type A = $aes;

        let key = black_box([7u8; 16]);
        let rks = ks::key_expansion_128(&key);
        let dks = ks::inverse_key_schedule_128(&rks);

        let mut st = B::from_bytes(&[1u8; 16]);
        measure($name, "encrypt latency (aes128)", 10, || {
            let mut s = st.xor(&rks[0]);
            for rk in &rks[1..10] {
                s = A::block_encrypt(&s, rk);
            }
            st = A::block_encrypt_last(&s, &rks[10]);
        });
        black_box(st);

        let mut st = B::from_bytes(&[1u8; 16]);
        measure($name, "decrypt latency (aes128)", 10, || {
            let mut s = st.xor(&dks[0]);
            for rk in &dks[1..10] {
                s = A::block_decrypt(&s, rk);
            }
            st = A::block_decrypt_last(&s, &dks[10]);
        });
        black_box(st);

        let mut sts = [B::from_bytes(&[3u8; 16]); 8];
        for (i, s) in sts.iter_mut().enumerate() {
            *s = s.xor(&rks[i]);
        }
        let rk = rks[1];
        measure($name, "encrypt throughput (x8)", 8, || {
            // Not a loop: with a loop, the compiler no longer interleaves the
            // eight rounds.
            let rk = black_box(rk);
            let [a, b, c, d, e, f, g, h] = &mut sts;
            *a = A::block_encrypt(a, &rk);
            *b = A::block_encrypt(b, &rk);
            *c = A::block_encrypt(c, &rk);
            *d = A::block_encrypt(d, &rk);
            *e = A::block_encrypt(e, &rk);
            *f = A::block_encrypt(f, &rk);
            *g = A::block_encrypt(g, &rk);
            *h = A::block_encrypt(h, &rk);
        });
        black_box(sts);

        let rk = dks[1];
        measure($name, "decrypt throughput (x8)", 8, || {
            let rk = black_box(rk);
            let [a, b, c, d, e, f, g, h] = &mut sts;
            *a = A::block_decrypt(a, &rk);
            *b = A::block_decrypt(b, &rk);
            *c = A::block_decrypt(c, &rk);
            *d = A::block_decrypt(d, &rk);
            *e = A::block_decrypt(e, &rk);
            *f = A::block_decrypt(f, &rk);
            *g = A::block_decrypt(g, &rk);
            *h = A::block_decrypt(h, &rk);
        });
        black_box(sts);
    }};
}

fn main() {
    bench_impl!(
        "protected",
        softaes::Block,
        softaes::SoftAes,
        softaes::key_schedule
    );
    bench_impl!(
        "unprotected",
        softaes::unprotected::Block,
        softaes::unprotected::SoftAes,
        softaes::unprotected::key_schedule
    );
}
