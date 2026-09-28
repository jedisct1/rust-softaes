use softaes::unprotected::{Block as UBlock, SoftAes as USoftAes};
use softaes::{Block, SoftAes};

// A tiny xorshift generator so the test stays deterministic without rand.
fn next(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn block16(state: &mut u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&next(state).to_le_bytes());
    out[8..16].copy_from_slice(&next(state).to_le_bytes());
    out
}

/// Both implementations must agree on every round function, for random inputs.
#[test]
fn protected_rounds_match_table_rounds() {
    let mut state = 0x0123_4567_89ab_cdef;
    for _ in 0..100_000 {
        let blk = block16(&mut state);
        let rk = block16(&mut state);

        let p = Block::from_bytes(&blk);
        let prk = Block::from_bytes(&rk);
        let u = UBlock::from_bytes(&blk);
        let urk = UBlock::from_bytes(&rk);

        assert_eq!(
            SoftAes::block_encrypt(&p, &prk).to_bytes(),
            USoftAes::block_encrypt(&u, &urk).to_bytes(),
            "block_encrypt"
        );
        assert_eq!(
            SoftAes::block_encrypt_last(&p, &prk).to_bytes(),
            USoftAes::block_encrypt_last(&u, &urk).to_bytes(),
            "block_encrypt_last"
        );
        assert_eq!(
            SoftAes::block_decrypt(&p, &prk).to_bytes(),
            USoftAes::block_decrypt(&u, &urk).to_bytes(),
            "block_decrypt"
        );
        assert_eq!(
            SoftAes::block_decrypt_last(&p, &prk).to_bytes(),
            USoftAes::block_decrypt_last(&u, &urk).to_bytes(),
            "block_decrypt_last"
        );
    }
}
