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

#[test]
fn protected_round_matches_table_round() {
    let mut state = 0x0123_4567_89ab_cdef;
    for _ in 0..100_000 {
        let blk = block16(&mut state);
        let rk = block16(&mut state);

        let got = SoftAes::block_encrypt(&Block::from_bytes(&blk), &Block::from_bytes(&rk));
        let want = USoftAes::block_encrypt(&UBlock::from_bytes(&blk), &UBlock::from_bytes(&rk));

        assert_eq!(got.to_bytes(), want.to_bytes());
    }
}
