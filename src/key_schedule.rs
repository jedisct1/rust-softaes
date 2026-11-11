use super::{bitsliced, Block};

// Round constants (Rcon); index 0 is unused.
pub(crate) const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

/// Rotates a 32-bit word left by 8 bits.
fn rot_word(word: u32) -> u32 {
    word.rotate_left(8)
}

/// Applies the inverse MixColumns transformation to an entire Block.
pub fn inv_mix_block(block: Block) -> Block {
    Block {
        lo: bitsliced::inv_mix_columns(block.lo),
        hi: bitsliced::inv_mix_columns(block.hi),
    }
}

/// Packs four key expansion words into a round key.
fn pack_round_key(w: &[u32], j: usize) -> Block {
    let mut bytes = [0u8; 16];
    for (i, chunk) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        *chunk = w[j + i].to_be_bytes();
    }
    Block::from_bytes(&bytes)
}

/// Expands a 16-byte AES-128 key into 11 128-bit blocks.
pub fn key_expansion_128(key: &[u8; 16]) -> [Block; 11] {
    const NK: usize = 4;
    const TOTAL_WORDS: usize = 44;
    let mut w = [0u32; TOTAL_WORDS];

    // Copy key into the first NK words.
    let mut i = 0;
    while i < NK {
        let j = i * 4;
        w[i] = ((key[j] as u32) << 24)
            | ((key[j + 1] as u32) << 16)
            | ((key[j + 2] as u32) << 8)
            | (key[j + 3] as u32);
        i += 1;
    }
    while i < TOTAL_WORDS {
        let mut temp = w[i - 1];
        if i % NK == 0 {
            temp = bitsliced::sub_word(rot_word(temp)) ^ ((RCON[i / NK] as u32) << 24);
        }
        w[i] = w[i - NK] ^ temp;
        i += 1;
    }
    let mut blocks = [Block::default(); 11];
    let mut i = 0;
    while i < 11 {
        let j = i * 4;
        blocks[i] = pack_round_key(&w, j);
        i += 1;
    }
    blocks
}

/// Expands a 24-byte AES-192 key into 13 128-bit blocks.
pub fn key_expansion_192(key: &[u8; 24]) -> [Block; 13] {
    const NK: usize = 6;
    const TOTAL_WORDS: usize = 52;
    let mut w = [0u32; TOTAL_WORDS];
    let mut i = 0;
    while i < NK {
        let j = i * 4;
        w[i] = ((key[j] as u32) << 24)
            | ((key[j + 1] as u32) << 16)
            | ((key[j + 2] as u32) << 8)
            | (key[j + 3] as u32);
        i += 1;
    }
    while i < TOTAL_WORDS {
        let mut temp = w[i - 1];
        if i % NK == 0 {
            temp = bitsliced::sub_word(rot_word(temp)) ^ ((RCON[i / NK] as u32) << 24);
        }
        w[i] = w[i - NK] ^ temp;
        i += 1;
    }
    let mut blocks = [Block::default(); 13];
    let mut i = 0;
    while i < 13 {
        let j = i * 4;
        blocks[i] = pack_round_key(&w, j);
        i += 1;
    }
    blocks
}

/// Expands a 32-byte AES-256 key into 15 128-bit blocks.
pub fn key_expansion_256(key: &[u8; 32]) -> [Block; 15] {
    const NK: usize = 8;
    const TOTAL_WORDS: usize = 60;
    let mut w = [0u32; TOTAL_WORDS];
    let mut i = 0;
    while i < NK {
        let j = i * 4;
        w[i] = ((key[j] as u32) << 24)
            | ((key[j + 1] as u32) << 16)
            | ((key[j + 2] as u32) << 8)
            | (key[j + 3] as u32);
        i += 1;
    }
    while i < TOTAL_WORDS {
        let mut temp = w[i - 1];
        if i % NK == 0 {
            temp = bitsliced::sub_word(rot_word(temp)) ^ ((RCON[i / NK] as u32) << 24);
        } else if i % NK == 4 {
            temp = bitsliced::sub_word(temp);
        }
        w[i] = w[i - NK] ^ temp;
        i += 1;
    }
    let mut blocks = [Block::default(); 15];
    let mut i = 0;
    while i < 15 {
        let j = i * 4;
        blocks[i] = pack_round_key(&w, j);
        i += 1;
    }
    blocks
}

/// Inverts an AES-128 encryption key schedule (11 blocks) to produce the
/// decryption key schedule.
///
/// For decryption the round keys are applied in reverse order, and every key
/// except the first and last is passed through InvMixColumns.
pub fn inverse_key_schedule_128(enc: &[Block; 11]) -> [Block; 11] {
    let mut dec = [Block::default(); 11];
    dec[0] = enc[10]; // Last round key (no InvMixColumns)
    let mut i = 1;
    while i < 10 {
        dec[i] = inv_mix_block(enc[10 - i]);
        i += 1;
    }
    dec[10] = enc[0]; // First round key (no InvMixColumns)
    dec
}

/// Inverts an AES-192 encryption key schedule (13 blocks) to produce the decryption key schedule.
pub fn inverse_key_schedule_192(enc: &[Block; 13]) -> [Block; 13] {
    let mut dec = [Block::default(); 13];
    dec[0] = enc[12];
    let mut i = 1;
    while i < 12 {
        dec[i] = inv_mix_block(enc[12 - i]);
        i += 1;
    }
    dec[12] = enc[0];
    dec
}

/// Inverts an AES-256 encryption key schedule (15 blocks) to produce the decryption key schedule.
pub fn inverse_key_schedule_256(enc: &[Block; 15]) -> [Block; 15] {
    let mut dec = [Block::default(); 15];
    dec[0] = enc[14];
    let mut i = 1;
    while i < 14 {
        dec[i] = inv_mix_block(enc[14 - i]);
        i += 1;
    }
    dec[14] = enc[0];
    dec
}
