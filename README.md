# softaes

A fast software implementation of the AES round function in pure Rust.

This crate is not a high-level "encrypt my buffer" library. It exposes the AES
round function itself as a building block, the same primitive that backs
constructions such as AEGIS, AES-based PRFs, and other designs that lean on the
AES round for mixing. If that is what you need, you get it here without pulling
in hardware intrinsics or unsafe assembly.

The code is `no_std`, has no dependencies, and runs anywhere Rust runs.

## Two implementations

The crate ships two round functions and lets you pick the trade-off explicitly.

The default path, at the crate root, is **constant-time**. The round is computed
with a bitsliced representation (called SRM-1R) that holds the block as eight
32-bit bit planes. ShiftRows is folded into the input packing, SubBytes is a
gate-only Boolean S-box circuit, and MixColumns is a fixed sequence of rotations
and XORs. No step ever indexes memory with secret data, so the round runs in
constant time on every platform. This is the one to reach for when the input is
secret.

The `unprotected` module is a classic table-based implementation. It is faster
on machines with good caches, but the table lookups are indexed by secret data,
so it leaks through cache-timing side channels. Use it only when the data is not
secret, or when you have already accepted that risk.

## Installation

```toml
[dependencies]
softaes = "0.1"
```

## Using the constant-time round

`SoftAes::block_encrypt` applies one full forward round: SubBytes, ShiftRows,
MixColumns, and then AddRoundKey with the round key you pass in.

```rust
use softaes::{Block, SoftAes};

let state = Block::from_bytes(&[0u8; 16]);
let round_key = Block::from_bytes(&[0u8; 16]);

let next = SoftAes::block_encrypt(&state, &round_key);
let bytes = next.to_bytes();
```

For historical reasons the crate also exports `SoftAesFast`, `SoftAesModerate`,
and `SoftAesSlow`. These used to select between table variants with different
amounts of cache-timing hardening; they are now all aliases for the single
constant-time `SoftAes`, kept so existing code keeps compiling.

## Building the full cipher

A standard AES encryption is the initial AddRoundKey, a number of full rounds,
and a final round that omits MixColumns. The constant-time path deliberately
exposes only the full round, which is all the AES-round constructions need. To
assemble the complete cipher, including the final round and decryption, use the
`unprotected` module, which provides `block_encrypt`, `block_encrypt_last`,
`block_decrypt`, and `block_decrypt_last`.

```rust
use softaes::unprotected::{Block, SoftAes};
use softaes::unprotected::key_schedule::key_expansion_128;

let key = [0u8; 16];
let plaintext = [0u8; 16];

let round_keys = key_expansion_128(&key);

let mut state = Block::from_bytes(&plaintext).xor(&round_keys[0]);
for rk in &round_keys[1..10] {
    state = SoftAes::block_encrypt(&state, rk);
}
let ciphertext = SoftAes::block_encrypt_last(&state, &round_keys[10]).to_bytes();
```

## Key schedule

Both paths carry a `key_schedule` module with the same interface:

- `key_expansion_128`, `key_expansion_192`, `key_expansion_256` expand a key into
  the encryption round keys.
- `inverse_key_schedule_128`, `inverse_key_schedule_192`,
  `inverse_key_schedule_256` turn an encryption schedule into the matching
  decryption schedule, reversing the round-key order and applying InvMixColumns
  to every key except the first and last.

The constant-time `key_schedule` runs its S-box lookups in constant time; the one
under `unprotected` uses a direct table. Both produce identical round keys, and
the expansions are checked against the FIPS 197 Appendix C test vectors.

## License

MIT. See [LICENSE](LICENSE).
