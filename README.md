# 0x307 examples

Runnable reference implementations for the 0x307 post-quantum crates. Every
example in this repository is compiled and executed by CI on every push — if
a published release breaks one, the build goes red before a reader finds out.

Each example pins the exact version `cargo add` gives you today. Nothing here
depends on an unreleased branch, a private crate, or a local path.

```bash
git clone https://github.com/0x307/examples
cd examples
cargo run -p ex01-pqc-digital-signatures
```

## The examples

| | Crate | What it shows |
| :-- | :-- | :-- |
| [01](01-pqc-digital-signatures) | `pqc-sig` | ML-DSA-65 (FIPS 204) sign and verify, context-bound signatures, W3C Multikey encoding |
| [02](02-pqc-key-exchange) | `pqc-kem` | ML-KEM-768 (FIPS 203) encapsulation, and hybrid X25519 + ML-KEM for migration |
| [03](03-anonymous-agent-identity) | `aethel-sdk` | Per-context identity projection — unlinkable identifiers instead of one static DID |
| [04](04-x402-vault-micropayments) | `aethel-vault` | Policy-gated EIP-3009 / x402 USDC authorization with a real `k256` signer |

## What these crates are and are not

**Not independently audited.** These crates implement NIST-standardized
algorithms and are covered by known-answer tests against NIST ACVP vectors,
but no third party has audited them. Treat them accordingly.

**FN-DSA (FIPS 206) is a draft standard** and is off by default in `pqc-sig`.
Its Multikey codes are private-use and will not be understood by generic
decoders. Do not use it as an interop default.

**`aethel-vault` contains no ECDSA code.** It builds the EIP-712 digest and
enforces your spend policy; you supply the secp256k1 signer. Example 04
implements one with `k256` so it actually runs.

**Known version constraint:** `aethel-vault 0.2.0` depends on
`aethel-core "0.6"` while the latest `aethel-core` is `0.7.0`. Using both at
their newest versions puts two incompatible copies in the dependency graph.
Pin `aethel-core = "0.6.1"` alongside the vault. Example 04 documents this
inline.

## Links

* Crates: [pqc-sig](https://crates.io/crates/pqc-sig) ·
  [pqc-kem](https://crates.io/crates/pqc-kem) ·
  [aethel-core](https://crates.io/crates/aethel-core) ·
  [aethel-sdk](https://crates.io/crates/aethel-sdk) ·
  [aethel-vault](https://crates.io/crates/aethel-vault) ·
  [pqc-privacy](https://crates.io/crates/pqc-privacy)
* API docs: [docs.rs/pqc-sig](https://docs.rs/pqc-sig) ·
  [docs.rs/pqc-kem](https://docs.rs/pqc-kem) ·
  [docs.rs/aethel-sdk](https://docs.rs/aethel-sdk) ·
  [docs.rs/aethel-vault](https://docs.rs/aethel-vault)
* Questions, bugs, or something that does not run: open an issue, or
  hello@0x307.com

## License

MIT OR Apache-2.0, matching the crates themselves.
