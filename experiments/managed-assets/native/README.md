# Native MNG1 role checks

Reproduce the registered proof construction and all 13 relation verdicts using the [profile commands](PROFILE.md). The registered key's SHA-256 is `1895505caa69ce3cf55adcde8ce2e60c03ac0d7d4d8551888d71a8176e8b946d`. The registered relation has 489 gates before blinding and 31 public inputs, with padded degree 4,096. AST1 had 488 gates and the same padded degree. Full-size and timing comparisons require actual packets and live role meters. [Registration](REGISTER.json) · [Accepted and rejected witnesses](CHECK.json)

For the issuer check, run the following against the same freshly registered native binary. It uses a temporary private RAM directory for two independent wallets, restores the original issuer in a new wallet process and sends only a public key, digest and signature to the verifier process. Its disposable test digest uses the actual supply authorization encoder with a synthetic payload. Payment verification and canonical outer-envelope checks are separate live-node tests.

```sh
python3 -IB experiments/managed-assets/native/check_issuer.py "$lab/build" | cmp - experiments/managed-assets/native/ISSUER.json
```

The signed message is exactly SHA-256(ASCII MNG1/supply-auth/v1 || NUL || network32 || operation_u8 || issuer_pk32 || sequence_u64_LE || previous32 || SHA-256(inner_packet)). The signed operations are managed registration (2) and mint (3). The unsigned outer operation codes are transfer (0), fixed registration (1) and burn (4). The verifier's V command checks only the signature over its supplied digest. The node independently constructs that digest from the packet and branch state, performs the authorization/state checks and validates the complete inner proof. [Canonical outer encoder](../managed_ops.py) · [Issuer verdicts](ISSUER.json)

The pinned RustCrypto signing path calls deterministic pure SLH-DSA with empty context, and the verification path uses the corresponding pure-mode encoding. This signature authenticates a **public** issuer key, so repeated managed registrations under one wallet's issuer identity are linkable. A signed MSP1 wrapper adds 17,166 bytes to the complete inner payment. An unsigned MSP1 wrapper adds six. The difference is 32 key bytes, eight sequence bytes, 32 prior-event bytes and 17,088 signature bytes. The signed issue does not add a public key to subsequent ordinary private transfers. No formal end-to-end PQ/privacy qualification or independent FIPS validation was performed. [Pinned signature implementation](https://docs.rs/crate/slh-dsa/0.2.0-rc.5/source/src/signing_key.rs) · [Stateless hash-based signature standard](https://csrc.nist.gov/pubs/fips/205/final)

## Historical AST1 branch verification

The upgraded verifier also accepts complete AST1 inner packets, using the exact release key with SHA-256 `99ed868d5bd0f8541bb6467a210bf75140ec696e49e53044f7bca011ed59438a`. The build embeds the published bytes and records their hash in BUILD.json. Each public process decodes the key once at startup. The four-byte packet magic selects one of two operator-pinned circuits. The selected circuit validates the original proof and the public effects decoder checks the corresponding receipts. New wallet payments always use MNG1. The chain layer still controls which transaction forms and issuance policy each block height admits.

The author archive contains 14 complete historical packets, including three issuances and eleven ordinary payments across its recorded branches. Both the original and upgraded binaries verified all 14 and returned identical 3,797-byte effects on each. The upgraded binary rejected the historical proof relabelled MNG1 and a changed ciphertext. This packet comparison is separate from replay of the blocks, fork choice and an actual new spend of old funds. [Historical comparison](LEGACY.json) · [Released public AST1 captures](https://github.com/jouliene/pq-private-chain/releases/tag/live-user-assets-2026-11-20)

```sh
python3 -IB experiments/managed-assets/native/check_legacy.py "$ast1_build" "$lab/build" "$ast1_author_public_tar_gz" | cmp - experiments/managed-assets/native/LEGACY.json
```
