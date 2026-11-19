# TKN1 private fixed-pair payments

TKN1 adds a second conserved integer to the blinded DLF1 note relation. The four additional typed openings, range checks, dummy guards and sum equation increase the unblinded gate count from 455 to 468. Both circuits round up to degree 4096. The two blinded proofs occupy the same 139,594 bytes on this configuration. Public inputs identify the anchor, nullifiers, output commitments, native fee and ordered receipt digest. Private input positions, 62-bit values on both lanes, spending keys, and four raw openings remain witnesses.

[Registered profile](PROFILE.md) · [Registered verifier](registry/token.vk) · [Measurements and controls](evidence/RESULT.json)

## Reproduce

The root reproduction tool provides clean checkout and input handling. For a component run from the canonical repository root, give the builder a pristine checkout of Qnero revision `f04c91307837c0231668383bec76ba98d89d2652`, Rust 1.93.0 with Cargo, Linux x86-64 with bubblewrap, and a writable Cargo target directory. Cargo fetches the locked dependency set and compiles offline. The builder uses its own disposable source copy, compiles the wallet and verifier into a single role-selecting executable, and captures hashes of all generated source files plus the lockfile. The binary hash can vary with build paths and environment. Both the validator and the prover derive the exact registered verifier again from the source. A wallet has a private tmpfs mount. Neither public role sees it.

```sh
python3 -IB experiments/token-profile/candidate/build.py "$work" "$upstream" "$target"
RAYON_NUM_THREADS=2 "$work/native" register "$work/registered"
cmp "$work/registered/token.vk" experiments/token-profile/candidate/registry/token.vk
python3 -IB experiments/token-profile/candidate/campaign.py generate "$work" "$work/public"
python3 -IB experiments/token-profile/candidate/campaign.py replay "$work" \
  experiments/token-profile/candidate/evidence \
  --approve-genesis 9e95a8af648c826ce0c0d5614ddbcf520a07dbf7a0f20f8a77d6d2102f338e0d
```

The last command replays the distributed public capture. A fresh generator uses new random wallets, receipts, proofs and PoW nonces, and records its own genesis digest. The author used `.work/token-profile-03`, clean Qnero at `.work/proof-architecture-01/upstream`, the existing `.work/proof-architecture-01/target` and `RUSTUP_HOME=/tmp/qnero-193-runtime`.

## Authenticated fixture

The validator checks the operator-approved genesis file digest, fixed network ID, four declared allocation pairs, unique endowment contexts and filled commitments. Genesis uses 8-byte magic, 32-byte network ID and four 112-byte rows. A row consists of context32, spend public key32, native LE64, token LE64 and CM32. The context hashes the network and row index. The profile derives public rho and raw randomness by hashing the 80-byte preimage under distinct TKN1 genesis domains. The fixture explicitly discloses this initialization and the intended synthetic transfers for audit. Private spending keys, note openings of wallet-generated outputs and wallet backups are absent from the evidence.

| Block | Payer → recipient | Real inputs, native/token | Payment native/token | Change native/token | Native fee |
|---|---|---:|---:|---:|---:|
| 1 | A → C | two, 200/120 | 0/40 | 197/80 | 3 |
| 2 | B → C | two, 200/120 | 70/65 | 127/55 | 3 |
| 3 | restored C → D | two, 70/105 | 41/75 | 26/30 | 3 |
| 4 | restored D → B | one, 41/75 | 12/14 | 26/61 | 3 |

C and D exported addresses and exited before the first payer began. Each recovery uses an empty, separately mounted private directory into which the driver copies the 32-byte seed alone. C receives all common genesis and receipt data, independently decrypts two incoming notes, checks both typed commitments, generates both private membership paths and pays D. One of its spent inputs has zero native value and 40 tokens. D independently opens a single incoming note and funds a fourth payment using a zero-valued dummy for the other input. At the end the four wallets hold 388 native and 240 token units. The public fee sink holds 12 native units. The two integers are units on fixed lanes with genesis-defined supply; there is no user asset-ID field.

Each accepted block is a fresh 22-bit SHA-256 proof-of-work seal. The 132-byte native header binds its parent native anchor, height, ordered public body digest, authenticated state digest and funded-note root. The state digest also includes the last accepted PoW hash. A fresh public role rebuilds the VK, opens only the approved genesis and public blocks, verifies every proof and both ciphertexts and recomputes commitments, spentness, native fee sink, header state and child linkage. The state transition computes and checks all candidate fields before mutating the in-memory state. This research ledger takes a single ordered branch. Fork selection, durable crash recovery, P2P relay and activation on earlier devnets are outside the experiment. Its linear wallet scans and fixed-order selection of the first one/two spendable notes serve this small fixture.

## Cost boundaries

A transfer contains 9 bytes of TKN1 framing, a 139,594-byte proof and two 1,792-byte encrypted receipts, totaling 143,187 bytes. Each archived singleton block adds 184 bytes and the approved genesis adds 488 bytes once. Four blocks and genesis occupy 573,972 bytes. One framed local public verifier call transfers 143,191 bytes in and 3,761 bytes of verified effects back. A local wallet's private proof request occupies 1,623 bytes including frame length and recipient address, and its result frame occupies 143,191 bytes. These directions are distinct. There is no measured peer transport on this fixture. A common-history scan at height h sends 601 + 3,712h framed bytes to a wallet and returns 8 + 20k local owner-only bytes for k current owned notes. Repeated restore and scan are additional traffic. Fee sink and commitments are inside blocks; proof and receipts need no extra content store.

The raw role meters use a monotonically increasing wall clock, process CPU including both Rayon threads, and Linux process peak RSS (a lifetime high-water mark). Setup, successful proof, negative control, scan and proof verification have distinct rows. Wallet request duration includes lazy setup for a cold role and stops at receipt of the payment packet. Header construction, mining and public replay are excluded from that duration.

| Wallet role | Setup wall s | Proof wall s | Proof CPU s | Process peak KiB |
|---|---:|---:|---:|---:|
| A | 1.564 | 3.810 | 7.439 | 451,828 |
| B | 1.382 | 3.839 | 7.477 | 451,960 |
| C after restoration | 1.426 | 3.864 | 7.573 | 451,680 |
| D after restoration | 1.402 | 3.787 | 7.422 | 452,044 |

A's earlier inconsistent-witness check paid its lazy setup. The measured public replay verifier took 1.473 s wall / 2.707 s CPU for setup and 6.69–6.80 ms wall for each of the four accepted packets, reaching 200,832 KiB process peak. These are four local samples.

## Controls and remaining assumptions

A dedicated test command constructs an otherwise honest, correctly funded spend with one extra token in the change output. Its four typed openings, native amounts, both ciphertexts, authenticated funded paths and spend credentials agree. The prover refuses this assignment. A canonical one-field change to a genuine proof's fee preserves its representation; source-selected verification precedes effects decoding. A repeated genuine payment reaches fresh cryptographic verification and is then refused by public current spentness. A wallet-only scan gives a successfully decryptable receipt next to the wrong public CM; the later correct receipt still restores and the complete public root remains checked.

Honest wallets encrypt both native and token values plus rho, raw opening and fixed-width memo using the pinned ML-KEM-1024 and ChaCha20-Poly1305 implementation. The on-chain proof binds the submitted ciphertext bytes through their digest. Correct encryption to either intended owner is an honest-wallet assumption. A recipient accepts an opening only when its private decoded values recreate the authenticated CM. A sender can still create an unusable receipt under this profile. Ciphertext digest calculation, full-protocol privacy, the proof system's quantum knowledge/zero-knowledge bounds, KEM recipient anonymity and its multi-user composition need their respective independent arguments. The fixed genesis, registered verifier, exact anchor branch and no alternate creation path are essential to the new monetary guarantee. The same raw keys or an imported historical commitment tree would need a distinct migration analysis.

The underlying fixed-width note machinery is pinned in this repository's source receipt. The general lattice KEM specification does not establish the security of the whole payment. [Qnero pinned upstream](https://github.com/DigitalGuards/qnero/tree/f04c91307837c0231668383bec76ba98d89d2652) · [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
