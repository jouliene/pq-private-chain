# SWP1 private same-chain swap

Two wallets exchange assets in one mined state transition. In the walkthrough Alice pays 7 fixed units and the three-unit native fee. Bob pays 30 managed dollars. Both receive change. The same local PoW network, genesis, note tree, nullifier set, issuance and reward schedule remain in use. Participating nodes install the new consensus rules before the first swap block. The original AST1 and MNG1 paths stay executable.

## Reproduce

Use x86-64 Linux, Python 3.10+, Rustup, Git, a C toolchain, network access for pinned build dependencies and a working unprivileged bubblewrap installation. From the release checkout:

~~~sh
rustup toolchain install 1.93.0 --profile minimal
lab=$(mktemp -d)
./pqd swap --home "$lab/net" walkthrough
python3 -IB experiments/atomic-swap/measure.py "$lab/net/deployment" "$lab/net/public/SWAP.bin"
python3 -IB experiments/atomic-swap/controls.py "$lab/net/deployment" "$lab/net/public/SWAP.bin"
python3 -IB experiments/atomic-swap/check_admission.py "$lab/net"
~~~

The first command using the new home builds the original MNG1 suite and the separate registered SLG1 spend verifier. Keep the directory private. The operator walkthrough generates disposable seeds, separate wallet databases, three peer processes and a fourth empty node. Each private proving role mounts only its own seed directory. The local test harness shares a Unix account and simulates exchange of messages using private files. Each owner has a private backup directory separate from the negotiated messages. The proving sandbox receives no counterparty wallet or backup mount. For the manual two-party command sequence see the [wallet guide](wallet/README.md).

## Before final authorization

The counterparties exchange addresses and privately agree on the network, deadline, which party pays the fee, assets and quantities. A fresh 32-byte secret salt blinds the public commitment to the agreement. Each owner makes a proof using its own funding openings, spend keys and private tree paths. The two original receipts in each leg remain valid inputs to the ordinary MNG1 wallet. Each leg proves conservation for one hidden asset and native currency, including the exact local fee. It disallows issuance, requires a real first input and binds a fresh SLH-DSA-SHAKE-128f public key into the proof and both output commitments. [Registered leg relation and security assumptions](native/PROFILE.md)

A wallet checks both complete proofs, its funding anchor and pinned inputs, the exact private agreement, counterparty address, local fee, deadline and its own change. It decrypts the counterparty's incoming receipt, recomputes the commitment using its **own spending-derived public key**, checks the exact asset, native and token amounts and derives the real nullifier. A party can check control of the promised note before signing. Inclusion supplies the eventual tree membership. A competing spend or reorganization can still prevent inclusion.

Each wallet signs the same digest of the network, private terms commitment, inclusive expiry height, fee-paying seat and hashes of both ordered complete leg packets. Those hashes cover the two proofs, four commitments through their verified statements, and all four exact receipt ciphertexts. The wallet durably records its signature before returning it. Once both signatures have been released, any holder of the assembled bytes can submit the agreed swap while it remains eligible. A party can abort before release. Withholding its own signature after seeing the other's prevents inclusion and causes no on-chain debit. Disconnecting after release leaves the signature usable. See the [abort, expiry and reservation rules](wallet/README.md).

## Node and wire rules

The network admits one logical SWB1 submission containing exactly two SWF1 frames. Each physical frame carries one leg, one signature and the digest of the other ordered leg. The relay advertises the whole bundle under its SHA-256 ID. Isolated frame submissions are ineligible. In a block the frames must be adjacent in the order A, B. Every peer verifies both proofs and both signatures afresh, checks fee allocation and expiry at the candidate height, validates both branch anchors, and checks all four nullifiers and commitments for duplication or conflict. Database admission, state changes, miner fee credit and reorg processing use the complete group. Wallet history keeps one row per physical leg. Public transaction indices distinguish the two frame hashes and the one relay ID. [Canonical encoding](swap_wire.py) · [Consensus validation](swap_ledger.py)

An ordinary packet still has a 262,144-byte limit. Each swap frame has the same limit and consumes one of the four existing block slots. The submission transport accepts at most 524,301 bytes for the paired form. The previous 1,048,814-byte block maximum and four-slot bound still apply. A queued pair remains together when only one block slot remains. No incomplete legs are cached by a node. The released path adds public cost for two ephemeral signatures and two complete proofs and leaves historical proof-storage costs open.

## Visibility and remaining assumptions

The chain exposes that a swap occurred, its two seats, the payer and fee, inclusive expiry, anchors, four nullifiers, four output commitments, four ciphertexts, fresh authorization keys, signatures and the salted agreement commitment. This wallet always pays the counterparty at output zero and returns change at output one, so observers can label the positions. Public statements omit the amounts, asset identifiers and wallet addresses. Counterparties know the negotiated prices, assets and addresses. They also see each other's leg effects. A repeated bundle is byte-linkable. An ordinary conflict or reproposal spending the same note exposes its same real nullifier. The transport does not obscure network origin or timing. The public trial deliberately discloses its synthetic amounts and asset labels so an auditor can reconcile the balances.

Correctness depends on the registered spend proof, note/receipt binding, authenticated addresses, collision resistance of the commitment and authorization hashes, sound private randomness and the signatures. Finite runs do not establish a concrete end-to-end post-quantum knowledge or zero-knowledge bound. The file handoff assumes a confidential authenticated negotiation channel between counterparties. The prototype supplies neither such a network service nor fairness against a last signer who withholds authorization. Height expiry and the eight-block anchor window refer to a specific branch. PoW reorganization may reverse a previously included swap.

## Measured author exchange

The author captured both 139,658-byte leg proofs, four 1,792-byte ciphertexts, two 17,088-byte authorizations and all frame fields. Each leg before final authorization was 143,251 bytes. Each signed SWF1 block frame was 160,446 bytes. SWB1 was 320,905 bytes. The measured sender-to-node submit request was 320,928 bytes. Framing in a block adds 320,900 bytes above an empty block, resulting in a 321,122-byte swap-only block. One copy of the private terms, two preoffers and both released signatures totals 324,036 bytes before node submission. The negotiation used file handoff. A participant acting as assembler can retain its own final signature locally. A separate authenticated channel would add transport overhead. [Byte decomposition](evidence/AUTHOR-COST.json)

The prepared proofs took 4.78 s and 4.85 s wall time in the two owner roles. The wallets used approximately 441 MiB peak RSS apiece. After one warmup the five complete two-proof/two-signature checks took a median 24.96 ms wall and 24.35 ms CPU. The isolated native verifier reached 201,136 KiB peak RSS. A cold launch through its first verdict took 1.324 s wall and 2.418 CPU seconds across the observed processes. These measurements cover the proof/authorization or verifier role named. Mining, disk commits, initial builds and peer propagation are separate. [Per-wallet counters](evidence/AUTHOR-RUN.json) · [Cold and warm raw samples](evidence/AUTHOR-COST.json)

The author run included the swap at height 17 after the first funding view at 15. Two rejected negotiations used full, valid prepared proofs. One lacked the second owner's authorization. Another offered exactly 29 dollars and Alice's wallet rejected it before signing. One live branch included the swap, another included an ordinary spend of Bob's input, and a third advanced past expiry with both original inputs unspent. Reorganizations removed and restored both sides on a peer. The final fresh height-27 node counted 70 fixed units, 330 managed units, 2,700 newly mined native units and 36 in native fees across all selected activity. The swap supplied three of those fee units. Both restored wallets spent the actual incoming commitments using separate native fee funding. [Public outcomes](evidence/AUTHOR-RUN.json) · [Rejection checks](evidence/AUTHOR-CONTROLS.json)
