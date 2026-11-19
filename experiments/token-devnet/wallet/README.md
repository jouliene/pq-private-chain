# Ordinary fixed-pair wallet

The staged ordinary CLI accepts `send SENDER RECIPIENT NATIVE TOKEN`, where the recipient is a local name or an exported public-address file prefixed with `@`. Either requested amount may be zero. A positive token-only payment still needs three native fee units. `balance` reports `balance` (native), `token_balance`, and counts of current funded, mined, incoming and change notes. `resume` reuses the durable intent, including both amounts and the exact selected real inputs. `backup` writes the existing 32-byte private seed only. `restore` reconstructs selected-branch funds but cannot reconstruct the sender's off-chain intent journal from a seed.

The isolated role reconstructs each typed note from the authenticated public founding or reward record, or from an individually decryptable encrypted receipt that matches the output commitment. Direct funding uses the shared `C` rule. Reward records in common history carry 104 bytes with an implicit zero token amount; the wallet inserts the zero before checking their commitments. A keyed fixed-width memo allows the originating wallet to recognize its change after a fresh restore. Normal proof requests contain up to two exact private source rows and current compact sibling paths. Each real path independently authenticates its commitment to the same header root before proving. The secret wallet directory is accessible only to the isolated wallet role.

The existing history, frontier, sparse paths, retained eight-block rollback, deep reset and fixed-prefix endpoint validation remain active. Private balances and witness availability count a note when either lane is positive. A deep reset reconstructs the approved typed genesis row and root. Cold non-owners download the same public pages as owners on the same cursor and target. The wallet first tests available unreserved single notes, then pairs in leaf order, including token-only notes. Finding a suitable pair has quadratic worst-case local selection time. Both change amounts must fit 62 bits. Insufficient funding, a lost acknowledgment and an unavailable reserved note preserve the off-chain intent. Each first successful packet and its reservations are committed atomically, before submission; reanchoring may only reuse those real commitments.

The build overlays the live wallet code onto the published TKN1 build. Its public checker, circuit, dependency lock and receipt rules are unchanged. Register the resulting key and compare it byte-for-byte against `experiments/token-profile/candidate/registry/token.vk`. The isolated verifier has no wallet mount. On the author host the build used the following invocation:

```sh
RUSTUP_HOME=/tmp/qnero-193-runtime python3 -IB experiments/token-devnet/wallet/build.py \
  .work/token-net-native01 .work/proof-architecture-01/upstream .work/proof-architecture-01/target
RAYON_NUM_THREADS=2 .work/token-net-native01/native register .work/token-net-native01/registered
cmp experiments/token-profile/candidate/registry/token.vk .work/token-net-native01/registered/token.vk
```

`check.py DISPOSABLE_STAGED_HOME` exercises the installed role, genesis opening and witness, two-lane selection, immutable intent terms, and rollback of reservations when a private journal write fails. Use a newly staged home dedicated to this check, since it adds one test intent. The ordinary live scenario provides the four distinct observations that this component check does not exercise: mining, packet submission, canonical confirmation, and a restored payee's subsequent spend.
