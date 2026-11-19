# APV2 crash and uncertain-delivery checks

The harness requires the complete authoritative public author trace, approved genesis, registered verifier keys and binary. It creates separate local archival databases, relays actual public payment packets and invokes the normal selected-chain and ingress implementations. The binary's only roles here are hashing and public proof verification. No wallet setup, private opening, builder or prover is involved.

## Process death during a selected-branch switch

1. A fresh process replays the genuine author prefix into its own archive, confirms the published pre-switch state and exits. It records the SQL rows of all four tables via a typed, length-framed SHA-256, including every block header, full body, frontier, output, nullifier, fee and database identity.
2. A second process opens the database and calls the normal `Ledger.switch` with a replacement-block iterator. Once that iterator resumes after its first yield, the normal verifier has already checked the actual nonempty replacement block, its parent/anchor and effects and the SQLite writer has inserted it. The crash checkpoint confirms the new full body/tip inside the still-open transaction, an on-disk rollback journal, and a further genuine replacement block awaiting validation. The test lowers SQLite's cache size on this writer to encourage dirty-page spill.
3. The parent sends SIGKILL to that process while it is paused. No language-level cleanup or SQL rollback handler can run in the writer. A third process reopens the same DB with fresh public roles. It compares the old published state and all-table fingerprint, checks SQLite integrity and foreign keys, then retries the complete valid switch and compares the result to the alternate tip in the author trace.

## Lost acknowledgement after durable enqueue

A local Unix proxy forwards one real, genesis-anchored singleton to the preferred endpoint, receives its genuine 32-byte post-COMMIT acknowledgement, observes the durable preferred row through a separate SQLite connection and closes the payer connection without returning the acknowledgement. Unchanged `upload` retries the entire frame at the direct endpoint. Both full frame dispositions are counted, including the first failed delivery from the payer's perspective. The test checks that retry promotes the original row to direct without changing its sequence, first arrival, identity or bytes. It restarts both ingress endpoints, resubmits on a fresh direct process and admits exactly the original published singleton block through normal proof and state verification. It then uploads the same bytes after inclusion, verifies the spent-nullifier rejection and empty queue, and compares all ledger rows to the first-commit fingerprint.

These tests cover local process death and real post-commit acknowledgement loss on this SQLite/filesystem configuration. A machine-power cut, hostile disk firmware, remote-peer outage, cross-host replicated queue and bounded delivery under permanent partition require different evidence. The origin can observe an intake acknowledgement before final admission. A stale accepted packet may re-enter the queue transiently after inclusion; admission must recheck its nullifiers.

```sh
python3 -I -B experiments/advancing-payments/assurance/durability/check.py \
  --evidence "$public_author_trace_dir" --work "$new_temporary_work_dir" \
  --binary "$registered_binary" --binary-sha "$approved_binary_sha256" \
  --keys "$registered_keys" --profile-sha "$approved_profile_sha256" \
  --genesis-sha "$approved_genesis_sha256"
```

[Executable test](check.py) · [state transition implementation](../../state.py) · [ingress implementation](../../ingress.py)
