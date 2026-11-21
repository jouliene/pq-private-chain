# Independent archive recovery checks

The public reader starts from the registered A/B network and reconstructs each
PoW branch from its original bytes. It checks the managed proof for each transfer,
both proofs and approvals for each swap, issuer authorizations, height eligibility,
current nullifiers, branch roots, supply revisions and per-miner fee credits. It
uses the earlier independent funded-proof decoder and reference root and reward
helpers. It does not import the new pruned state transition or trust the
controller's reported tip. The highest verified work wins, with the lower tip ID
breaking equal-work ties. The separately disclosed fixture amounts permit a
per-participant arithmetic check on each branch. Private transfer amounts are
not decoded by the public reader.

For a stopped home store, `replay.py` compares the selected-height index, note
commitments, receipt ciphertexts, reward openings, asset revisions, spent set,
transaction locations and swap group locations against the independently rebuilt
state. It re-encodes and compares the complete compact row for every selected
height. It compares the last three raw bodies against their originals and
checks that every earlier body column is empty. It searches every regular file
inside this fixture's home role, including SQLite storage, for a 96-byte interior
fragment of each discarded proof-bearing frame. This finite check detects raw
copies in the observed installation. It does not model remanence outside the
role directory, such as host backups or storage-device snapshots.

The separate `seed_check.py` mounts one backup into a new registered wallet
role and scans the winning branch. It checks the two positive A/B receipts,
the nullifiers derived under that single backup, their joint appearance in the
accepted B payment, the change and a subsequent selected block. Only disclosed
fixture totals leave the checker. The public replay receives no seed argument.

`peers.py` reads the private archive-side traces and compares actual inbound
request fields, framing lengths, returned body sizes and per-phase block
identifiers with the captured branches. Both peers must refuse the H12 block,
and the second must subsequently serve it. It reports aggregate observations.
The measured interface exposes source address, queried public ranges, block
identifiers and timing to archives. A loopback test cannot establish network
anonymity or independent administrative ownership of the peers.

Source review identified the baseline equal-work tie rule, persistent native
verifier lifetime, honest incomplete status after a higher archive disappears,
and the duplicate long-lived receipt index as necessary review points. The
current node serializes proof operations in one persistent worker. SQLite
triggers bind its local checksum update to the same transaction as the changed
rows. Reopen checks recompute the stored checksum. This provides a local
integrity check under the operator's storage trust assumption. A peer advertising
unavailable higher work can still delay automatic readiness. Authorizations,
ciphertexts, transport privacy and formal quantum assumptions retain the
funded protocol's previous assurance boundaries.
