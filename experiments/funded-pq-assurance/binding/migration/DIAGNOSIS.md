# Diagnosed pre-build bridge failure

The first draft was stopped before any proof was generated. It proposed using
the public nullifiers from the historical C packet that **created** the notes
being migrated. Those nullifiers belong to that packet's inputs, not to its
outputs. Treating them as output-note identities would neither consume the
selected notes nor establish their ownership, and could collide with already
spent unrelated inputs. The only heavy attempt reached Rust compilation and
failed before linking on three local source errors (21.96 s wall, 411,616 KiB
maximum RSS); it did not generate a verifier key or proof.

The replacement is a two-proof composition. A fresh MNG3 packet is generated
specifically for migration. Its inputs are the funded C notes. The wallet
derives `ask` and `nk` from its seed and supplies them only as private witness
values; the C circuit does not receive or derive the seed. The circuit
constrains `ask -> ak -> pk` and `NF(nk, rho, typed opening)`, recomputes each
input commitment and proves exact-depth membership at the selected eligible
anchor. Therefore
that fresh packet's public input nullifiers are the identities the bridge must
consume. Its two C outputs are transient conservation witnesses. The equality
proof opens those outputs and maps their values to N7 outputs; the node never
inserts the transient C commitments.

Reusing the historical creator packet is an experiment-invalid condition and
must be a hard harness failure. The genuine run must replay/fork through the
funding height, ask the restored owner wallet for a new migration packet at
the next eligible candidate height, and admit that packet only inside the
atomic bridge bundle.
