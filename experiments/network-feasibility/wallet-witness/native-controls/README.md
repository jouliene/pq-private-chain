# Native selective-frontier controls

Source-only Gate3 component until Root allocates/reviews a new helper build.
No new payment proof relation, hash, depth, field or security parameter. The
native child calls existing fixed CP03 LEAF4 and NODE5 framing under the supplied
chain; the wallet coordinator authenticates cursor/root/count against common
selected history and owns genesis/profile/inventory/revision capabilities.
Canonical helper state is not an authenticated user checkpoint/bootstrap.

One opcode6 child advances a whole block of0..256ordered funded leaves. The
private input contains only origin/CM, local16-byte discovery/forget tokens and
opaque bounded state; no wallet spending/receiving key or plaintext note enters
this helper. Witnesses are index-ascending, with40canonical siblings each. Old
opcodes1..5/caps remain unchanged. Invalid tree API/native/response input fails
HashCoreFailure, never a recipient miss or complete empty wallet.

## Fixed wire, all integers little endian

Outer request remains `CPCH0301`, opcode byte6, chain32 (41bytes).
Tree payload header24: `CPTRQ006`, version:u16=1, K:u16=1..64,
state_bytes:u32, forget_count:u16<=64, leaf_count:u16<=256, reserved:u32=0.
Follow with state (zero bytes means new genesis), strictly lex-sorted unique
forget tokens16, then152-byte leaves: origin64,CM64,ownedflag:u8=0/1,
reserved7zero,token16 (allzero if unowned). Discovery tokens are unique and
cannot alias any pre-call live target, including a token forgotten in that call.
A bounded stateless helper cannot remember all forgotten historical tokens;
coordinator ownership/revision discipline prevents reuse of old authority.

State header64: `CPTRST06`, version:u16=1,depth:u16=40,chain32,K:u16,
live_targets:u16,forest_count:u8,reserved7zero,count:u64<=2^40.
The canonical prefix forest has at most40records of80bytes:
start:u64,level:u8,reserved7zero,digest64. Its levels/starts must exactly match
the set bits of count in descending order and cover[0,count). Count2^40 is one
level40root; node hashes themselves only use levels0..39.
Targets are increasing-index records: token16,index:u64,stored leaf digest64,
completed-mask:u64, followed only by the present64-byte siblings in level order.
A mask bit is present iff its sibling subtree's end<=count. Tokens and indices
are unique; indices<count. All field limbs must be<P. Wanted positions are
rederived, not serialized. Prior and resulting paths must fold from stored leaf
identity to the computed root. Padding modifies a private clone only; the live
serialized mask/forest never contain temporary padded right siblings.

Reply header92: `CPTRP006`,version:u16=1,K:u16,count:u64,root64,
state_bytes:u32,witness_count:u16,reserved:u16=0. Follow with state and index-
ascending2584-byte witnesses(token16,index:u64,siblings40×64). Exact lengths,
EOF, reserved bytes, fields, state shape, token/index/count alignment and caps
are checked before an owned output result is returned.

Conservative exact caps: state173248B =64+40×80+64×(96+40×64);
whole request213249B =41+24+173248+64×16+256×152;
reply338716B =92+173248+64×2584. Each is below1MiB. Legacy request135723B
and reply82434B stay exact. maxBuffer is capped at the respective reply+1.
Native stdin chooses the fixed cap from the validated opcode prefix.

## Boundaries to verify after allocation

Rust public controls use a small full-tree oracle only in tests, compare current
roots/paths, and include count1 target0→append leaf1 (the padded-sibling trap),
forget, caps, duplicate/unknown tokens, canonical geometry/presence masks,
noncanonical fields, corrupted stored leaf/path, crosschain/K, trailing input,
empty/genesis and structural full-capacity shape. No all-history vector exists
in the runtime builder. A structural synthetic count2^40 fixture is not an
executed trillion-leaf replay.

The JS production parser is shared with public parser controls; it supplies no
branded wallet authority. The wrapper executes the held FD after pre/post SHA256
checks, copies owned return buffers, and best-effort clears request, payload,
state/token input copies, transient stdout/stderr and partial output copies.
Native input/output/state copies are likewise cleared best effort. This is not
a guaranteed compiler/allocator erasure boundary. No state/token/path bytes or
digests, wallet selection, private request/response streams or raw diagnostics
may enter evidence. Controls emit only fixed typed counts/pass/failure labels.

Root owns source manifests, new helper/ELF/installation approvals and heavy
allocations. Source syntax inspection is not a native control PASS. After review,
a new source-root installation and helper SHA are required; never relabel the old
five-opcode helper as supporting opcode6 or weaken program/runtime verification.
