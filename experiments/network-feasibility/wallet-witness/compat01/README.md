# Network04 wallet compatibility boundary

The three canonical wallet files are owned here only for the coupled Network04
genesis/CLI/reduced-history compatibility required by Gate1. This does not
integrate the selective witness prototype or close Gate3. Original and successor
bytes are preserved under `preimages/` and `postimages/`; SOURCE01 approval is
`d18d70a6a41a1e2a9dfc91e74faa6d3d069a873e0ca15bc31a153f41be04db81`.

- `encodeGenesis({...version:4})` permits1..128 sorted unique sources; omitted
  version remains3 with the old1..16 bound. Statements, bodies, proof parameters
  and fees retain their exact old bytes.
- `preparePublicLedger({...blockVersion:4,retention:'retain'})` uses `init-retain`,
  accepts0..128 body paths, requires the CLI's explicit `block_version:'4'` head
  marker and returns `blockVersion:4`. Defaults remain legacy3/archive; legacy
  head JSON/object shape is unchanged. `check-scan` JSON retains its old shape;
  the native parser independently derives/binds the actual genesis version.
- `recoverHistory(wallet,scan,endpoint,basis,{genesis,genesisRoot})` requires both
  public genesis bytes and the independently trusted initial root for version4.
  `endpoint.blockVersion` is numeric4; omission defaults3. Genesis hash/chain/
  version, source ordering/count/total and field encodings are checked. The wallet
  still delegates proof validity, consensus/freshness and availability.
- Version4 reduced frames use the exact8408-byte header cap and1224804-byte raw
  scan-block cap (plus4outer framing bytes). Declared complete size is recomputed
  as228+68n+sum(prefix bytes+declared proof bytes), bounded by256MiB. Empty frames
  preserve root/count/fees/liabilities, including initial genesis liability.
  Windows are bounded independently by256payments and256blocks. Empty-only and
  trailing windows advance the cursor without recipient preparation, statement
  helper contexts or candidate collection. Legacy receiving remains eager.

Compatibility nuance accepted by Root: the **private recovered view's** endpoint
now also carries numeric `blockVersion:3` by default. It is internal metadata,
not a wire-byte/default change; this unused optional field is intentionally not
stripped merely to preserve its former private object key set. Version3 four-arg
callers continue to work. Actual complete recovery/producer evidence must come
from the newly reviewed installation, not from these source statements.

Actual source checks: all three Node syntax checks passed. Public codec controls
reproduced the old genesis and four old statement/body vectors byte for byte,
encoded128sources into339320bytes, and rejected five invalid variants. No private
key, new proof or admission was used in those checks. Independent review gave
source GO; the combined core build and genuine diagnostic producer remain Root's
separate runtime gates. These controls do not demonstrate large-block resource
viability or the real Gate3 expiry/reorg/backup acceptance sequence.
