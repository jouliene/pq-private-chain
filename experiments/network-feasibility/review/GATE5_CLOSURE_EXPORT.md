# Finite full01 public closure export

Status: construction only; independent full01 acceptance review remains separate.
The exporter reads the exact public RESULT, genesis and 264 named public bodies,
then computes one external canonical SQL reference. It copies no DB, receiver
inventory, destination descriptor, backup, key, raw Parent/wallet stream or
standalone duplicate proof. The source DB is read only by the external oracle;
its snapshot is comparison-only and cannot seed the fresh replay.

The exact construction command (one sequential body copy/hash pass, no native
or cryptographic verification) is:

```sh
python3 -I - <<'PY'
from pathlib import Path
import hashlib, importlib.util, json, os, time
repository = Path('/home/neo/jouliene/pq-private-chain')
base = repository / 'experiments/network-feasibility/wallet-integration'
origin = base / '.work/wallet-full01'
destination = base / '.work/full01-public-closure'
expected_result = '2835c26138b20e75716b6ce048e55731b41001b38f2a2dfdf7768a2b55068637'
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
assert digest(origin/'RESULT.json') == expected_result
result = json.loads((origin/'RESULT.json').read_bytes())
assert result['passed'] and result['source_runtime_unchanged']
assert result['all_generated_proofs_positive_native_admission']
assert not result['private_raw_streams_or_backup_persisted_or_hashed']
driver = base/'public_replay.py'
oracle_path = base.parent/'transport/oracle.py'
assert digest(driver) == 'ca27d58994db90607d757ed6ae1c2fb3473997594456c271c93a5cf97b6f810f'
assert digest(oracle_path) == '9c122418ba87f00be44ed518ef9c8c4d984166397f6a4408e0f10771ad4a439c'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value
replay=load('fixed_public_export',driver)
oracle=load('fixed_public_export_oracle',oracle_path)
rows={row['label']:row for row in result['proofs']}
assert len(result['proofs']) == len(rows) == 264 and set(rows) == set(replay.LABELS)
assert all(row['positive_admissions'] >= 1 for row in rows.values())
assert not destination.exists()
destination.mkdir();(destination/'bodies').mkdir()
public=origin/'public-output'
genesis={'path':'genesis.bin','bytes':(public/'genesis.bin').stat().st_size,
         'sha256':digest(public/'genesis.bin')}
replay.copy_public(replay.artifact(public,genesis,339320),destination/'genesis.bin',genesis)
bodies={}
for label in replay.LABELS:
    row=rows[label]
    assert row['body'] == 'public-output/'+label+'.body'
    assert row['arity'] == replay.label_arity(label)
    entry={'path':label+'.body','bytes':row['body_bytes'],'sha256':row['body_sha256']}
    replay.copy_public(replay.artifact(public,entry,2106575),
                       destination/'bodies'/(label+'.body'),entry)
    bodies[label]={**entry,'path':'bodies/'+label+'.body'}
canonical=oracle.snapshot(origin/'controller/ledger.sqlite',canonical=True)
replay.validate_reference(canonical)
assert all(canonical[name] == result['final_all14_snapshot'][name]
           for name in canonical if name != 'body_cache')
assert canonical['bodies']['rows'] == canonical['cores']['rows'] == 261
assert canonical['blocks']['rows'] == 260 and canonical['leaves']['rows'] == 522
assert canonical['nullifiers']['rows'] == 516 and canonical['sources']['rows'] == 2
manifest={'format':'CP04-WALLET-FULL-PUBLIC-CLOSURE01',
          'chain':result['head']['chain'],'genesis':genesis,'bodies':bodies,
          'final_head':result['head'],'final_canonical_snapshot':canonical}
manifest_path=destination/'closure.json'
replay.save(manifest_path,manifest)
print(json.dumps({'manifest':str(manifest_path),'manifest_sha256':digest(manifest_path),
                  'complete_bodies':len(bodies),'body_bytes':sum(e['bytes'] for e in bodies.values()),
                  'genesis_bytes':genesis['bytes'],'manifest_bytes':manifest_path.stat().st_size,
                  'canonical_tables':len(canonical),'reference_scope':'comparison only; source DB not copied',
                  'independent_full_review':'pending; export is not acceptance'},sort_keys=True))
PY
```

The destination is exclusive. Any failure/partial output must be retained; no
unchanged overwrite or regeneration is authorized by this command. Runtime/source
pins and original artifacts are not modified. Only body label/path/size/hash
allowlisted by the actual result can enter the closure. `canonical=True` excludes
only `body_cache.catalog_id`; all other columns remain compared. The reference
map and original RESULT never authorize proof acceptance in the fresh verifier.

Actual command status: exit0. `closure.json` SHA256 is
`6ee13309b7c0d5fafb6363787076a86be0334799c850e670147571903cbae094`.
It binds264 complete bodies (462,275,126 bytes), genesis (5,672 bytes), the actual
height260/522-leaf/551,305,634-fee head and14 canonical table references. Manifest
size is49,348 bytes; total copied closure bytes including it are462,330,146.
Independent full01 review was pending at export; this receipt is construction,
not acceptance or a fresh cryptographic replay result.
