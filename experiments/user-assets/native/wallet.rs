use crate::{
    codec::{encode, read_frame, write_frame, Meter, CT},
    header,
    registry::{typed, WalletProver},
};
use anyhow::{ensure, Context, Result};
use qnero_circuit::{
    chain::ct_digest,
    header::HeaderInputs,
    merkle::{empty_digest, MerklePath},
    witness::{InputNote, OutputNote, SpendWitness},
};
use qnero_notes::{
    encrypt::{decrypt_token_pair, encrypt_token_pair},
    Address, Digest, Note, NoteCiphertext, SpendingKey, MAX_VALUE,
};
use rand::{Rng, RngCore};
use std::{
    io::{Read, Write},
    path::Path,
};
include!("seed.inc");

struct Pair {
    note: Note,
    token: u64,
    id: Digest,
    raw: Digest,
}
impl Pair {
    fn new(pk: Digest, native: u64, token: u64, id: Digest, rho: Digest, raw: Digest) -> Result<Self> {
        ensure!(token <= MAX_VALUE && (token == 0) == (id == empty_digest()), "asset opening");
        ensure!(id.to_bytes().chunks_exact(8).all(|limb| limb[7] < 128), "asset ID range");
        Ok(Self {
            note: Note::new(pk, native, rho, typed(id, token, raw))?,
            token,
            id,
            raw,
        })
    }
}
fn u64le(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(bytes.try_into()?))
}
fn endowment(body: &[u8]) -> Result<Pair> {
    ensure!(body.len() == 80, "endowment length");
    Pair::new(
        Digest::from_slice(&body[32..64])?,
        u64le(&body[64..72])?,
        u64le(&body[72..])?,
        empty_digest(),
        Digest::hash_bytes(&[b"AST1/reward/rho", body]),
        Digest::hash_bytes(&[b"AST1/reward/raw", body]),
    )
}
pub fn reward_note(body: &[u8]) -> Result<Note> {
    Ok(endowment(body)?.note)
}
fn pay(
    header: &HeaderInputs,
    choices: &[(MerklePath, Pair)],
    key: &SpendingKey,
    prover: &WalletProver,
    to: &Address,
    native: u64,
    token: u64,
    asset: Digest,
    supply: u64,
) -> Result<Vec<u8>> {
    let real = choices.len();
    ensure!(
        (native > 0 || token > 0)
            && native <= MAX_VALUE
            && token <= MAX_VALUE
            && (1..=2).contains(&real),
        "requested amounts"
    );

    let v: u64 = choices.iter().map(|(_, p)| p.note.value).sum();
    let t: u64 = choices.iter().map(|(_, p)| p.token).sum();
    ensure!(supply <= MAX_VALUE && (supply == 0 || (supply == token && t == 0)), "issuance");
    let available = t + supply;
    ensure!((available == 0) == (asset == empty_digest()), "asset presence");
    ensure!(choices.iter().all(|(_, p)| p.token == 0 || p.id == asset), "funding asset");
    ensure!(asset.to_bytes().chunks_exact(8).all(|limb| limb[7] < 128), "asset ID range");
    ensure!(
        v >= native + 3 && available >= token && v - native - 3 <= MAX_VALUE && available - token <= MAX_VALUE,
        "funding"
    );
    let mut rng = rand::rng();
    let shuffled = rng.random::<bool>();
    let mut random = || {
        let mut r = [0; 32];
        rng.fill_bytes(&mut r);
        r
    };
    let mut fresh = || Digest::hash_bytes(&[b"AST1/open", &random()]);
    let keys = key.derived();
    let path = choices[0].0.clone();
    let depth = path.depth();
    let first = InputNote::real(&keys, &choices[0].1.note, path)?;
    let (second, second_open) = if real == 2 {
        let (path, p) = &choices[1];
        (
            InputNote::real(&keys, &p.note, path.clone())?,
            (p.token, p.raw),
        )
    } else {
        let raw = fresh();
        (
            InputNote::dummy(&keys, fresh(), typed(empty_digest(), 0, raw), depth),
            (0, raw),
        )
    };
    let own = key.address();
    let mut outs = [
        (to, native, token, fresh(), false),
        (&own, v - native - 3, available - token, fresh(), true),
    ];
    if shuffled {
        outs.swap(0, 1);
    }
    let note_id = |qty| if qty == 0 { empty_digest() } else { asset };
    let mut w = SpendWitness {
        header: header.clone(),
        depth,
        inputs: [first, second],
        outputs: outs.map(|(a, v, t, r, _)| OutputNote::new(a.pk, v, typed(note_id(t), t, r))),
        fee: 3,
        ct_digest: empty_digest(),
    };
    let mut cts = Vec::new();
    for (i, (a, _, t, r, change)) in outs.iter().enumerate() {
        let note = w.output_note(i)?;
        let mut memo = vec![0; 61];
        memo[..32].copy_from_slice(&note_id(*t).to_bytes());
        if *change {
            memo[32..].copy_from_slice(&change_marker(key, &note.commitment()));
        }
        let ct = encrypt_token_pair(a, &note, *t, *r, &memo, &random())?.to_bytes();
        ensure!(ct.len() == CT, "receipt width");
        cts.extend(ct);
    }
    w.ct_digest = Digest::from_bytes(&ct_digest(&[&cts[..CT], &cts[CT..]]))?;
    let p = prover.prove(
        &w,
        [
            (choices[0].1.token, choices[0].1.raw),
            second_open,
            (outs[0].2, outs[0].3),
            (outs[1].2, outs[1].3),
        ],
        asset,
        supply,
    )?;
    Ok(encode(1, &p, &cts))
}

fn change_marker(key: &SpendingKey, cm: &Digest) -> [u8; 29] {
    use blake2::{Blake2b512, Digest as _};
    let mut h = Blake2b512::new();
    h.update(b"AST1/devnet/change");
    h.update(key.expose_bytes());
    h.update(cm.to_bytes());
    h.finalize()[..29].try_into().unwrap()
}
fn open(key: &SpendingKey, row: &[u8]) -> Result<Option<(Pair, u8)>> {
    if row.len() == 112 {
        let p = endowment(&row[..80])?;
        ensure!(
            p.note.commitment() == Digest::from_slice(&row[80..])?,
            "public note opening"
        );
        return Ok((p.note.pk == key.pk()).then_some((p, 1)));
    }
    ensure!(row.len() == 32 + CT, "receipt length");
    let cm = Digest::from_slice(&row[..32])?;
    let ct = NoteCiphertext::from_bytes(&row[32..])?;
    Ok(decrypt_token_pair(&key.incoming_viewing_key(), &ct)
        .ok()
        .and_then(|(v, t, rho, r, memo)| {
            if memo.len() != 61 {
                return None;
            }
            let id = Digest::from_slice(&memo[..32]).ok()?;
            let pair = Pair::new(key.pk(), v, t, id, rho, r).ok()?;
            (pair.note.commitment() == cm)
                .then(|| (pair, if memo[32..] == change_marker(key, &cm) { 3 } else { 2 }))
        }))
}
fn compact(
    key: &SpendingKey,
    dir: &Path,
    prover: &mut Option<WalletProver>,
    raw: &[u8],
) -> Result<Vec<u8>> {
    let mut cur = std::io::Cursor::new(raw);
    fn take<const N: usize>(c: &mut std::io::Cursor<&[u8]>) -> Result<[u8; N]> {
        let mut a = [0; N];
        c.read_exact(&mut a)?;
        Ok(a)
    }
    let h = header(&take::<132>(&mut cur)?)?;
    let native = u64::from_le_bytes(take(&mut cur)?);
    let token = u64::from_le_bytes(take(&mut cur)?);
    let asset = Digest::from_bytes(&take::<32>(&mut cur)?)?;
    let supply = u64::from_le_bytes(take(&mut cur)?);
    let to = Address::from_bytes(&take::<1601>(&mut cur)?)?;
    let count = take::<1>(&mut cur)?[0];
    ensure!((1..=2).contains(&count), "real input count");
    let mut inputs = Vec::new();
    for _ in 0..count {
        let size = u16::from_le_bytes(take(&mut cur)?) as usize;
        let depth = take::<1>(&mut cur)?[0];
        ensure!(
            (size == 112 || size == 32 + CT) && (1..=20).contains(&depth),
            "compact input"
        );
        let mut row = vec![0; size];
        cur.read_exact(&mut row)?;
        let (p, _) = open(key, &row)?.context("input opening")?;
        let cm = p.note.commitment();
        ensure!(p.note.value > 0 || p.token > 0, "empty input");
        let mut rows = Vec::new();
        for _ in 0..depth {
            rows.push([
                Digest::from_slice(&take::<32>(&mut cur)?)?,
                Digest::from_slice(&take::<32>(&mut cur)?)?,
                Digest::from_slice(&take::<32>(&mut cur)?)?,
            ]);
        }
        let path = MerklePath::from_unsorted(&rows, cm)?;
        ensure!(path.root(cm)? == h.zk_tree_root, "private funding root");
        ensure!(
            inputs
                .iter()
                .all(|(_, n): &(MerklePath, Pair)| n.note.commitment() != cm),
            "duplicate input"
        );
        inputs.push((path, p));
    }
    ensure!(cur.position() as usize == raw.len(), "trailing input");
    if prover.is_none() {
        let m = Meter::start();
        *prover = Some(WalletProver::new(dir)?);
        m.finish("wallet_setup");
    }
    let m = Meter::start();
    let packet = pay(
        &h,
        &inputs,
        key,
        prover.as_ref().unwrap(),
        &to,
        native,
        token,
        asset,
        supply,
    )?;
    m.finish("compact_prove");
    Ok(packet)
}
pub fn actor(
    dir: &Path,
    path: &Path,
    mode: &str,
    r: &mut impl Read,
    w: &mut impl Write,
) -> Result<()> {
    let key = seed(path, mode)?;
    write_frame(w, &key.address().to_bytes())?;
    let mut prover = None;
    loop {
        let cmd = read_frame(r)?;
        if cmd.is_empty() {
            return Ok(());
        }
        let result = match cmd[0] {
            b'D' => open(&key, &cmd[1..]).map(|hit| match hit {
                None => b"MISS".to_vec(),
                Some((p, k)) => {
                    let mut b = b"HIT".to_vec();
                    b.extend(p.note.nullifier(&key.nk()).to_bytes());
                    b.extend(p.note.value.to_le_bytes());
                    b.extend(p.token.to_le_bytes());
                    b.extend(p.id.to_bytes());
                    b.push(k);
                    b
                }
            }),
            b'K' => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                compact(&key, dir, &mut prover, &cmd[1..])
            }))
            .unwrap_or_else(|_| Err(anyhow::anyhow!("wallet rejected request"))),
            _ => Err(anyhow::anyhow!("unknown wallet request")),
        };
        write_frame(w, &result.unwrap_or_else(|_| vec![b'0']))?;
    }
}
