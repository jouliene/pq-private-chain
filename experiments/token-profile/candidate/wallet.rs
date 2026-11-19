use crate::{
    codec::{encode, read_frame, write_frame, Meter, CT},
    header,
    registry::{typed, WalletProver},
    words,
};
use anyhow::{ensure, Context, Result};
use qnero_circuit::{
    chain::ct_digest,
    header::HeaderInputs,
    merkle::{empty_digest, CommitmentTree},
    witness::{InputNote, OutputNote, SpendWitness},
};
use qnero_notes::{
    encrypt::{decrypt_token_pair, encrypt_token_pair},
    pad_memo, Address, Digest, Note, NoteCiphertext, SpendingKey, MAX_VALUE,
};
use rand::{Rng, RngCore};
use std::{
    collections::HashSet,
    io::{Read, Write},
    path::Path,
};
include!("seed.inc");

struct Pair {
    note: Note,
    token: u64,
    raw: Digest,
}
impl Pair {
    fn new(pk: Digest, native: u64, token: u64, rho: Digest, raw: Digest) -> Result<Self> {
        ensure!(token <= MAX_VALUE, "token range");
        Ok(Self {
            note: Note::new(pk, native, rho, typed(token, raw))?,
            token,
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
        Digest::hash_bytes(&[b"TKN1/genesis/rho", body]),
        Digest::hash_bytes(&[b"TKN1/genesis/raw", body]),
    )
}
pub fn reward_note(body: &[u8]) -> Result<Note> {
    Ok(endowment(body)?.note)
}
struct Scan {
    header: HeaderInputs,
    tree: CommitmentTree,
    available: Vec<(usize, Pair)>,
}
fn scan(key: &SpendingKey, h: &[u8], gen: &[u8], rows: &[u8], nfs: &[u8]) -> Result<Scan> {
    ensure!(
        gen.len() % 112 == 0 && rows.len() % (32 + CT) == 0,
        "scan alignment"
    );
    let h = header(h)?;
    let spent: HashSet<_> = words(nfs)?.into_iter().collect();
    let mut cms = Vec::new();
    let mut available = Vec::new();
    let mut record = |cm: Digest, pair: Option<Pair>| {
        if let Some(p) = pair {
            ensure!(p.note.commitment() == cm, "typed opening mismatch");
            if p.note.pk == key.pk() && !spent.contains(&p.note.nullifier(&key.nk())) {
                available.push((cms.len(), p));
            }
        }
        cms.push(cm);
        Ok::<_, anyhow::Error>(())
    };
    for row in gen.chunks_exact(112) {
        record(
            Digest::from_slice(&row[80..])?,
            Some(endowment(&row[..80])?),
        )?;
    }
    let ivk = key.incoming_viewing_key();
    for row in rows.chunks_exact(32 + CT) {
        let ct = NoteCiphertext::from_bytes(&row[32..])?;
        let cm = Digest::from_slice(&row[..32])?;
        // Authenticated history advances even when this individual receipt cannot be opened.
        let received = decrypt_token_pair(&ivk, &ct)
            .ok()
            .and_then(|(v, t, rho, r, _)| Pair::new(key.pk(), v, t, rho, r).ok())
            .filter(|p| p.note.commitment() == cm);
        record(cm, received)?;
    }
    let tree = CommitmentTree::new(&cms, CommitmentTree::depth_for(cms.len())?)?;
    ensure!(tree.root() == h.zk_tree_root, "scan anchor");
    Ok(Scan {
        header: h,
        tree,
        available,
    })
}
fn pay(
    s: &Scan,
    key: &SpendingKey,
    prover: &WalletProver,
    to: &Address,
    native: u64,
    token: u64,
    real: usize,
    control: bool,
) -> Result<Vec<u8>> {
    ensure!(
        (native > 0 || token > 0)
            && native <= MAX_VALUE
            && token <= MAX_VALUE
            && (1..=2).contains(&real),
        "requested amounts"
    );
    let choices = &s.available.get(..real).context("spendable inputs")?;
    let v: u64 = choices.iter().map(|(_, p)| p.note.value).sum();
    let t: u64 = choices.iter().map(|(_, p)| p.token).sum();
    ensure!(
        v >= native + 3 && t >= token && v - native - 3 <= MAX_VALUE && t - token <= MAX_VALUE,
        "funding"
    );
    let mut rng = rand::rng();
    let shuffled = rng.random::<bool>();
    let mut random = || {
        let mut r = [0; 32];
        rng.fill_bytes(&mut r);
        r
    };
    let mut fresh = || Digest::hash_bytes(&[b"TKN1/open", &random()]);
    let keys = key.derived();
    let path = s.tree.path(choices[0].0)?;
    let depth = path.depth();
    let first = InputNote::real(&keys, &choices[0].1.note, path)?;
    let (second, second_open) = if real == 2 {
        let (i, p) = &choices[1];
        (
            InputNote::real(&keys, &p.note, s.tree.path(*i)?)?,
            (p.token, p.raw),
        )
    } else {
        let raw = fresh();
        (
            InputNote::dummy(&keys, fresh(), typed(0, raw), depth),
            (0, raw),
        )
    };
    let own = key.address();
    let mut outs = [
        (to, native, token, fresh()),
        (
            &own,
            v - native - 3,
            t - token + u64::from(control),
            fresh(),
        ),
    ];
    if shuffled {
        outs.swap(0, 1);
    }
    let mut w = SpendWitness {
        header: s.header.clone(),
        depth,
        inputs: [first, second],
        outputs: outs.map(|(a, v, t, r)| OutputNote::new(a.pk, v, typed(t, r))),
        fee: 3,
        ct_digest: empty_digest(),
    };
    let mut cts = Vec::new();
    for (i, (a, _, t, r)) in outs.iter().enumerate() {
        let note = w.output_note(i)?;
        let ct = encrypt_token_pair(a, &note, *t, *r, &pad_memo("")?, &random())?.to_bytes();
        ensure!(ct.len() == CT, "receipt width");
        cts.extend(ct);
    }
    w.ct_digest = Digest::from_bytes(&ct_digest(&[&cts[..CT], &cts[CT..]]))?;
    // Control alters the token output itself before both CM and honest encryption. Native conservation
    // and the four typed openings agree. Only the new token conservation equation is unsatisfied.
    let p = prover.prove(
        &w,
        [
            (choices[0].1.token, choices[0].1.raw),
            second_open,
            (outs[0].2, outs[0].3),
            (outs[1].2, outs[1].3),
        ],
    )?;
    Ok(encode(1, &p, &cts))
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
    let mut state = None;
    let mut prover = None;
    loop {
        let cmd = read_frame(r)?;
        if cmd.is_empty() {
            return Ok(());
        }
        let reply = match cmd.first() {
            Some(b'S') if cmd.len() == 1 => {
                let meter = Meter::start();
                let s = scan(
                    &key,
                    &read_frame(r)?,
                    &read_frame(r)?,
                    &read_frame(r)?,
                    &read_frame(r)?,
                )?;
                let mut out = b"SCAN".to_vec();
                for (i, p) in &s.available {
                    out.extend((*i as u32).to_le_bytes());
                    out.extend(p.note.value.to_le_bytes());
                    out.extend(p.token.to_le_bytes());
                }
                state = Some(s);
                meter.finish("scan");
                out
            }
            Some(b'P' | b'T') if cmd.len() == 1619 => {
                if prover.is_none() {
                    let m = Meter::start();
                    prover = Some(WalletProver::new(dir)?);
                    m.finish("wallet_setup");
                }
                let m = Meter::start();
                let control = cmd[0] == b'T';
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    pay(
                        state.as_ref().context("scan first")?,
                        &key,
                        prover.as_ref().unwrap(),
                        &Address::from_bytes(&cmd[18..])?,
                        u64le(&cmd[2..10])?,
                        u64le(&cmd[10..18])?,
                        cmd[1] as usize,
                        control,
                    )
                }));
                match result {
                    Ok(Ok(packet)) => {
                        m.finish("prove");
                        packet
                    }
                    _ => {
                        m.finish("refused");
                        b"0".to_vec()
                    }
                }
            }
            _ => b"0".to_vec(),
        };
        write_frame(w, &reply)?;
    }
}
