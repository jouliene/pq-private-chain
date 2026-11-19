use crate::{
    codec::{encode, read_frame, write_frame, Meter, CT},
    header, registry, words,
};
use anyhow::{ensure, Context, Result};
use blake2::{Blake2b512, Digest as _};
use qnero_circuit::chain::ct_digest;
use qnero_circuit::header::HeaderInputs;
use qnero_circuit::merkle::{empty_digest, CommitmentTree, MerklePath};
use qnero_circuit::witness::{InputNote, OutputNote, SpendWitness};
use qnero_notes::{
    encrypt_note, pad_memo, try_receive, Address, Digest, Note, NoteCiphertext, SpendingKey,
    MAX_VALUE,
};
use qnero_prover::WalletProver;
use rand::{Rng, RngCore};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

const FEE: u64 = 3;
const REWARD: usize = 104;
const RECEIPT: usize = 32 + CT;

pub fn reward_note(body: &[u8]) -> Result<Note> {
    ensure!(body.len() == 72, "reward preimage length");
    let pk = Digest::from_slice(&body[32..64])?;
    let value = u64::from_le_bytes(body[64..].try_into()?);
    ensure!(value > 0 && pk != empty_digest(), "invalid public reward");
    Ok(Note::new(
        pk,
        value,
        Digest::hash_bytes(&[b"PQDEV1/reward/rho", body]),
        Digest::hash_bytes(&[b"PQDEV1/reward/r", body]),
    )?)
}

fn seed(path: &Path, mode: &str) -> Result<SpendingKey> {
    if mode == "create" {
        let key = SpendingKey::random(&mut rand::rng());
        let temp = path.with_extension("creating");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        let result = (|| -> Result<()> {
            f.write_all(key.expose_bytes())?;
            f.sync_all()?;
            fs::hard_link(&temp, path)?;
            fs::File::open(path.parent().context("private directory")?)?.sync_all()?;
            Ok(())
        })();
        fs::remove_file(temp)?;
        result?;
        return Ok(key);
    }
    ensure!(mode == "restore", "wallet mode");
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.len() == 32 && m.permissions().mode() & 0o077 == 0,
        "private seed mode"
    );
    let mut seed = [0; 32];
    fs::File::open(path)?.read_exact(&mut seed)?;
    Ok(SpendingKey::take_from(&mut seed))
}

fn pages(r: &mut impl Read, stride: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    loop {
        let p = read_frame(r)?;
        if p.is_empty() {
            return Ok(data);
        }
        ensure!(
            p.len() <= 256 * 1024 && p.len() % stride == 0,
            "public page"
        );
        data.extend(p);
    }
}

// Only this wallet can label its change on restore. Bind the private memo to the output CM.
fn change_memo(key: &SpendingKey, cm: &Digest) -> Vec<u8> {
    let mut hash = Blake2b512::new();
    hash.update(b"PQDEV1/own-change");
    hash.update(key.expose_bytes());
    hash.update(cm.to_bytes());
    let mut memo = vec![0; 61];
    memo[..32].copy_from_slice(&hash.finalize()[..32]);
    memo
}
#[derive(Clone, Copy)]
enum Source {
    Reward = 1,
    Incoming = 2,
    Change = 3,
}
struct Owned {
    note: Note,
    pos: usize,
    kind: Source,
    spent: bool,
}
struct Selected {
    header: HeaderInputs,
    tree: Option<CommitmentTree>,
    owned: Vec<Owned>,
}
impl Selected {
    fn scan(
        key: &SpendingKey,
        h: &[u8],
        cms: &[u8],
        rewards: &[u8],
        rows: &[u8],
        nfs: &[u8],
    ) -> Result<Self> {
        let header = header(h)?;
        let leaves = words(cms)?;
        let tree = if leaves.is_empty() {
            None
        } else {
            Some(CommitmentTree::new(
                &leaves,
                CommitmentTree::depth_for(leaves.len())?,
            )?)
        };
        ensure!(
            tree.as_ref()
                .map(CommitmentTree::root)
                .unwrap_or_else(empty_digest)
                == header.zk_tree_root,
            "funded root mismatch"
        );
        let mut pending: HashMap<_, _> = leaves
            .iter()
            .copied()
            .enumerate()
            .map(|(i, w)| (w, i))
            .collect();
        ensure!(
            pending.len() == leaves.len() && !pending.contains_key(&empty_digest()),
            "invalid funded inventory"
        );
        let raw_nfs = words(nfs)?;
        let spent: HashSet<_> = raw_nfs.iter().collect();
        ensure!(spent.len() == raw_nfs.len(), "duplicate spent nullifier");
        let mut owned = Vec::new();
        let nk = key.nk();
        let mut keep = |note: Note, pos, kind| {
            let used = spent.contains(&note.nullifier(&nk));
            owned.push(Owned {
                note,
                pos,
                kind,
                spent: used,
            });
        };
        for row in rewards.chunks_exact(REWARD) {
            let n = reward_note(&row[..72])?;
            let cm = Digest::from_slice(&row[72..])?;
            ensure!(n.commitment() == cm, "reward commitment mismatch");
            let pos = pending.remove(&cm).context("reward inventory")?;
            if n.pk == key.pk() {
                keep(n, pos, Source::Reward);
            }
        }
        let ivk = key.incoming_viewing_key();
        for row in rows.chunks_exact(RECEIPT) {
            let cm = Digest::from_slice(&row[..32])?;
            let pos = pending.remove(&cm).context("receipt inventory")?;
            let ct = NoteCiphertext::from_bytes(&row[32..])?;
            if let Ok(hit) = try_receive(&ivk, &ct, &cm) {
                let kind = if hit.memo == change_memo(key, &cm) {
                    Source::Change
                } else {
                    Source::Incoming
                };
                keep(hit.note, pos, kind);
            }
        }
        ensure!(pending.is_empty(), "missing public history");
        owned.sort_unstable_by_key(|hit| hit.pos);
        Ok(Self {
            header,
            tree,
            owned,
        })
    }
    fn inventory(&self) -> Vec<u8> {
        let mut b = b"SCAN".to_vec();
        for o in &self.owned {
            b.extend(o.note.commitment().to_bytes());
            b.extend(o.note.value.to_le_bytes());
            b.extend([o.kind as u8, u8::from(o.spent)]);
        }
        b
    }
    fn select(&self, amount: u64) -> Result<Vec<&Owned>> {
        ensure!(amount > 0 && amount <= MAX_VALUE, "amount");
        let target = amount + FEE;
        let mut available: Vec<_> = self
            .owned
            .iter()
            .filter(|o| !o.spent && o.note.value > 0)
            .collect();
        available.sort_unstable_by_key(|o| (o.note.value, o.pos));
        if let Some(n) = available.iter().find(|n| n.note.value >= target) {
            return Ok(vec![*n]);
        }
        let mut lo = 0;
        let mut hi = available.len().saturating_sub(1);
        let mut best = None;
        while lo < hi {
            let sum = available[lo].note.value + available[hi].note.value;
            if sum < target {
                lo += 1;
                continue;
            }
            if sum - target <= MAX_VALUE && best.as_ref().map_or(true, |(prev, _, _)| sum < *prev) {
                best = Some((sum, lo, hi));
            }
            hi -= 1;
        }
        best.map(|(_, i, j)| vec![available[i], available[j]])
            .context("insufficient value within two inputs")
    }
    fn pay(
        &self,
        key: &SpendingKey,
        prover: &WalletProver,
        notes: &[&Owned],
        amount: u64,
        to: &Address,
    ) -> Result<Vec<u8>> {
        let tree = self.tree.as_ref().context("empty inventory")?;
        let proved = notes
            .iter()
            .map(|n| Ok((n.note.clone(), tree.path(n.pos)?)))
            .collect::<Result<Vec<_>>>()?;
        pay_with_paths(&self.header, key, prover, &proved, amount, to)
    }
}

fn pay_with_paths(
    anchor: &HeaderInputs,
    key: &SpendingKey,
    prover: &WalletProver,
    notes: &[(Note, MerklePath)],
    amount: u64,
    to: &Address,
) -> Result<Vec<u8>> {
    ensure!(
        (1..=2).contains(&notes.len()) && amount > 0 && amount <= MAX_VALUE,
        "positive amount and funding"
    );
    let depth = notes[0].1.depth();
    ensure!(
        depth > 0
            && notes.iter().all(|(n, p)| n.pk == key.pk()
                && n.value > 0
                && p.depth() == depth
                && p.root(n.commitment()).ok() == Some(anchor.zk_tree_root)),
        "invalid compact membership"
    );
    ensure!(
        notes.len() == 1 || notes[0].0.commitment() != notes[1].0.commitment(),
        "duplicate funding"
    );
    let total: u64 = notes.iter().map(|x| x.0.value).sum();
    ensure!(
        total >= amount + FEE && total - amount - FEE <= MAX_VALUE,
        "insufficient bounded funding"
    );
    let keys = key.derived();
    let mut rng = rand::rng();
    let real = |(n, p): &(Note, MerklePath)| InputNote::real(&keys, n, p.clone());
    let second = if notes.len() == 2 {
        real(&notes[1])?
    } else {
        InputNote::dummy_random(&mut rng, &keys, depth)
    };
    let own = key.address();
    let mut dest = [(to, amount, false), (&own, total - amount - FEE, true)];
    if rng.random::<bool>() {
        dest.swap(0, 1);
    }
    let mut random = || {
        let mut raw = [0u8; 32];
        rng.fill_bytes(&mut raw);
        raw
    };
    let mut witness = SpendWitness {
        header: anchor.clone(),
        depth,
        inputs: [real(&notes[0])?, second],
        outputs: dest.map(|(a, v, _)| {
            OutputNote::new(a.pk, v, Digest::hash_bytes(&[b"PQDEV1/output", &random()]))
        }),
        fee: FEE,
        ct_digest: empty_digest(),
    };
    let mut cts = Vec::new();
    for (i, (addr, _, change)) in dest.into_iter().enumerate() {
        let note = witness.output_note(i)?;
        let memo = if change {
            change_memo(key, &note.commitment())
        } else {
            pad_memo("")?
        };
        let ct = encrypt_note(&addr.ek, &note, &memo, &random())?.to_bytes();
        ensure!(ct.len() == CT, "receipt length");
        cts.extend(ct);
    }
    witness.ct_digest = Digest::from_bytes(&ct_digest(&[&cts[..CT], &cts[CT..]]))?;
    Ok(encode(1, &prover.prove_submission(vec![witness])?, &cts))
}

fn open_row(key: &SpendingKey, row: &[u8]) -> Result<Option<(Note, Source)>> {
    if row.len() == REWARD {
        let note = reward_note(&row[..72])?;
        ensure!(
            note.commitment() == Digest::from_slice(&row[72..])?,
            "reward opening"
        );
        return Ok((note.pk == key.pk()).then_some((note, Source::Reward)));
    }
    ensure!(row.len() == RECEIPT, "receipt length");
    let cm = Digest::from_slice(&row[..32])?;
    let ct = NoteCiphertext::from_bytes(&row[32..])?;
    Ok(try_receive(&key.incoming_viewing_key(), &ct, &cm)
        .ok()
        .map(|hit| {
            let kind = if hit.memo == change_memo(key, &cm) {
                Source::Change
            } else {
                Source::Incoming
            };
            (hit.note, kind)
        }))
}
fn ensure_prover<'a>(dir: &Path, prover: &'a mut Option<WalletProver>) -> Result<&'a WalletProver> {
    if prover.is_none() {
        let m = Meter::start();
        registry::compare(
            dir,
            0,
            &qnero_aggregator::artifacts::canonical_leaf_verifier_data(),
        )?;
        let p = WalletProver::new(1)?;
        registry::compare(dir, 1, &p.batch_verifier_data())?;
        *prover = Some(p);
        m.finish("wallet_prover_setup");
    }
    prover.as_ref().context("prover init")
}
fn compact(
    key: &SpendingKey,
    dir: &Path,
    prover: &mut Option<WalletProver>,
    raw: &[u8],
) -> Result<Vec<u8>> {
    ensure!(raw.len() >= 1742, "compact request");
    let anchor = header(&raw[..132])?;
    let amount = u64::from_le_bytes(raw[132..140].try_into()?);
    let to = Address::from_bytes(&raw[140..1741])?;
    let count = usize::from(raw[1741]);
    ensure!((1..=2).contains(&count), "input count");
    let mut rest = &raw[1742..];
    let mut notes = Vec::new();
    for _ in 0..count {
        ensure!(rest.len() >= 3, "compact framing");
        let size = u16::from_le_bytes(rest[..2].try_into()?) as usize;
        let depth = rest[2] as usize;
        ensure!(
            depth > 0 && depth <= 20 && rest.len() >= 3 + size + 96 * depth,
            "compact path length"
        );
        let (note, _) = open_row(key, &rest[3..3 + size])?.context("not owned")?;
        let rows = rest[3 + size..3 + size + 96 * depth]
            .chunks_exact(96)
            .map(|r| -> Result<_> {
                Ok([
                    Digest::from_slice(&r[..32])?,
                    Digest::from_slice(&r[32..64])?,
                    Digest::from_slice(&r[64..])?,
                ])
            })
            .collect::<Result<Vec<_>>>()?;
        let path = MerklePath::from_unsorted(&rows, note.commitment())?;
        ensure!(
            path.root(note.commitment())? == anchor.zk_tree_root,
            "compact funding root mismatch"
        );
        notes.push((note, path));
        rest = &rest[3 + size + 96 * depth..];
    }
    ensure!(rest.is_empty(), "trailing compact fields");
    let p = ensure_prover(dir, prover)?;
    let meter = Meter::start();
    let result = pay_with_paths(&anchor, key, p, &notes, amount, &to)?;
    meter.finish("compact_prove");
    Ok(result)
}

pub fn actor(
    dir: &Path,
    path: &Path,
    mode: &str,
    r: &mut impl Read,
    w: &mut impl Write,
) -> Result<()> {
    let meter = Meter::start();
    let key = seed(path, mode)?;
    write_frame(w, &key.address().to_bytes())?;
    meter.finish("wallet_open");
    let mut selected: Option<Selected> = None;
    let mut prover = None;
    loop {
        let cmd = read_frame(r)?;
        if cmd.is_empty() {
            return Ok(());
        }
        match cmd.first() {
            Some(b'D') => {
                let result = open_row(&key, &cmd[1..]);
                match result {
                    Ok(Some((n, kind))) => {
                        let mut b = b"HIT".to_vec();
                        b.extend(n.nullifier(&key.nk()).to_bytes());
                        b.extend(n.value.to_le_bytes());
                        b.push(kind as u8);
                        write_frame(w, &b)?;
                    }
                    Ok(None) => write_frame(w, b"MISS")?,
                    Err(_) => write_frame(w, b"invalid row")?,
                }
            }
            Some(b'K') => {
                let result = compact(&key, dir, &mut prover, &cmd[1..]);
                match result {
                    Ok(b) => write_frame(w, &b)?,
                    Err(_) => write_frame(w, b"invalid compact payment")?,
                }
            }
            Some(b'S') => {
                selected = None;
                let leaves = pages(r, 32)?;
                let rewards = pages(r, REWARD)?;
                let rows = pages(r, RECEIPT)?;
                let nfs = pages(r, 32)?;
                let m = Meter::start();
                match Selected::scan(&key, &cmd[1..], &leaves, &rewards, &rows, &nfs) {
                    Ok(s) => {
                        write_frame(w, &s.inventory())?;
                        selected = Some(s);
                        m.finish("wallet_scan");
                    }
                    Err(_) => {
                        write_frame(w, b"invalid selected history")?;
                        m.finish("wallet_rejected");
                    }
                }
            }
            Some(b'P') => {
                let addr = read_frame(r)?;
                let Some(s) = &selected else {
                    write_frame(w, b"scan selected history first")?;
                    continue;
                };
                let Ok(raw) = <&[u8; 8]>::try_from(&cmd[1..]) else {
                    write_frame(w, b"invalid amount")?;
                    continue;
                };
                let amount = u64::from_le_bytes(*raw);
                let Ok(to) = Address::from_bytes(&addr) else {
                    write_frame(w, b"invalid address")?;
                    continue;
                };
                if amount == 0 || amount > MAX_VALUE {
                    write_frame(w, b"invalid amount")?;
                    continue;
                }
                let Ok(notes) = s.select(amount) else {
                    write_frame(w, b"insufficient funds within two inputs")?;
                    continue;
                };
                ensure_prover(dir, &mut prover)?;
                let m = Meter::start();
                let result = s.pay(
                    &key,
                    prover.as_ref().context("wallet setup")?,
                    &notes,
                    amount,
                    &to,
                );
                match result {
                    Ok(packet) => {
                        // These accounting fields remain on the owner's private process pipe.
                        // Only the embedded canonical APV2 packet is submitted to the node.
                        let total: u64 = notes.iter().map(|owned| owned.note.value).sum();
                        let mut response = b"PAY1".to_vec();
                        response.extend(total.to_le_bytes());
                        response.push(notes.len() as u8);
                        response.extend(packet);
                        write_frame(w, &response)?;
                        m.finish("wallet_prove");
                    }
                    Err(_) => {
                        write_frame(w, b"proving failed")?;
                        m.finish("wallet_rejected");
                    }
                }
            }
            _ => write_frame(w, b"unknown wallet command")?,
        }
    }
}
