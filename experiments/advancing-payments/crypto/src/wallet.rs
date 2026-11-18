use crate::{
    codec::{encode, read_frame, write_frame, Meter, CT},
    header, registry, words,
};
use anyhow::{anyhow, ensure, Context, Result};
use qnero_circuit::chain::ct_digest;
use qnero_circuit::merkle::CommitmentTree;
use qnero_circuit::witness::{InputNote, OutputNote, SpendWitness};
use qnero_notes::{
    encrypt_note, pad_memo, try_receive, Address, Digest, Note, NoteCiphertext, SpendingKey,
};
use qnero_prover::WalletProver;
use rand::{Rng, RngCore};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

/// Pages contain only whole public records; an empty frame ends each stream.
fn read_pages(r: &mut impl Read, stride: usize) -> Result<Vec<u8>> {
    let mut records = Vec::new();
    loop {
        let page = read_frame(r)?;
        if page.is_empty() {
            return Ok(records);
        }
        ensure!(
            page.len() <= 256 * 1024 && page.len() % stride == 0,
            "public history page"
        );
        records.extend_from_slice(&page);
    }
}

struct Wallet {
    key: SpendingKey,
    genesis: Vec<Note>,
    received: Vec<Note>,
    prover: WalletProver,
}

fn backup(path: &Path, mode: &str) -> Result<SpendingKey> {
    if mode == "create" {
        let key = SpendingKey::random(&mut rand::rng());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(key.expose_bytes())?;
        file.sync_all()?;
        return Ok(key);
    }
    ensure!(mode == "restore", "wallet mode");
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_file() && info.len() == 32 && info.permissions().mode() & 0o077 == 0,
        "private backup permissions/length"
    );
    let mut seed = [0u8; 32];
    fs::File::open(path)?.read_exact(&mut seed)?;
    Ok(SpendingKey::take_from(&mut seed))
}
impl Wallet {
    fn scan(&mut self, rows: &[u8], spent: &[u8]) -> Result<u32> {
        ensure!(rows.len() % (32 + CT) == 0, "history rows");
        let spent: HashSet<_> = words(spent)?.into_iter().map(|d| d.to_bytes()).collect();
        let ivk = self.key.incoming_viewing_key();
        let nk = self.key.nk();
        let mut seen = HashSet::new();
        let mut notes = Vec::new();
        for row in rows.chunks_exact(32 + CT) {
            let cm = Digest::from_slice(&row[..32])?;
            ensure!(
                seen.insert(cm.to_bytes()),
                "duplicate receipt in supplied history"
            );
            let ct = NoteCiphertext::from_bytes(&row[32..])?;
            if let Ok(hit) = try_receive(&ivk, &ct, &cm) {
                if !spent.contains(&hit.note.nullifier(&nk).to_bytes()) {
                    notes.push(hit.note);
                }
            }
        }
        self.received = notes;
        Ok(u32::try_from(self.received.len())?)
    }
    fn pay(&self, sel: u16, h: &[u8], raw_leaves: &[u8], addr: &[u8]) -> Result<Vec<u8>> {
        let anchor = header(h)?;
        let leaves = words(raw_leaves)?;
        let tree = CommitmentTree::new(&leaves, CommitmentTree::depth_for(leaves.len())?)?;
        ensure!(
            tree.root() == anchor.zk_tree_root,
            "wallet funded root mismatch"
        );
        let to = Address::from_bytes(addr)?;
        let notes = if sel == u16::MAX {
            self.received.get(..2)
        } else {
            let i = 2 * usize::from(sel);
            self.genesis.get(i..i + 2)
        }
        .context("two selected local notes")?;
        let keys = self.key.derived();
        let input = |note: &Note| -> Result<InputNote> {
            let i = leaves
                .iter()
                .position(|cm| *cm == note.commitment())
                .context("absent funding")?;
            InputNote::real(&keys, note, tree.path(i)?)
        };
        let total = notes[0]
            .value
            .checked_add(notes[1].value)
            .context("total")?;
        let fee = 3;
        let amount = total / 2;
        let change = total.checked_sub(amount + fee).context("unfunded fee")?;
        ensure!(amount > 0 && change > 0, "two positive outputs");
        let own = self.key.address();
        let mut rng = rand::rng();
        let mut dest = [(&to, amount), (&own, change)];
        if rng.random::<bool>() {
            dest.swap(0, 1);
        }
        let mut random = || {
            let mut raw = [0; 32];
            rng.fill_bytes(&mut raw);
            raw
        };
        let mut witness = SpendWitness {
            header: anchor,
            depth: tree.depth(),
            inputs: [input(&notes[0])?, input(&notes[1])?],
            outputs: dest.map(|(a, v)| {
                OutputNote::new(
                    a.pk,
                    v,
                    Digest::hash_bytes(&[b"pq-private-chain/APV2/output", &random()]),
                )
            }),
            fee,
            ct_digest: Digest::from_bytes(&[0; 32])?,
        };
        let mut cts = Vec::new();
        for (i, (addr, _)) in dest.iter().enumerate() {
            let ct = encrypt_note(
                &addr.ek,
                &witness.output_note(i)?,
                &pad_memo("")?,
                &random(),
            )?
            .to_bytes();
            ensure!(ct.len() == CT, "receipt length");
            cts.extend(ct);
        }
        witness.ct_digest = Digest::from_bytes(&ct_digest(&[&cts[..CT], &cts[CT..]]))?;
        let proof = self.prover.prove_submission(vec![witness])?;
        Ok(encode(1, &proof, &cts))
    }
}

pub fn actor(
    dir: &Path,
    path: &Path,
    mode: &str,
    r: &mut impl Read,
    w: &mut impl Write,
) -> Result<()> {
    let meter = Meter::start();
    let key = backup(path, mode)?;
    let mut genesis = Vec::new();
    if mode == "create" {
        for _ in 0..12 {
            for value in [40, 60] {
                genesis.push(Note::random(&mut rand::rng(), key.pk(), value)?);
            }
        }
    }
    let leaf = qnero_aggregator::artifacts::canonical_leaf_verifier_data();
    registry::compare(dir, 0, &leaf)?;
    let prover = WalletProver::new(1)?;
    registry::compare(dir, 1, &prover.batch_verifier_data())?;
    let mut wallet = Wallet {
        key,
        prover,
        genesis,
        received: Vec::new(),
    };
    meter.finish("wallet_setup");
    write_frame(w, &wallet.key.address().to_bytes())?;
    let cms = wallet
        .genesis
        .iter()
        .flat_map(|note| note.commitment().to_bytes())
        .collect::<Vec<_>>();
    write_frame(w, &cms)?;
    loop {
        let command = read_frame(r)?;
        if command.is_empty() {
            return Ok(());
        }
        match command.first() {
            Some(b'P') => {
                let leaves = read_pages(r, 32)?;
                let addr = read_frame(r)?;
                let meter = Meter::start();
                let result = (|| -> Result<Vec<u8>> {
                    ensure!(command.len() == 135, "wallet pay command");
                    wallet.pay(
                        u16::from_le_bytes(command[1..3].try_into()?),
                        &command[3..],
                        &leaves,
                        &addr,
                    )
                })();
                meter.finish(if result.is_ok() {
                    "wallet_prove"
                } else {
                    "wallet_rejected"
                });
                write_frame(w, &result.unwrap_or_else(|_| vec![b'0']))?;
            }
            Some(b'S') => {
                let rows = read_pages(r, 32 + CT)?;
                let spent = read_pages(r, 32)?;
                let meter = Meter::start();
                let result = if command.len() == 1 {
                    wallet.scan(&rows, &spent)
                } else {
                    Err(anyhow!("scan command"))
                };
                meter.finish(if result.is_ok() {
                    "wallet_scan"
                } else {
                    "wallet_rejected"
                });
                match result {
                    Ok(n) => write_frame(w, &n.to_le_bytes())?,
                    Err(_) => write_frame(w, b"0")?,
                }
            }
            _ => write_frame(w, b"0")?,
        }
    }
}
