// This isolated wallet-only example writes one bounded assignment into a caller-mounted private kernel FIFO.
fn capture(
    w: &SpendWitness, opened: [(u64,Digest);4], id: Digest, delta: u64, key: &[u32], proof: &Proof,
) -> Result<()> {
    use std::io::Write;
    use plonky2::field::types::PrimeField64;
    let mut dst = std::fs::OpenOptions::new().write(true).open("/assignment")?;
    dst.write_all(b"FWIT01")?;
    let put = |out: &mut std::fs::File, x: u64| out.write_all(&x.to_le_bytes());
    let header = w.header.preimage();
    put(&mut dst,header.len() as u64)?;
    for f in header { put(&mut dst,f.to_canonical_u64())?; }
    put(&mut dst,w.depth as u64)?;
    for (i,n) in w.inputs.iter().enumerate() {
        for d in [n.ask.expose_digest(),n.nk.expose_digest(),n.rho,opened[i].1] { dst.write_all(&d.to_bytes())?; }
        for v in [n.value,opened[i].0,n.is_dummy as u64,n.path.siblings.len() as u64] { put(&mut dst,v)?; }
        for (pos,siblings) in n.path.positions.iter().zip(&n.path.siblings) {
            put(&mut dst,*pos as u64)?;
            for d in siblings { dst.write_all(&d.to_bytes())?; }
        }
    }
    for (i,n) in w.outputs.iter().enumerate() {
        dst.write_all(&n.pk.to_bytes())?;
        dst.write_all(&opened[i+2].1.to_bytes())?;
        put(&mut dst,n.value)?;
        put(&mut dst,opened[i+2].0)?;
    }
    dst.write_all(&id.to_bytes())?;
    put(&mut dst,w.fee)?;
    put(&mut dst,delta)?;
    put(&mut dst,key.len() as u64)?;
    for k in key {put(&mut dst,*k as u64)?;}
    dst.write_all(&w.ct_digest.to_bytes())?;
    put(&mut dst,proof.public_inputs.len() as u64)?;
    for f in &proof.public_inputs {put(&mut dst,f.to_canonical_u64())?;}
    Ok(())
}
