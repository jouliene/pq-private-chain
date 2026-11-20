const BURN: u64 = 1 << 62;

// Supply words share the same encoding between the wallet IPC, proof and node.
fn available_after_delta(input: u64, recipient: u64, encoded: u64) -> Result<u64> {
    ensure!(encoded < 2 * BURN, "reserved supply bit");
    let magnitude = encoded & (BURN - 1);
    if encoded & BURN != 0 {
        ensure!(magnitude != 0 && input >= magnitude, "invalid burn");
        return Ok(input - magnitude);
    }
    if magnitude != 0 {
        ensure!(input == 0 && recipient == magnitude, "invalid mint request");
    }
    Ok(input + magnitude)
}
