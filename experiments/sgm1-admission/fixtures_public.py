"""Public-only fixture indexing; no witness, verification verdict or imported tree state."""
from packets import funded, need
def read_prefix(directory):
    pin = bytes.fromhex((directory/"genesis.sha256").read_text().strip())
    chain, rows = funded(directory/"prefix",pin)
    return pin,chain,rows

def read_rows(directory, limit):
    for index in range(1,limit+1):
        f=directory/f"op-{index:02}.bin"
        with f.open("rb") as stream:
            wire=stream.read(524309)
        need(0 < len(wire) <=524308,"operation extent")
        yield wire
