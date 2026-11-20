"""Identify the precise received note for a redemption and a compatible native fee input."""

ZERO = bytes(32)


def return_commitment(db, txid, asset, quantity):
    # A self-transfer can appear as an incoming (non-change) receipt. Checking
    # the sender's locally discovered nullifiers also excludes such transfers.
    if db.execute("SELECT 1 FROM owned WHERE spender=? LIMIT 1", (txid,)).fetchone():
        raise ValueError("return transaction spends a note owned by the redeeming wallet")
    rows = db.execute("SELECT cm FROM owned WHERE creator=? AND kind='incoming' "
                      "AND asset=? AND token=? AND spent IS NULL",
                      (txid, asset, quantity)).fetchall()
    if len(rows) != 1:
        raise ValueError("expected one unspent incoming return for the specified transaction, asset and amount")
    return bytes(rows[0][0])


def select_return(db, request, exclude, change_for):
    returned = return_commitment(db, request.return_tx, request.asset, request.burn)
    if exclude(returned.hex()):
        raise ValueError("the returned note is reserved by another intent")
    native, token = db.execute("SELECT amount,token FROM owned WHERE cm=?", (returned,)).fetchone()
    if change_for(request, native, token) is not None:
        return (returned.hex(),)
    fees = db.execute("SELECT cm,amount FROM owned WHERE spent IS NULL AND asset=? AND token=0 "
                      "AND amount>0 ORDER BY pos", (ZERO,))
    for other, amount in fees:
        if not exclude(other.hex()) and change_for(request, native + amount, token) is not None:
            return (returned.hex(), other.hex())
    raise ValueError("returned note needs an available native fee input")
