"""Compare individually isolated control wallets against two independently validated histories."""

OWNERS = ("miner-a", "miner-b", "alice", "bob", "forward", "conflict", "offline")
FIELDS = ("tip", "height", "work", "header", "anchor", "issued", "fees", "notes", "spent", "spent_set_sha256")


def compare(views, wallets, wanted):
    """Inputs are public statuses and disclosed fixture balances returned by separate processes.

    views maps each endpoint to a pair (status, registry). wallets maps each endpoint
    to {owner: wallet.py restore/balance result}. wanted optionally supplies exact
    (native, asset mapping) pairs for particular wallets with known funding/fee flows.
    """
    if len(views) != 2 or views.keys() != wallets.keys():
        raise ValueError("expected one pruned node and one full validator")
    observations = []
    cold_queries = {}
    for node, (status, registry) in views.items():
        public = {k: status[k] for k in FIELDS}
        restored = {}
        if set(wallets[node]) != set(OWNERS):
            raise ValueError("missing control owner")
        for owner, row in wallets[node].items():
            if not row["complete"] or row["tip"] != public["tip"] or row["height"] != public["height"]:
                raise ValueError("incomplete control-wallet endpoint")
            restored[owner] = {"native": row["native"], "assets": row["assets"], "notes": row["notes"]}
        cold = [row for row in wallets[node].values() if row["sync"]["start_height"] == 0]
        if len(cold) == len(OWNERS):
            first = cold[0]
            signature = (first["public_history_queries_sha256"], first["public_history_query_shapes"],
                         first["sync"]["request_B"], first["sync"]["public_body_B"])
            for row in cold[1:]:
                if (row["public_history_queries_sha256"], row["public_history_query_shapes"],
                    row["sync"]["request_B"], row["sync"]["public_body_B"]) != signature:
                    raise ValueError("cold wallet history queries depend on controlled holdings")
            cold_queries[node] = dict(owners=len(cold), digest=signature[0], operations=signature[1],
                                      request_B=signature[2], public_body_B=signature[3])
        for owner, (native, assets) in wanted.items():
            if (restored[owner]["native"], restored[owner]["assets"]) != (native, assets):
                raise ValueError(f"unexpected fixture balance for {owner}")
        if sum(r["native"] for r in restored.values()) != status["issued"]:
            raise ValueError("native controlled-wallet supply mismatch")
        totals = {}
        for r in restored.values():
            for asset, quantity in r["assets"].items():
                totals[asset] = totals.get(asset, 0) + quantity
        if totals != {asset: row["supply"] for asset, row in registry.items()}:
            raise ValueError("controlled wallets do not reproduce the entire selected registry supply")
        observations.append(dict(state=public, registry=registry, balances=restored))
    if observations[0] != observations[1]:
        raise ValueError("pruned/full validated state or control-wallet holdings differ")
    if len(cold_queries) == 2 and len({entry["digest"] for entry in cold_queries.values()}) != 1:
        raise ValueError("cold wallets on matching endpoints requested different public history")
    return dict(observations[0], cold_queries=cold_queries)
