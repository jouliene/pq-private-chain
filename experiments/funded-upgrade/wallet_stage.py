"""Install the original wallet/outbox with two separately pinned funding profiles."""
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent


def change(source, old, new):
    if source.count(old) != 1:
        raise ValueError("wallet adapter differs from its audited source: " + old[:65])
    return source.replace(old, new)


def apply(dev):
    def rewrite(name, edits, output=None):
        path = dev / name
        source = path.read_text()
        for old, new in edits:
            source = change(source, old, new)
        target = dev / (output or name)
        compile(source, str(target), "exec")
        target.write_text(source)

    rewrite("wallet.py", [
        ("class Wallet(AssetWallet):", "class Wallet(AssetWallet):\n    check_keys = staticmethod(checked_keys)"),
        ("checked_keys(keys),private=private", "self.check_keys(keys),private=private")])
    rewrite("asset_wallet.py", [
        ("class AssetWallet:", 'class AssetWallet:\n    proof_magic = b"MNG1\\x01"'),
        ('raw[:5] != b"MNG1\\x01"', 'raw[:5] != self.proof_magic')])
    # A saved negotiation keeps the suite of its actual offered leg. A new
    # profile must never return a cached leg or released signature of the old one.
    rewrite("swap_wallet.py", [
        ('            packet = old["leg"]', '            packet = old["leg"]\n            frame(packet)'),
        ('    joint = digest(terms.network,key,terms.expiry,terms.payer,legs)',
         '    for leg in legs:\n        frame(leg)\n    joint = digest(terms.network,key,terms.expiry,terms.payer,legs)')])
    rewrite("swap_wallet.py", [
        ('MAGIC = b"SLG1\\x01"', 'MAGIC = b"SLG2\\x01"'),
        ('deploy/"swap-keys/swap.vk"', 'deploy/"b-swap-keys/swap.vk"'),
        ('deploy/"devnet/swap.vk"', 'deploy/"devnet/b-swap.vk"'),
        ('deploy/"devnet/approved-swap-native.sha256"', 'deploy/"devnet/approved-b-swap-native.sha256"'),
        ('deploy/"swap-runtime/native"', 'deploy/"b-swap-runtime/native"'),
    ], "swap_b_wallet.py")
    # On a retry the outbox keeps its recipient, amount and original real input pins.
    # Rebuild only an obsolete pending transfer, after checking selected inclusions.
    rewrite("intents.py", [
        ('if attempt is None or force_new or state.height-attempt["height"]>=WINDOW:',
         '''obsolete = False
            if attempt is not None and attempt["packet"] is not None and row["operation"] == "transfer":
                from upgrade_rules import FIRST_B, FIRST_B_ONLY
                next_height = state.height + 1
                is_b = attempt["packet"].startswith(b"MSP2")
                obsolete = next_height < FIRST_B if is_b else next_height >= FIRST_B_ONLY
            if attempt is None or force_new or obsolete or state.height-attempt["height"]>=WINDOW:''')])
    shutil.copyfile(HERE / "upgrade_wallet.py", dev / "upgrade_wallet.py")
