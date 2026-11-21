"""Wallet profile C uses the same receiving keys, private source records and spent identities."""
from upgrade_wallet_ab import BWallet, FundedLab as PreviousLab, DEV
from wire import need


class CWallet(BWallet):
    proof_magic = b"MNG3\x01"

    @staticmethod
    def check_keys(keys):
        key = keys/"managed.vk"
        need(not keys.is_symlink() and not key.is_symlink() and set(keys.iterdir()) == {key}
             and key.read_bytes() == (DEV/"c-managed.vk").read_bytes(), "unapproved C wallet registration")
        return keys


class FundedLab(PreviousLab):
    def __init__(self,home,suite):
        super().__init__(home,suite)
        self.suite = suite

    def wallet(self,name,mode="restore"):
        if self.suite != "C":
            return super().wallet(name,mode)
        binary = DEV.parent/"c-runtime"/"native"
        need(not binary.is_symlink() and not binary.parent.is_symlink(), "unapproved C wallet binary")
        pin = (DEV/"approved-c-native.sha256").read_text().strip()
        return CWallet(binary,pin,DEV.parent/"c-keys",self.walletdir(name),mode)
