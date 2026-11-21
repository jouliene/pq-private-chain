"""Install a bounded experiment extension into a disposable funded deployment."""
import shutil


def replace(path, old, new):
    source = path.read_text()
    if source.count(old) != 1:
        raise ValueError('unrecognized registration seam in ' + str(path))
    path.write_text(source.replace(old, new))


def stage(source, destination):
    shutil.copytree(source,destination)
    dev = destination/'devnet'
    ledger = dev/'swap_ledger.py'
    chain = dev/'chain.py'
    replace(ledger, 'from swap_wire import BUNDLE, FRAME, bundle, digest, groups, pair, read_frame, split',
            'from swap_wire import digest, pair\nfrom registration import BUNDLE, FRAME, bundle, groups, read_frame, split')
    replace(ledger, 'for slot in verify_pair(group,self.swap_verifier(),NETWORK,head["h"]+1):',
            'for slot in self.registered_group(group,head):')
    replace(chain, 'from swap_wire import split as split_swap','from registration import split as split_swap')
    replace(chain, 'packet.startswith(b"SWB1")', 'packet.startswith((b"SWB1",b"FTB1"))')
    replace(chain, 'slots.extend(verify_pair(g,self.swap_verifier(),NETWORK,height))',
            'slots.extend(self.registered_group(g,self._row(b.parent),archived=True))')
    replace(chain, 'class Chain(SwapSupport,ManagedChain):', 'from registration import BranchProofs\nclass Chain(BranchProofs,SwapSupport,ManagedChain):')
    registry = dev/'managed_ledger.py'
    replace(registry, 'from swap_wire import FRAME, read_frame', 'from registration import FRAME, read_frame')
    replace(registry, 'slot = verify_pair(packets[base:base+2],self.swap_verifier(),NETWORK,hit["h"])[side]',
            'slot = self.registered_group(packets[base:base+2],self._row(decode_block(hit["raw"]).parent),archived=True)[side]')
