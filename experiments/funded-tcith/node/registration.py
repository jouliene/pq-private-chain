"""FTL1 experiment registration on an isolated copy of the funded PoW node."""
from hashlib import sha256
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
EX = HERE.parents[1]
sys.path[:0] = [str(HERE.parent/'wallet')]
import ftl_wire as ft
from funded_projection import pivot
import swap_wire as sw
from managed_ledger import ManagedSlot
from wire import ZERO, need

BUNDLE = (sw.BUNDLE, ft.BUNDLE)
FRAME = (sw.FRAME, ft.FRAME)


def read_frame(raw):
    return ft.read_frame(raw) if raw.startswith(ft.FRAME) else sw.read_frame(raw)


def bundle(frames):
    if frames[0].startswith(ft.FRAME):
        raw = ft.BUNDLE + b''.join(struct.pack('<I', len(f)) + f for f in frames)
        ft.split(raw)
        return raw
    return sw.bundle(frames)


def split(raw):
    return ft.physical_frames(raw) if raw.startswith(ft.BUNDLE) else sw.split(raw)


def groups(packets):
    stream = iter(packets)
    for first in stream:
        if first.startswith(FRAME):
            second = next(stream, None)
            need(second is not None, "incomplete atomic swap")
            bundle((first, second))
            yield first, second
        else:
            yield (first,)


class BranchProofs:
    """The verifier selects the program, branch, leaf population and accepted root."""
    params = None

    def archived_leaves(self, row):
        # Only for history-index backfill on previously validated side branches.
        # Reconstruct the body's public output order and verify its legacy frontier.
        from chain import Frontier, decode_block
        from swap_ledger import read_leg
        result = []
        branch = []
        current = row
        while current['h']:
            raw, = self.db.execute("SELECT raw FROM blocks WHERE id=?", (current['id'],)).fetchone()
            branch.append(decode_block(raw))
            current = self._row(current['parent'])
        for block in reversed(branch):
            for group in groups(block.packets):
                if len(group) == 1:
                    slot, = self.backend.verify(group[0])
                    result.extend(slot.cms)
                else:
                    for raw_frame in group:
                        frame = read_frame(raw_frame)
                        if frame.leg.startswith(ft.LEG):
                            words = ft.candidate_fields(frame.leg)
                            result.extend(struct.pack('<4Q', *words[i:i+4]) for i in (13,17))
                        else:
                            result.extend(read_leg(self.swap_verifier(), frame.leg)[3])
            result.append(block.reward_cm)
        frontier = Frontier(0, b'', self.backend.hashes)
        for leaf in result:
            frontier.append(leaf)
        need(frontier.count == row['n'] and frontier.root() == row['header'][100:], 'archived funded branch')
        return result

    def registered_group(self, frames, head, archived=False):
        from chain import NETWORK, WINDOW
        from swap_ledger import verify_pair
        if frames[0].startswith(sw.FRAME):
            return verify_pair(frames, self.swap_verifier(), NETWORK, head['h']+1)
        raw = bundle(frames)
        words = ft.candidate_fields(read_frame(frames[0]).leg)
        h = words[4]
        need(1 <= head['h']+1-h <= WINDOW, 'anchor age')
        if archived:
            row = head
            while row['h'] > h:
                row = self._row(row['parent'])
        else:
            row = self.db.execute("SELECT blocks.id,blocks.ap,blocks.n FROM sel JOIN blocks USING(id) WHERE sel.h=?", (h,)).fetchone()
        need(row and row['ap'] == struct.pack('<4Q', *words[:4]), 'anchor branch')
        if archived:
            leaves = self.archived_leaves(row)
        else:
            leaves = [r[0] for r in self.db.execute("SELECT cm FROM outs WHERE h<=? ORDER BY pos", (h,))]
        need(len(leaves) == row['n'] and 0 < len(leaves) <= 4**20, 'funded branch population')
        if self.params is None:
            self.params = pivot.f.constants(Path('/constants.rs'))
        aux = pivot.tree(self.params, leaves, 0)[0]
        metrics = {}
        _, effects = ft.validate_pair(raw, Path('/engine'), Path('/shape'), NETWORK, head['h']+1,
                                      row['id'], row['n'], aux, self.params, self.swap_verifier(), metrics=metrics)
        self.ft_metrics = dict(engine=metrics, anchor_height=h, endpoint=row['id'].hex(),
                               leaf_count=row['n'], aux_root=aux.hex())
        return [ManagedSlot(e.anchor,e.height,e.nfs,e.cms,e.fee,e.cts,ZERO,0,'swap',b'',0,ZERO,sha256(frame).digest())
                for e,frame in zip(effects,frames,strict=True)]
