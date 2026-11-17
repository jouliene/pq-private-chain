"""Selective append witnesses and bounded branch journal; no ledger/path oracle.

The caller supplies ordered PUBLIC funded leaves and local discovery tokens.
Tokens/indices/paths are private in a real wallet; this module has no file or
network API and does not hash selection metadata. The hash callable is an
experiment interface, not a transaction-selected cryptographic program.
"""
from collections import deque
from dataclasses import dataclass


class WitnessError(ValueError):
    pass


class ReplayRequired(WitnessError):
    """The requested common prefix is outside the bounded private undo journal."""


def need(ok, reason):
    if not ok:
        raise WitnessError(reason)


@dataclass(frozen=True)
class Head:
    height: int
    identity: bytes
    count: int
    root: tuple


@dataclass(frozen=True)
class Block:
    height: int
    parent: bytes
    identity: bytes
    count: int
    root: tuple
    leaves: tuple


@dataclass(frozen=True)
class Witness:
    index: int
    siblings: tuple
    anchor: Head


class SelectiveFrontier:
    """O(D+kD) current state. Register a target only at its incoming leaf."""
    def __init__(self, depth, node, empty_leaf, max_owned):
        need(type(depth) is int and 1 <= depth <= 40, 'depth bound')
        need(type(max_owned) is int and max_owned > 0, 'owned-note bound')
        self.depth, self.node, self.max_owned = depth, node, max_owned
        self.empty = [tuple(empty_leaf)]
        for level in range(depth):
            self.empty.append(tuple(node(level, self.empty[-1], self.empty[-1])))
        self.empty = tuple(self.empty)
        self.stack, self.paths, self.indices, self.wanted = [], {}, {}, {}
        self.count, self.peak_stack = 0, 0

    def clone(self):
        other = object.__new__(type(self))
        other.depth, other.node, other.max_owned = self.depth, self.node, self.max_owned
        other.empty = self.empty
        other.stack = list(self.stack)
        other.paths = {key: list(path) for key, path in self.paths.items()}
        other.indices = dict(self.indices)
        other.wanted = {key: set(values) for key, values in self.wanted.items()}
        other.count, other.peak_stack = self.count, self.peak_stack
        return other

    def _capture(self, start, level, value):
        for token in self.wanted.get((start, level), ()):
            previous = self.paths[token][level]
            need(previous is None or previous == value, 'inconsistent sibling')
            self.paths[token][level] = value

    def _subtree(self, start, level, value):
        need(start % (1 << level) == 0 and level <= self.depth, 'subtree alignment')
        self._capture(start, level, value)
        while self.stack and self.stack[-1][1] == level:
            old, _, left = self.stack.pop()
            need(old + (1 << level) == start and old % (2 << level) == 0, 'frontier adjacency')
            value = tuple(self.node(level, left, value))
            start, level = old, level + 1
            self._capture(start, level, value)
        self.stack.append((start, level, value))
        self.peak_stack = max(self.peak_stack, len(self.stack))

    def _discover(self, token):
        need(token not in self.paths and len(self.paths) < self.max_owned, 'owned-note capacity or duplicate')
        path = [None] * self.depth
        frontier = {(start, level): value for start, level, value in self.stack}
        for level in range(self.depth):
            sibling_start = ((self.count >> level) ^ 1) << level
            if (self.count >> level) & 1:
                # Every completed left sibling is in the prefix forest before
                # this leaf; no historical path or old leaf vector is queried.
                need((sibling_start, level) in frontier, 'missing prefix sibling')
                path[level] = frontier[sibling_start, level]
            else:
                self.wanted.setdefault((sibling_start, level), set()).add(token)
        self.paths[token], self.indices[token] = path, self.count

    def append(self, value, discovered=None):
        need(self.count < (1 << self.depth), 'tree capacity')
        if discovered is not None:
            self._discover(discovered)
        self._subtree(self.count, 0, tuple(value))
        self.count += 1

    def forget(self, token):
        if token not in self.paths:
            return
        del self.paths[token]
        del self.indices[token]
        for key in list(self.wanted):
            self.wanted[key].discard(token)
            if not self.wanted[key]:
                del self.wanted[key]

    def view(self):
        """Pad a private clone only; future real appends remain possible."""
        if self.count == 0:
            return self.empty[self.depth], {}
        temporary = self.clone()
        at = self.count
        while at < (1 << self.depth):
            level = (at & -at).bit_length() - 1
            temporary._subtree(at, level, self.empty[level])
            at += 1 << level
        need(len(temporary.stack) == 1 and temporary.stack[0][:2] == (0, self.depth), 'final frontier')
        need(all(all(value is not None for value in path) for path in temporary.paths.values()), 'incomplete witness')
        return temporary.stack[0][2], {key: tuple(path) for key, path in temporary.paths.items()}

    def payload_counts(self):
        """For PUBLIC diagnostic controls only; never serialize private state."""
        return {'frontier_digests': len(self.stack), 'path_slots': len(self.paths) * self.depth,
                'wanted_references': sum(map(len, self.wanted.values())), 'empty_digests': len(self.empty)}


class State:
    def __init__(self, head, frontier, anchors):
        self.head, self.frontier, self.anchors = head, frontier, anchors

    def clone(self):
        return State(self.head, self.frontier.clone(), deque(self.anchors))


class WalletWitnesses:
    """Committed state plus bounded private undo; no untrusted state bootstrap."""
    def __init__(self, genesis, node, empty_leaf, *, depth=40, max_owned=64, rewind_blocks=8,
                 anchor_window=256, block_leaf_cap=256, allow_empty_blocks=False):
        need(genesis.height == 0 and genesis.count == 0, 'start from genesis')
        need(type(rewind_blocks) is int and rewind_blocks >= 0, 'rewind bound')
        need(type(anchor_window) is int and anchor_window > 0, 'anchor bound')
        need(type(block_leaf_cap) is int and block_leaf_cap > 0, 'block bound')
        need(type(allow_empty_blocks) is bool, 'empty-block policy')
        frontier = SelectiveFrontier(depth, node, empty_leaf, max_owned)
        need(frontier.view()[0] == genesis.root, 'genesis empty root')
        self.state = State(genesis, frontier, deque([genesis]))
        self.history = deque([self.state.clone()], maxlen=rewind_blocks + 1)
        self.rewind_blocks, self.anchor_window, self.block_leaf_cap = rewind_blocks, anchor_window, block_leaf_cap
        self.revision = 0
        self.allow_empty_blocks, self.active_epoch = allow_empty_blocks, None

    def epoch(self, trusted_endpoint):
        return Epoch(self, trusted_endpoint)

    def witness(self, token):
        root, paths = self.state.frontier.view()
        need(root == self.state.head.root and token in paths, 'unspent selected occurrence required')
        return Witness(self.state.frontier.indices[token], paths[token], self.state.head)

    def anchor_eligible(self, root, count):
        # The wire binds root/count, not an alleged origin branch or block ID.
        return any(head.root == root and head.count == count for head in self.state.anchors)

    def draft_eligible(self, token, root, count):
        return (token in self.state.frontier.indices and self.state.frontier.indices[token] < count and
                self.anchor_eligible(root, count))

    def rewind(self, common_prefix):
        candidates = [state for state in self.history if state.head == common_prefix]
        if not candidates:
            raise ReplayRequired('common prefix outside private journal; authenticated replay required')
        selected = candidates[0]
        if self.active_epoch is not None:
            self.active_epoch.abort()
        self.state = selected.clone()
        self.history = deque([state for state in self.history if state.head.height <= common_prefix.height],
                             maxlen=self.rewind_blocks + 1)
        self.revision += 1


class Epoch:
    """All changes tentative until the independently selected endpoint matches."""
    def __init__(self, owner, trusted_endpoint):
        need(owner.active_epoch is None, 'one active epoch only')
        self.owner, self.endpoint = owner, trusted_endpoint
        self.state = owner.state.clone()
        self.history = deque(owner.history, maxlen=owner.rewind_blocks + 1)
        self.phase = 'active'
        self.base_revision = owner.revision
        owner.active_epoch = self

    def abort(self):
        if self.owner.active_epoch is self:
            self.owner.active_epoch = None
        self.phase = 'poisoned'
        self.state = None
        self.history.clear()

    def apply(self, block, discovery, spent_tokens=()):
        need(self.phase == 'active', 'inactive epoch')
        try:
            prior = self.state.head
            need(self.owner.active_epoch is self and self.owner.revision == self.base_revision, 'stale epoch after branch change')
            need(block.height == prior.height + 1 and block.height <= self.endpoint.height, 'block ordering')
            need(block.parent == prior.identity, 'parent identity')
            need(len(block.leaves) <= self.owner.block_leaf_cap and
                 (bool(block.leaves) or self.owner.allow_empty_blocks), 'bounded block and explicit empty policy')
            need(block.count == prior.count + len(block.leaves), 'leaf count')
            if not block.leaves:
                need(block.root == prior.root and block.count == prior.count and not spent_tokens,
                     'empty block must preserve tree and spent state')
            need(len(set(spent_tokens)) == len(spent_tokens), 'duplicate spent token')
            for token in spent_tokens:
                self.state.frontier.forget(token)
            for value in block.leaves:
                index = self.state.frontier.count
                self.state.frontier.append(value, discovery(index, value))
            need(self.state.frontier.view()[0] == block.root, 'authenticated root mismatch')
            head = Head(block.height, block.identity, block.count, block.root)
            self.state.head = head
            self.state.anchors.append(head)
            minimum = max(0, head.height - (self.owner.anchor_window - 1))
            while self.state.anchors and self.state.anchors[0].height < minimum:
                self.state.anchors.popleft()
            self.history.append(self.state.clone())
        except BaseException:
            self.abort()
            raise

    def finish(self):
        need(self.phase == 'active', 'inactive epoch')
        if self.owner.active_epoch is not self or self.owner.revision != self.base_revision:
            self.abort()
            raise WitnessError('stale epoch after branch change')
        if self.state.head != self.endpoint:
            self.abort()
            raise WitnessError('independently supplied endpoint mismatch')
        self.owner.state, self.owner.history = self.state, self.history
        self.owner.revision += 1
        self.owner.active_epoch = None
        # Finished epoch handles must not retain extra historical private copies.
        self.state, self.history = None, deque()
        self.phase = 'finished'
        return self.owner
