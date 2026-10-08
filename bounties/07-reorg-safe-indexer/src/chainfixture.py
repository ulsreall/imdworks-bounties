"""Deterministic fake-chain fixture for imdworks.fun bounty #07.

Stdlib only.  No network.  No randomness.  No private keys -- every address is a
public/derived constant and all hashes are sha256 over a fixed byte string.

The fixture models a node that serves TWO competing branches which share a
common ancestor:

    base    heights 0..9    identical blocks on both branches (common ancestor)
    branch A heights 10..14  first-seen chain (becomes orphaned)
    branch B heights 10..14  reorging chain (different txs and different hashes)

``ChainFixture(canonical="A")`` / ``ChainFixture(canonical="B")`` chooses which
branch the node currently serves; ``reorg()`` flips A -> B and models a
five-block reorg (heights 10..14 replaced).

Logs are encoded exactly like EVM logs, as the tuple
``(block_number, block_hash, parent_hash, tx_hash, tx_index, log_index,
topics, data)``, with a real (if non-keccak, fixture-local) topic0 = sha256 of
the canonical event signature, and ABI head/tail encoding of the data payload.

Event signatures mirror the escrow contract:

    BountyCreated(uint256,address,uint256,uint64,bytes32,string)
    RewardAdded(uint256,uint256,uint256)
    WorkSubmitted(uint256,address,address,bytes32,string)
    BountyAwarded(uint256,address,uint256)
    BountyRefunded(uint256,address,uint256,uint8)
    Withdrawn(address,address,uint256)

The encoder is ABI-correct (indexed params -> topics, the rest -> data with
dynamic head/tail layout) so the indexer decodes it from topics+data alone and
never trusts an out-of-band "name" field.
"""

from __future__ import annotations

import copy
import hashlib
import json

FIXTURE_VERSION = "imdworks.bounty07.chainfixture.v1"

# --- public constants (no private material anywhere) ------------------------

ESCROW = "0x" + hashlib.sha256(b"imdworks.fun/escrow/fixture").hexdigest()[:40]
CREATOR = "0x5f1f9bfad4ae9580519710f5ae1747ee4cbc1e97"  # bounty owner from the brief
ALICE = "0x1111111111111111111111111111111111111111"
BOB = "0x2222222222222222222222222222222222222222"

ZERO32 = "0x" + "00" * 32

# --- event ABI --------------------------------------------------------------

SIGS = {
    "BountyCreated": "BountyCreated(uint256,address,uint256,uint64,bytes32,string)",
    "RewardAdded": "RewardAdded(uint256,uint256,uint256)",
    "WorkSubmitted": "WorkSubmitted(uint256,address,address,bytes32,string)",
    "BountyAwarded": "BountyAwarded(uint256,address,uint256)",
    "BountyRefunded": "BountyRefunded(uint256,address,uint256,uint8)",
    "Withdrawn": "Withdrawn(address,address,uint256)",
}

# (name, type, indexed?) in declaration order.
PARAMS = {
    "BountyCreated": [
        ("bountyId", "uint256", True),
        ("creator", "address", True),
        ("reward", "uint256", False),
        ("deadline", "uint64", False),
        ("briefHash", "bytes32", False),
        ("uri", "string", False),
    ],
    "RewardAdded": [
        ("bountyId", "uint256", True),
        ("amount", "uint256", False),
        ("total", "uint256", False),
    ],
    "WorkSubmitted": [
        ("bountyId", "uint256", True),
        ("submitter", "address", True),
        ("worker", "address", False),
        ("proofHash", "bytes32", False),
        ("uri", "string", False),
    ],
    "BountyAwarded": [
        ("bountyId", "uint256", True),
        ("winner", "address", True),
        ("amount", "uint256", False),
    ],
    "BountyRefunded": [
        ("bountyId", "uint256", True),
        ("creator", "address", True),
        ("amount", "uint256", False),
        ("reason", "uint8", False),
    ],
    "Withdrawn": [
        ("account", "address", True),
        ("to", "address", False),
        ("amount", "uint256", False),
    ],
}

INT_TYPES = {"uint256", "uint128", "uint64", "uint32", "uint8", "int256"}


def topic0(name: str) -> str:
    """Fixture stand-in for keccak256(signature): deterministic and collision-free here."""
    return "0x" + hashlib.sha256(SIGS[name].encode()).hexdigest()


SIGTOPIC = {topic0(name): name for name in SIGS}


# --- minimal ABI codec ------------------------------------------------------

def _word_int(n: int) -> str:
    return format(int(n) & ((1 << 256) - 1), "064x")


def _enc_addr(a: str) -> str:
    return a.lower().replace("0x", "").rjust(64, "0")


def _enc_bytes32(b: str) -> str:
    h = b.lower().replace("0x", "")
    if len(h) != 64:
        raise ValueError(f"bytes32 must be 32 bytes, got {len(h)//2}")
    return h


def encode_params(types, values) -> str:
    """ABI head/tail encoding (no 0x)."""
    if len(types) != len(values):
        raise ValueError("arity mismatch")
    head = []
    tail = []
    tail_len = 0
    for t, v in zip(types, values):
        if t in INT_TYPES:
            head.append(_word_int(v))
        elif t == "address":
            head.append(_enc_addr(v))
        elif t == "bytes32":
            head.append(_enc_bytes32(v))
        elif t in ("string", "bytes"):
            data = v.encode() if isinstance(v, str) else bytes(v)
            offset = 32 * len(types) + tail_len
            head.append(_word_int(offset))
            padded = data.hex().ljust(((len(data) + 31) // 32) * 64, "0")
            enc = _word_int(len(data)) + padded
            tail.append(enc)
            tail_len += len(enc) // 2
        else:
            raise ValueError(f"unsupported type {t}")
    return "".join(head) + "".join(tail)


def decode_params(types, blob: str):
    if blob.startswith("0x"):
        blob = blob[2:]
    b = bytes.fromhex(blob)
    out = []
    for i, t in enumerate(types):
        w = b[i * 32:(i + 1) * 32]
        if t in INT_TYPES:
            out.append(int.from_bytes(w, "big"))
        elif t == "address":
            out.append("0x" + w[12:].hex())
        elif t == "bytes32":
            out.append("0x" + w.hex())
        elif t in ("string", "bytes"):
            off = int.from_bytes(w, "big")
            ln = int.from_bytes(b[off:off + 32], "big")
            raw = b[off + 32:off + 32 + ln]
            out.append(raw.decode() if t == "string" else raw)
        else:
            raise ValueError(f"unsupported type {t}")
    return out


def encode_topic(ptype: str, v) -> str:
    if ptype in INT_TYPES:
        return "0x" + _word_int(v)
    if ptype == "address":
        return "0x" + _enc_addr(v)
    if ptype == "bytes32":
        return "0x" + _enc_bytes32(v)
    raise ValueError(f"unindexable type {ptype}")


def decode_topic(ptype: str, topic: str):
    h = topic[2:] if topic.startswith("0x") else topic
    if ptype in INT_TYPES:
        return int(h, 16)
    if ptype == "address":
        return "0x" + h[24:]
    if ptype == "bytes32":
        return "0x" + h
    raise ValueError(ptype)


def decode_event(topics, data):
    """Recover (name, {field: value}) purely from topics + data."""
    if not topics:
        raise ValueError("no topics")
    name = SIGTOPIC.get(topics[0])
    if name is None:
        raise ValueError(f"unknown topic0 {topics[0]}")
    params = PARAMS[name]
    non_idx = [(n, t) for (n, t, ix) in params if not ix]
    data_vals = decode_params([t for _, t in non_idx], data)
    out = {}
    di = 0
    ti = 1
    for (n, t, ix) in params:
        if ix:
            out[n] = decode_topic(t, topics[ti])
            ti += 1
        else:
            out[n] = data_vals[di]
            di += 1
    return name, out


def make_log(block_number, block_hash, parent_hash, tx_hash, tx_index, log_index,
             address, name, args):
    topics = [topic0(name)]
    data_types = []
    data_vals = []
    for (pname, ptype, indexed) in PARAMS[name]:
        if pname not in args:
            raise KeyError(f"{name} missing arg {pname}")
        if indexed:
            topics.append(encode_topic(ptype, args[pname]))
        else:
            data_types.append(ptype)
            data_vals.append(args[pname])
    return {
        "block_number": int(block_number),
        "block_hash": block_hash,
        "parent_hash": parent_hash,
        "tx_hash": tx_hash,
        "tx_index": int(tx_index),
        "log_index": int(log_index),
        "address": address,
        "name": name,           # convenience only; the indexer re-derives it
        "topics": topics,
        "data": "0x" + encode_params(data_types, data_vals),
    }


def _block_hash(number, parent_hash, timestamp, tx_hashes) -> str:
    h = hashlib.sha256()
    h.update(FIXTURE_VERSION.encode())
    h.update(b"|block|")
    h.update(int(number).to_bytes(8, "big"))
    h.update(bytes.fromhex(parent_hash[2:]))
    h.update(int(timestamp).to_bytes(8, "big"))
    for th in tx_hashes:
        h.update(bytes.fromhex(th[2:]))
    return "0x" + h.hexdigest()


# --- deterministic scripted history ----------------------------------------

def _h32(label: str) -> str:
    return "0x" + hashlib.sha256(label.encode()).hexdigest()


BRIEF1 = _h32("brief:escrow:1")
BRIEF2 = _h32("brief:escrow:2")
DEADLINE1 = 1_760_000_000
DEADLINE2 = 1_760_500_000

# tx specs: block -> [ tx, ... ] ; tx -> [ [event_name, {args}], ... ]
# (a single-event tx is therefore a one-element list, and a tx may carry more
#  than one log so that per-tx log_index > 0 is exercised.)

BASE_TXS = {
    2: [[["BountyCreated", {"bountyId": 1, "creator": CREATOR, "reward": 1000,
                            "deadline": DEADLINE1, "briefHash": BRIEF1,
                            "uri": "ipfs://bafybrief1"}]]],
    # one tx, two logs -> log_index 0 and 1
    4: [[["RewardAdded", {"bountyId": 1, "amount": 200, "total": 1200}],
         ["RewardAdded", {"bountyId": 1, "amount": 300, "total": 1500}]]],
    6: [[["WorkSubmitted", {"bountyId": 1, "submitter": ALICE, "worker": ALICE,
                            "proofHash": _h32("proof:alice:base"),
                            "uri": "ipfs://work-alice-base"}]]],
    8: [[["BountyCreated", {"bountyId": 2, "creator": CREATOR, "reward": 700,
                            "deadline": DEADLINE2, "briefHash": BRIEF2,
                            "uri": "ipfs://bafybrief2"}]]],
}

BRANCH_A_TXS = {
    10: [[["RewardAdded", {"bountyId": 1, "amount": 500, "total": 2000}]]],
    11: [[["WorkSubmitted", {"bountyId": 1, "submitter": ALICE, "worker": ALICE,
                             "proofHash": _h32("proof:alice:A"),
                             "uri": "ipfs://work-alice-A"}]]],
    12: [[["BountyAwarded", {"bountyId": 1, "winner": ALICE, "amount": 1000}]]],
    13: [[["Withdrawn", {"account": ALICE, "to": ALICE, "amount": 400}]]],
    14: [[["RewardAdded", {"bountyId": 2, "amount": 300, "total": 1000}]]],
}

BRANCH_B_TXS = {
    10: [[["WorkSubmitted", {"bountyId": 1, "submitter": BOB, "worker": BOB,
                             "proofHash": _h32("proof:bob:B"),
                             "uri": "ipfs://work-bob-B"}]]],
    11: [[["BountyAwarded", {"bountyId": 1, "winner": BOB, "amount": 1500}]]],
    12: [[["BountyRefunded", {"bountyId": 2, "creator": CREATOR, "amount": 200,
                              "reason": 1}]]],
    13: [[["Withdrawn", {"account": BOB, "to": BOB, "amount": 100}]]],
    14: [[["RewardAdded", {"bountyId": 2, "amount": 300, "total": 1000}]]],
}

GENESIS_PARENT = ZERO32
FORK_START = 10
FORK_END = 14


def _ts(number: int) -> int:
    return 1_600_000_000 + number * 12


class ChainFixture:
    """A deterministic node serving two branches with a shared ancestor."""

    def __init__(self, canonical: str = "A"):
        if canonical not in ("A", "B"):
            raise ValueError("canonical must be 'A' or 'B'")
        self.canonical = canonical
        self._build()

    def _build(self):
        self.branches = {"A": {}, "B": {}}
        prev = GENESIS_PARENT
        for n in range(0, FORK_START):
            blk = self._make_block(n, prev, _ts(n), BASE_TXS.get(n, []), "base")
            self.branches["A"][n] = blk
            self.branches["B"][n] = blk
            prev = blk["hash"]
        base_tip = prev
        for br, txs in (("A", BRANCH_A_TXS), ("B", BRANCH_B_TXS)):
            prev = base_tip
            for n in range(FORK_START, FORK_END + 1):
                blk = self._make_block(n, prev, _ts(n), txs.get(n, []), br)
                self.branches[br][n] = blk
                prev = blk["hash"]
        self.head = FORK_END

    def _make_block(self, number, parent_hash, timestamp, tx_specs, branch):
        tx_hashes = []
        for i, spec in enumerate(tx_specs):
            payload = json.dumps(spec, sort_keys=True, separators=(",", ":"))
            th = "0x" + hashlib.sha256(
                f"imdtx:{branch}:{number}:{i}:{payload}".encode()).hexdigest()
            tx_hashes.append(th)
        bh = _block_hash(number, parent_hash, timestamp, tx_hashes)
        txs = []
        for i, (spec, th) in enumerate(zip(tx_specs, tx_hashes)):
            logs = []
            for j, item in enumerate(spec):
                name, args = item[0], item[1]
                logs.append(make_log(number, bh, parent_hash, th, i, j, ESCROW, name, args))
            txs.append({"index": i, "hash": th, "logs": logs})
        return {"number": int(number), "hash": bh, "parent_hash": parent_hash,
                "timestamp": int(timestamp), "txs": txs}

    # -- node-facing API -----------------------------------------------------

    def reorg(self):
        """The node switches to branch B: a five-block reorg of heights 10..14."""
        self.canonical = "B"

    def block(self, number: int, branch: str | None = None):
        b = branch or self.canonical
        return copy.deepcopy(self.branches[b][number])

    def block_hash(self, number: int, branch: str | None = None) -> str:
        b = branch or self.canonical
        if number not in self.branches[b]:
            raise KeyError(f"height {number} not on branch {b}")
        return self.branches[b][number]["hash"]

    def get_batch(self, start: int, end: int, branch: str | None = None):
        b = branch or self.canonical
        return [copy.deepcopy(self.branches[b][n]) for n in range(start, end + 1)]

    def all_logs(self, branch: str | None = None):
        b = branch or self.canonical
        out = []
        for n in sorted(self.branches[b]):
            for tx in self.branches[b][n]["txs"]:
                out.extend(tx["logs"])
        return out

    def describe(self):
        return {
            "fixture_version": FIXTURE_VERSION,
            "canonical": self.canonical,
            "head": self.head,
            "escrow": ESCROW,
            "common_ancestor": FORK_START - 1,
            "fork_range": [FORK_START, FORK_END],
            "branch_A_hashes": {n: self.branches["A"][n]["hash"] for n in range(FORK_START, FORK_END + 1)},
            "branch_B_hashes": {n: self.branches["B"][n]["hash"] for n in range(FORK_START, FORK_END + 1)},
        }


if __name__ == "__main__":
    import sys
    branch = sys.argv[1] if len(sys.argv) > 1 else "A"
    print(json.dumps(ChainFixture(canonical=branch).describe(), indent=2, sort_keys=True))
