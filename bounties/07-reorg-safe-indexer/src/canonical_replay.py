"""Independent, from-genesis canonical replay -- the oracle for bounty #07.

This builds a *fresh* database by replaying the node's current canonical branch
straight through (genesis -> head) with the same Indexer, into a separate file.
The incremental, fault-injected database is then compared against this oracle
row-for-row.  Because both derive state from the same deterministic event set,
any divergence is a real indexing bug (an orphaned log, a duplicated event, a
stale derived row, a wrong checkpoint), never a fixture artefact.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .chainfixture import ChainFixture
from .indexer import Indexer


def replay(db_path, chain: ChainFixture):
    """Fresh DB: wipe, then index 0..head of chain.canonical in one pass."""
    p = Path(db_path)
    for f in (p, Path(str(p) + "-wal"), Path(str(p) + "-shm")):
        if f.exists():
            f.unlink()
    idx = Indexer(str(p), chain).connect()
    try:
        idx.index_to_head()
    finally:
        idx.close()
    return str(p)


def main(argv=None):
    ap = argparse.ArgumentParser(description="fresh canonical replay (oracle)")
    ap.add_argument("--db", required=True)
    ap.add_argument("--canonical-branch", default="A", choices=["A", "B"])
    args = ap.parse_args(argv)
    chain = ChainFixture(canonical=args.canonical_branch)
    replay(args.db, chain)
    print("canonical replay ->", os.path.basename(args.db), "branch", chain.canonical,
          "head", chain.head)


if __name__ == "__main__":
    sys.exit(main() or 0)
