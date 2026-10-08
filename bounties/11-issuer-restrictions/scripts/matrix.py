#!/usr/bin/env python3
"""Aggregate per-mode test results into a reviewed behaviour matrix."""
import json, pathlib

rows = []
for p in sorted(pathlib.Path("results").glob("mode-*.json")):
    rows.append(json.loads(p.read_text()))

order = {"supported": 0, "unsupported": 1}
rows.sort(key=lambda r: (order.get(r["class"], 2), r["mode"]))

pathlib.Path("results/matrix.json").write_text(json.dumps({"rows": rows, "count": len(rows)}, indent=2))

hdr = ["mode", "deposit", "award/refund while restricted", "withdraw", "credit preserved", "needs issuer action", "class"]
lines = ["| " + " | ".join(hdr) + " |", "|" + "---|" * len(hdr)]
for r in rows:
    lines.append("| " + " | ".join([
        f"`{r['mode']}`", r["deposit"], r["award_refund_while_restricted"], r["withdraw"],
        "yes" if r["failed_withdraw_preserves_credit"] else "no",
        "yes" if r["recovery_requires_issuer_action"] else "**no**",
        r["class"],
    ]) + " |")
pathlib.Path("results/matrix.md").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
