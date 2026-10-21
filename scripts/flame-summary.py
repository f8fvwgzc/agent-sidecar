#!/usr/bin/env python3
"""Summarise folded CPU stacks (the .folded files scripts/profile.sh writes).

    python3 -I scripts/flame-summary.py .local/profile/before/orders.folded [--top 25]
    python3 -I scripts/flame-summary.py BEFORE.folded --compare AFTER.folded

Prints the share of samples per subsystem, the hottest frames by self time, and the hottest
agent-sidecar functions by inclusive time. Only the standard library is used.
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

# Subsystem of a frame name, first match wins (order matters).
CATEGORIES = [
    ("TLS (rustls, ring)", r"\b(rustls|ring)::|tokio_rustls"),
    ("gRPC framing (tonic, prost, h2)", r"\b(tonic|prost|h2)::"),
    ("HTTP (hyper, axum, reqwest)", r"\b(hyper|hyper_util|axum|reqwest|http_body)::"),
    ("JSON (serde_json)", r"serde_json::"),
    ("YAML (serde_yaml)", r"serde_yaml"),
    ("regex", r"\bregex(_automata|_syntax)?::"),
    ("hashing (sha2)", r"\bsha2::|digest::"),
    ("logging (tracing)", r"\btracing(_subscriber|_core)?::"),
    ("allocation", r"\b(malloc|free|realloc|calloc|_malloc|_free|szone_|nanov2_|tiny_|mi_|je_)|alloc::alloc::"),
    ("audit (agentsc_common::audit)", r"agentsc_common::audit"),
    ("charter (agentsc_charter)", r"agentsc_charter::"),
    ("sidecar (agentscd)", r"\bagentscd::"),
    ("async runtime (tokio)", r"\btokio::"),
    ("syscalls (write/read/kevent)", r"\b(write|read|writev|readv|kevent|__psynch|sendto|recvfrom|__sendmsg|__recvmsg)\b"),
]


def load(path: Path) -> list[tuple[list[str], int]]:
    stacks = []
    for line in path.read_text().splitlines():
        stack, _, count = line.rpartition(" ")
        if not stack or not count.isdigit():
            continue
        stacks.append((stack.split(";"), int(count)))
    return stacks


def short(name: str) -> str:
    name = re.sub(r"::h[0-9a-f]{16}$", "", name)
    name = re.sub(r"<[^<>]*>", "<…>", name)
    return name[:140]


def category(frames: list[str]) -> str:
    # The deepest frame that belongs to a known subsystem decides.
    for frame in reversed(frames):
        for label, pattern in CATEGORIES:
            if re.search(pattern, frame):
                return label
    return "other"


def summarise(stacks, top: int):
    total = sum(c for _, c in stacks) or 1
    cats, selfs, incl = Counter(), Counter(), Counter()
    for frames, count in stacks:
        cats[category(frames[1:])] += count
        if len(frames) > 1:
            selfs[short(frames[-1])] += count
        seen = set()
        for f in frames[1:]:
            if "agentsc" in f:
                s = short(f)
                if s not in seen:
                    incl[s] += count
                    seen.add(s)
    return total, cats, selfs.most_common(top), incl.most_common(top)


def pct(n: int, total: int) -> str:
    return f"{100 * n / total:5.1f}%"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("folded", type=Path)
    ap.add_argument("--compare", type=Path)
    ap.add_argument("--top", type=int, default=20)
    a = ap.parse_args()
    total, cats, selfs, incl = summarise(load(a.folded), a.top)
    print(f"{a.folded}: {total} samples")
    if a.compare:
        t2, c2, _, _ = summarise(load(a.compare), a.top)
        print(f"{a.compare}: {t2} samples\n")
        print(f"{'subsystem':40} {'before':>8} {'after':>8}")
        for label in sorted(set(cats) | set(c2), key=lambda k: -cats.get(k, 0)):
            print(f"{label:40} {pct(cats.get(label, 0), total):>8} {pct(c2.get(label, 0), t2):>8}")
        return
    print("\nshare of samples by subsystem (deepest known frame)")
    for label, n in cats.most_common():
        print(f"  {pct(n, total)}  {label}")
    print(f"\nhottest frames by self time (top {a.top})")
    for name, n in selfs:
        print(f"  {pct(n, total)}  {name}")
    print(f"\nhottest agent-sidecar functions, inclusive (top {a.top})")
    for name, n in incl:
        print(f"  {pct(n, total)}  {name}")


if __name__ == "__main__":
    main()
