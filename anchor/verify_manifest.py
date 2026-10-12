#!/usr/bin/env python3
"""
Independent re-implementation of the csd-anchor/v1 hashing spec.

It recomputes every unit's tree hash from a git checkout and checks it against
a manifest, so nobody has to trust the Rust tool (or whoever ran it).

    python3 verify_manifest.py --repo /path/to/math --manifest manifest.json

Spec:
    leaf(file)  = sha256d(blob bytes)
    tree(files) = sha256d(b"csd-anchor/tree/v1\\0" + b"".join(path + b"\\0" + leaf
                          for each file in ascending path-byte order))
    root payload_hash (on chain) = sha256d(exact bytes of manifest.json)

Only the Python standard library and `git` are needed.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from collections import defaultdict


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def list_files(repo, commit):
    out = subprocess.run(
        ["git", "-C", repo, "ls-tree", "-r", "-z", "--full-tree", commit],
        check=True, capture_output=True,
    ).stdout
    files = []
    for rec in out.split(b"\0"):
        if not rec:
            continue
        meta, path = rec.split(b"\t", 1)
        _mode, kind, oid = meta.decode().split(" ")
        files.append((path, kind, oid))
    files.sort(key=lambda f: f[0])
    return files


def leaves(repo, files):
    """Yield (path, leaf) using one `git cat-file --batch` process."""
    proc = subprocess.Popen(
        ["git", "-C", repo, "cat-file", "--batch"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    )
    blobs = [f for f in files if f[1] == "blob"]
    import threading

    def feed():
        for _, _, oid in blobs:
            proc.stdin.write(oid.encode() + b"\n")
        proc.stdin.close()

    threading.Thread(target=feed, daemon=True).start()
    for path, kind, oid in files:
        if kind != "blob":
            yield path, sha256d(f"gitlink:{oid}".encode())
            continue
        header = proc.stdout.readline().split()
        size = int(header[2])
        data = proc.stdout.read(size)
        proc.stdout.read(1)
        yield path, sha256d(data)
    proc.wait()


def unit_of(path: bytes, split):
    parts = path.split(b"/", 2)
    if parts[0].decode() in split and len(parts) == 3:
        return (parts[0] + b"/" + parts[1]).decode()
    return parts[0].decode()


def tree(items):
    h = hashlib.sha256()
    h.update(b"csd-anchor/tree/v1\0")
    for path, leaf in items:
        h.update(path + b"\0" + leaf)
    return hashlib.sha256(h.digest()).digest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--split", default="preprints", help="comma-separated")
    a = ap.parse_args()

    raw = open(a.manifest, "rb").read()
    m = json.loads(raw)
    commit = m["source"]["commit"]
    split = set(a.split.split(","))

    files = list_files(a.repo, commit)
    groups = defaultdict(list)
    everything = []
    for path, leaf in leaves(a.repo, files):
        groups[unit_of(path, split)].append((path, leaf))
        everything.append((path, leaf))

    errors = 0
    want = {u["path"]: u["tree_hash"] for u in m["units"]}
    for name in sorted(set(want) | set(groups)):
        got = "0x" + tree(groups.get(name, [])).hex() if name in groups else None
        if got != want.get(name):
            errors += 1
            print(f"MISMATCH {name}: manifest={want.get(name)} recomputed={got}")

    commit_hash = "0x" + tree(everything).hex()
    if commit_hash != m["commit_tree_hash"]:
        errors += 1
        print(f"MISMATCH commit_tree_hash: manifest={m['commit_tree_hash']} recomputed={commit_hash}")

    print(f"commit             {commit}")
    print(f"files              {len(files)}")
    print(f"units checked      {len(want)}")
    print(f"commit tree hash   {commit_hash}")
    print(f"root payload_hash  0x{sha256d(raw).hex()}   (compare with the on-chain root proposal)")
    print("OK" if errors == 0 else f"{errors} mismatches")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
