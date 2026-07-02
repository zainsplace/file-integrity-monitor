#!/usr/bin/env python3
"""Threat-model-aware file integrity monitor.

Subcommands:
    create   Build an HMAC-signed baseline over a set of files/directories.
    verify   Check that the baseline's own signature is intact.
    scan     Verify the baseline, then diff the live filesystem against it.

The HMAC key is loaded from the FIM_KEY environment variable or a --key-file
path. It is never hardcoded and never written into the baseline.
"""

import argparse
import hashlib
import hmac
import json
import os
import stat
import sys

BASELINE_VERSION = 1
_HASH_CHUNK = 1024 * 1024


class EntryError(Exception):
    """Raised when a single path cannot be turned into an entry."""


def load_key(key_file):
    """Return the HMAC key as bytes, or exit if it cannot be found."""
    if key_file:
        try:
            with open(key_file, "rb") as fh:
                key = fh.read()
        except OSError as exc:
            sys.exit(f"error: cannot read key file {key_file!r}: {exc}")
        if key.endswith(b"\n"):
            key = key[:-1]
    else:
        env = os.environ.get("FIM_KEY")
        if env is None:
            sys.exit(
                "error: no key provided. Set FIM_KEY in the environment or pass "
                "--key-file."
            )
        key = env.encode("utf-8")

    if len(key) < 16:
        sys.exit("error: key is too short; use at least 16 bytes of key material.")
    return key


def build_entry(path):
    """Build a baseline entry for the object at path, or None if untracked."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise EntryError(f"cannot lstat {path!r}: {exc}") from exc

    mode = st.st_mode
    entry = {
        "path": os.path.normpath(path),
        "mode": stat.S_IMODE(mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "inode": st.st_ino,
    }

    if stat.S_ISREG(mode):
        entry["type"] = "file"
        entry["size"] = st.st_size
        entry["mtime"] = st.st_mtime
        entry["sha256"] = hash_file(path)
    elif stat.S_ISLNK(mode):
        entry["type"] = "symlink"
        entry["mtime"] = st.st_mtime
        try:
            entry["target"] = os.readlink(path)
        except OSError as exc:
            raise EntryError(f"cannot readlink {path!r}: {exc}") from exc
    elif stat.S_ISDIR(mode):
        entry["type"] = "dir"
    else:
        return None

    return entry


def hash_file(path):
    """Return the hex SHA-256 of a file's contents, or None if unreadable."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None

    digest = hashlib.sha256()
    try:
        with os.fdopen(fd, "rb") as fh:
            for chunk in iter(lambda: fh.read(_HASH_CHUNK), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def collect_entries(targets):
    """Walk targets and return (entries, errors) without following symlinks."""
    entries = []
    errors = []
    for target in targets:
        if not os.path.lexists(target):
            errors.append(f"target does not exist: {target!r}")
            continue

        if os.path.islink(target) or not os.path.isdir(target):
            _try_append(entries, errors, target)
            continue

        for root, dirs, files in os.walk(target, followlinks=False):
            _try_append(entries, errors, root)

            real_dirs = []
            for d in dirs:
                dpath = os.path.join(root, d)
                if os.path.islink(dpath):
                    _try_append(entries, errors, dpath)
                else:
                    real_dirs.append(d)
            dirs[:] = real_dirs

            for name in files:
                _try_append(entries, errors, os.path.join(root, name))

    return entries, errors


def _try_append(entries, errors, path):
    try:
        entry = build_entry(path)
    except EntryError as exc:
        errors.append(str(exc))
        return
    if entry is not None:
        entries.append(entry)


def canonical_payload(entries):
    """Produce the deterministic bytes that get signed."""
    ordered = sorted(entries, key=lambda e: e["path"])
    payload = {"version": BASELINE_VERSION, "entries": ordered}
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sign(key, entries):
    """Return the hex HMAC-SHA256 over the canonical payload."""
    return hmac.new(key, canonical_payload(entries), hashlib.sha256).hexdigest()


def write_baseline(path, entries, signature):
    """Write the baseline atomically as human-readable JSON."""
    document = {
        "version": BASELINE_VERSION,
        "algorithm": "HMAC-SHA256",
        "entries": entries,
        "signature": signature,
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, path)


def read_baseline(path):
    """Load and minimally validate a baseline document from disk."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            document = json.load(fh)
    except OSError as exc:
        sys.exit(f"error: cannot read baseline {path!r}: {exc}")
    except json.JSONDecodeError as exc:
        sys.exit(f"error: baseline {path!r} is not valid JSON: {exc}")

    for field in ("entries", "signature"):
        if field not in document:
            sys.exit(f"error: baseline {path!r} is missing required field {field!r}.")
    if not isinstance(document["entries"], list):
        sys.exit(f"error: baseline {path!r} has a malformed 'entries' field.")
    return document


def verify_signature(key, document):
    """Constant-time compare the recomputed HMAC against the stored signature."""
    expected = sign(key, document["entries"])
    return hmac.compare_digest(expected, str(document["signature"]))


_FIELD_CLASS = {
    "sha256": "content",
    "size": "content",
    "type": "content",
    "target": "content",
    "mode": "permissions",
    "uid": "owner",
    "gid": "owner",
    "mtime": "mtime",
    "inode": "inode",
}


def diff(baseline_entries, current_entries):
    """Compare two entry lists by path and classify every difference."""
    base_by_path = {e["path"]: e for e in baseline_entries}
    curr_by_path = {e["path"]: e for e in current_entries}

    base_paths = set(base_by_path)
    curr_paths = set(curr_by_path)

    added = sorted(curr_paths - base_paths)
    removed = sorted(base_paths - curr_paths)

    modified = []
    for path in sorted(base_paths & curr_paths):
        b = base_by_path[path]
        c = curr_by_path[path]
        changed_fields = {}
        for field in sorted(set(b) | set(c)):
            if field == "path":
                continue
            if b.get(field) != c.get(field):
                cls = _FIELD_CLASS.get(field, "other")
                changed_fields.setdefault(cls, []).append(
                    {"field": field, "baseline": b.get(field), "current": c.get(field)}
                )
        if changed_fields:
            modified.append({"path": path, "classes": changed_fields})

    return {"added": added, "removed": removed, "modified": modified}


def cmd_create(args):
    key = load_key(args.key_file)
    entries, errors = collect_entries(args.targets)
    for err in errors:
        print(f"warning: {err}", file=sys.stderr)

    signature = sign(key, entries)
    write_baseline(args.baseline, entries, signature)
    print(f"baseline written: {args.baseline}")
    print(f"  entries: {len(entries)}")
    print(f"  signature (HMAC-SHA256): {signature}")
    if errors:
        print(f"  {len(errors)} path(s) skipped -- see warnings above.")
    return 0


def cmd_verify(args):
    key = load_key(args.key_file)
    document = read_baseline(args.baseline)
    if verify_signature(key, document):
        print(f"OK: baseline {args.baseline} signature is intact.")
        return 0
    print(
        f"FAIL: baseline {args.baseline} signature is INVALID. "
        "The baseline was modified, or the wrong key was supplied.",
        file=sys.stderr,
    )
    return 2


def cmd_scan(args):
    key = load_key(args.key_file)
    document = read_baseline(args.baseline)

    if not verify_signature(key, document):
        print(
            f"ABORT: baseline {args.baseline} failed signature verification. "
            "Refusing to scan against an untrusted baseline.",
            file=sys.stderr,
        )
        return 2

    current, errors = collect_entries(args.targets)
    for err in errors:
        print(f"warning: {err}", file=sys.stderr)

    result = diff(document["entries"], current)

    if args.json:
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        _print_scan_human(result)

    drift = result["added"] or result["removed"] or result["modified"]
    return 1 if drift else 0


def _print_scan_human(result):
    if not (result["added"] or result["removed"] or result["modified"]):
        print("OK: no changes; filesystem matches the verified baseline.")
        return

    for path in result["added"]:
        print(f"ADDED    {path}")
    for path in result["removed"]:
        print(f"REMOVED  {path}")
    for item in result["modified"]:
        classes = ",".join(sorted(item["classes"]))
        print(f"MODIFIED {item['path']}  [{classes}]")
        for cls, changes in sorted(item["classes"].items()):
            for change in changes:
                print(
                    f"           {cls}: {change['field']}  "
                    f"{_fmt_value(change['field'], change['baseline'])} -> "
                    f"{_fmt_value(change['field'], change['current'])}"
                )


def _fmt_value(field, value):
    if field == "mode" and isinstance(value, int):
        return oct(value)
    return repr(value)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="fim",
        description="Threat-model-aware file integrity monitor.",
    )
    parser.add_argument(
        "--key-file",
        metavar="PATH",
        help="Path to a file containing the HMAC key. Falls back to $FIM_KEY.",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Build a signed baseline.")
    p_create.add_argument("--baseline", required=True, help="Output baseline path.")
    p_create.add_argument("targets", nargs="+", help="Files/directories to baseline.")
    p_create.set_defaults(func=cmd_create)

    p_verify = sub.add_parser("verify", help="Check the baseline's own signature.")
    p_verify.add_argument("--baseline", required=True, help="Baseline path to verify.")
    p_verify.set_defaults(func=cmd_verify)

    p_scan = sub.add_parser(
        "scan", help="Verify the baseline, then diff the live filesystem against it."
    )
    p_scan.add_argument("--baseline", required=True, help="Baseline path to scan against.")
    p_scan.add_argument("targets", nargs="+", help="Files/directories to re-scan.")
    p_scan.add_argument(
        "--json", action="store_true", help="Emit the diff as JSON instead of text."
    )
    p_scan.set_defaults(func=cmd_scan)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
