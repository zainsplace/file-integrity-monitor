# fim — threat-model-aware file integrity monitor

A small file integrity monitor in Python (standard library only). It builds an
HMAC-signed baseline of a set of files, verifies that baseline hasn't been
tampered with, and reports exactly what changed on the filesystem since — added,
removed, or modified, and for modified files *which* fields differ (content,
permissions, owner, mtime, inode).

See [THREATMODEL.md](THREATMODEL.md) for the attacks it defends against and its
limitations, and [NOTES.md](NOTES.md) for the design rationale.

## Requirements

- Python 3.8+
- No third-party dependencies.

## The key

The HMAC key is loaded from the `FIM_KEY` environment variable or a `--key-file`
path. It is never hardcoded and never stored in the baseline. Use at least 16
bytes of key material.

```sh
export FIM_KEY="$(head -c 32 /dev/urandom | base64)"
# or
python fim.py --key-file /path/to/key.bin <command> ...
```

## Usage

```sh
# Build a signed baseline for one or more targets
python fim.py create --baseline base.json /etc /usr/bin

# Check that the baseline's own signature is intact
python fim.py verify --baseline base.json

# Verify the baseline, then diff the live filesystem against it
python fim.py scan --baseline base.json /etc /usr/bin

# Machine-readable diff
python fim.py scan --baseline base.json /etc /usr/bin --json
```

### Example

```
$ python fim.py scan --baseline base.json demo
ADDED    demo/c.txt
REMOVED  demo/sub/b.txt
MODIFIED demo/a.txt  [content,mtime]
           content: sha256  '8ed3f6...' -> 'd97aab...'
           content: size  5 -> 14
           mtime: mtime  1782911193.67 -> 1782911205.29
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success / no changes detected |
| 1 | `scan` detected drift, or a usage/key error |
| 2 | Signature verification failed (`verify`/`scan`) |

The non-zero exit on drift makes `scan` composable in cron jobs and CI.

## Notes on portability

`uid`, `gid`, `mode`, `inode`, and `O_NOFOLLOW` are Unix concepts. The tool runs
on Windows but reports `uid`/`gid` as 0 and cannot apply the symlink-hashing
race protection there; its guarantees are Unix-centric.
