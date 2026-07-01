# Threat Model

This document states what the FIM defends against, *how* each defense maps to a
specific attacker capability, and — honestly — where the whole scheme falls
over. A FIM that oversells itself is worse than none, because it buys false
confidence.

## Assumed attacker capabilities

We design against an attacker who has gained some level of access to the
monitored host and wants to make a persistent, hidden change:

- **A. File write.** Can create, modify, delete, and re-permission files in the
  monitored scope. This is the baseline capability — if they couldn't touch
  files, there'd be nothing to monitor.
- **B. Baseline tampering.** Can also read and rewrite the baseline file on
  disk (it lives on the same host).
- **C. Observation.** Can observe the tool running and measure how long its
  comparisons take (a timing side channel).

The **one** capability we assume the attacker does **not** have: reading the
HMAC key. See "Core limitation" below — this is load-bearing.

---

## Attack 1 — Re-baseline (attacker rewrites history)

**The attack.** Attacker with capability A modifies a watched file (say, plants
a backdoor in `/usr/bin/sshd`), then — knowing a FIM is watching — simply
regenerates the baseline so the new, malicious state becomes the "known good"
state. Under a naive FIM that just re-hashes and overwrites, the next scan is
clean. The tamper is laundered into the baseline.

**The defense.** The baseline is **HMAC-SHA256 signed** over a deterministic
serialization of its entries (`canonical_payload` in `fim.py`). Regenerating the
baseline requires producing a valid HMAC, which requires the key. An attacker
with capability B can rewrite the entries all they like, but cannot produce a
matching signature. `scan` **verifies the signature before it trusts a single
entry** and aborts if verification fails — so a re-baselined-but-unsigned (or
mis-signed) baseline is rejected outright rather than diffed against.

**Residual risk.** If the attacker can also run `create` *with the real key*
(e.g. the key is present in the environment of a process they control), this
defense evaporates. That's the core limitation, restated.

---

## Attack 2 — Metadata-only change (privilege escalation without touching bytes)

**The attack.** Attacker with capability A does **not** change a file's
contents — instead they `chmod 4755` a root-owned binary to add the setuid bit,
or `chown` a config file to a user they control. The SHA-256 of the contents is
unchanged. A content-only FIM (one that hashes bytes and nothing else) sees
nothing wrong, yet the host is now exploitable.

**The defense.** Each entry records **mode (permission bits), uid, and gid**
alongside the content hash, and the `scan` diff reports *which class* of field
changed — `permissions`, `owner`, `content`, `mtime`, or `inode` — separately.
A setuid-added-but-content-identical file is flagged as `[permissions]`; a
`chown` is flagged as `[owner]`. Splitting `st_mode` into a `type` field and a
`mode` (permission-bits-only) field is deliberate: it lets the tool say "only
the setuid bit changed" rather than a vague "mode differs".

**Also caught here:** the *inconsistent mtime* tell. An attacker who changes
content and then `touch -r`s the mtime back to hide the edit produces an entry
where `content` differs but `mtime` does not — visible in the classified diff.

---

## Attack 3 — File / inode swap (replace the object, not its bytes)

**The attack.** Two variants, both using capability A:

1. **Symlink swap.** Attacker replaces a monitored regular file (or directory)
   with a **symlink** pointing at an attacker-controlled or sensitive target. A
   FIM that *follows* symlinks would then hash whatever the link points at —
   potentially recording the wrong file as "good", or being walked into `/` for
   a denial-of-service. Worse, following symlinks during hashing opens a
   **TOCTOU race** (capability C + A): stat the real file, then the attacker
   swaps in a symlink before the open.

2. **Inode swap.** Attacker replaces a file wholesale (unlink + create, or
   rename another file over it) rather than editing it in place. If they can
   reconstruct identical content/mode/owner, the only surviving tell that the
   object was *replaced* rather than *edited* is that its **inode number**
   changed.

**The defense.**

- Symlinks are handled with `os.lstat` (never `os.stat`) and recorded via
  `os.readlink` — we capture *where the link points* as metadata and **never
  dereference it**. The filesystem walk sets `followlinks=False` and records
  symlinked directories as symlink entries instead of descending into them, so
  a planted symlink can neither redirect our hashing nor blow up our traversal.
- Hashing uses `os.open(..., O_NOFOLLOW)` where the platform supports it, so if
  a regular file is swapped for a symlink in the TOCTOU window, the open fails
  loudly instead of hashing an attacker-chosen target.
- The **inode** is stored per entry. A `[inode]`-only change on an otherwise
  identical file is the signature of a swap-in-place and is surfaced in the
  diff. (Inode changes are noisy on their own — normal editors rename temp
  files — so this is a *signal to investigate*, read in combination with the
  other classes, not a standalone alarm.)

---

## Cross-cutting defenses (not attack-specific)

- **Constant-time signature comparison.** `verify_signature` uses
  `hmac.compare_digest`, not `==`. A short-circuiting compare leaks, via timing
  (capability C), how many leading bytes of a submitted signature are correct,
  enabling byte-by-byte forgery. Constant-time compare closes that oracle.
- **No wrong-key vs tampered-data distinction.** `verify` reports a single
  "signature invalid" for both a bad key and modified data. Telling the attacker
  "correct key, wrong data" would itself be an oracle.
- **Downgrade resistance.** The format `version` is folded *inside* the signed
  payload, so an attacker cannot rewrite the version field to coax a lenient
  older parser into running against a new-format (or vice versa) baseline.
- **Deterministic serialization.** Entries are sorted by path and serialized
  with fixed key order and no whitespace before signing, so the signature is a
  stable function of *state*, not of walk order or JSON formatting. Without this
  the signature would be unstable and verification would false-alarm.

---

## Core limitation — this is the honest part

**If the HMAC key is compromised, the entire scheme fails.** Full stop.

An attacker who obtains the key can:

- forge a baseline that legitimises any malicious file state (defeats Attack 1),
- and do so such that both `verify` and `scan` report a clean, "intact" result.

Everything above reduces to the single assumption that **the attacker cannot
read the key**. That pushes the real security boundary *off the monitored host*:

- The key should be injected at scan time by a trusted orchestrator, or stored
  on a read-only, differently-owned mount — **not** sitting in a file next to
  the baseline that capability-A gives the attacker.
- Better still, the baseline and the verification should run on a **separate,
  more-trusted host** (the classic Tripwire model), so an attacker who owns the
  monitored box never sees the key at all.

Secondary honest caveats:

- **TOCTOU is only narrowed, not eliminated.** `O_NOFOLLOW` closes the
  symlink-swap race during hashing, but a sufficiently fast attacker racing the
  walk can still momentarily hide changes. A FIM samples state; it does not hold
  a lock on the filesystem.
- **mtime is attacker-controlled** and is treated only as a corroborating
  signal, never as proof.
- **This detects, it does not prevent.** By the time a scan runs, the tamper has
  already happened; the value is in *fast, trustworthy detection*, which is why
  the signature check must be unforgeable and must run first.
