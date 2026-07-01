# Design Notes

Key decisions behind the implementation and the alternatives that were
considered and rejected.

## Key decisions

1. **Sign a `{version, entries}` payload, not just the entries.** Signing only
   the entries would leave the format version unauthenticated, which is a
   downgrade-attack surface (rewrite the version, aim the baseline at a lenient
   parser). Folding the version into the signed payload closes that at no cost.

2. **Canonical serialization = sort entries by path + `json.dumps(sort_keys,
   no-whitespace)`.** Determinism is both a correctness and a security property:
   the signature must be a function of state alone, not of walk order or JSON
   formatting. Verification re-derives the canonical bytes from the parsed
   entries and ignores the on-disk formatting, so reformatting the baseline JSON
   changes nothing.

3. **Split `st_mode` into `type` + `mode`.** Type bits and permission bits are
   different attacks — a file→symlink swap vs a setuid chmod. Storing them
   separately lets `scan` name exactly which happened.

4. **A field-to-class table drives the diff output** (`content / permissions /
   owner / mtime / inode`). Reporting *what class* of change occurred is what
   tells a responder "trojan" vs "privilege escalation" vs "metadata fiddling."
   A bare "file differs" would be nearly useless.

5. **`scan` verifies the signature first and aborts on failure.** Diffing
   against an unauthenticated baseline is diffing against attacker-controlled
   data.

6. **`hmac.compare_digest` for the signature check**, with a single
   "signature invalid" message that does not distinguish wrong-key from
   tampered-data. Both are anti-oracle measures.

7. **Symlinks: `lstat` + `readlink`, never followed; `followlinks=False`;
   `O_NOFOLLOW` on hashing.** Following is an attack vector (redirect hashing,
   DoS the walk, TOCTOU). Symlinks are recorded as metadata instead.

8. **Key from `--key-file` or `$FIM_KEY` only, 16-byte minimum, no default.** A
   default or hardcoded key is a non-secret. No key is a hard error, never a
   silent fallback.

9. **Atomic baseline write (temp + `os.replace`).** A half-written baseline that
   later reads as "tampered" is a false alarm; atomic rename prevents it.

## Alternatives considered and rejected

- **Encrypt the baseline instead of / in addition to signing.** The threat is
  integrity, not secrecy — the list of watched files and their hashes is not
  sensitive; an attacker forging it is. HMAC is the right primitive; encryption
  would add key-management pain for no gain here. (If the file list itself were
  sensitive, that trade-off would flip.)

- **Digital signatures (Ed25519/RSA) instead of HMAC.** Asymmetric signing would
  let a low-trust monitored host verify with only a public key while the private
  key stays on a trusted host — genuinely better for the "key on the monitored
  box" limitation. HMAC keeps the tool small and self-contained; the asymmetric
  design is the first thing to change for a production deployment.

- **Store mtime as an integer / drop it.** Dropping it loses a useful tamper
  tell: the inconsistent case (content changed, mtime unchanged). Kept at full
  float precision so truncation does not manufacture spurious diffs.

- **Merkle tree / per-directory rollup hashes.** Would help incremental re-scan
  performance and localize changes, but adds real complexity. A flat,
  path-keyed entry list is simpler.

- **SQLite baseline instead of JSON.** Faster and more scalable for very large
  trees, but opaque. Signed, human-readable JSON is easier to inspect and reason
  about; SQLite would win at scale.

- **Follow symlinks with realpath normalization + scope-fencing.** Strictly more
  attack surface (TOCTOU, DoS, scope escape) for no benefit. Not following is
  both simpler and safer.

- **Distinguish "wrong key" from "tampered baseline" for better UX.** Rejected
  as an oracle. The small usability loss is worth denying the attacker feedback.

## Known gaps

- No incremental scanning / no persistence of per-run results.
- No handling of hardlinks as an aliasing concern beyond the inode signal.
- On Windows, `uid`/`gid` are 0 and `mode`/`inode` semantics are limited (these
  are Unix concepts); `O_NOFOLLOW` is absent, so the symlink TOCTOU narrowing
  does not apply there. The tool runs, but its guarantees are Unix-centric.
- Detection only, never prevention — see THREATMODEL.md.
