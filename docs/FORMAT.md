# Repository and encryption format

This document describes the on-storage format of an rs-shield repository,
with a focus on encryption format **v3**. Every backend (local directory,
S3-compatible bucket, in-memory storage) holds the same objects under the same
keys. All integers are big-endian.

## Repository layout

| Key | Content |
|-----|---------|
| `keys/repo.key` | Repository key file (JSON). Only present in v3 repositories. |
| `keys/repo.key.bak-<ts>` | Temporary copy that exists only while a password change runs (or after one failed). |
| `snapshots/<name>.toml` | Snapshot manifest: zstd(TOML), encrypted when the backup is encrypted. |
| `data/clear/<hash>` | Unencrypted object: raw or zstd-compressed content. |
| `data/enc/<hash>` | Encrypted object (legacy v1, v2 or v3 blob). |
| `locks/<uuid>.lock` | Repository locks (JSON). |

`<hash>` is the BLAKE3 hash (64 lowercase hex characters) of the object's
**plaintext**: the whole file, or one chunk of a file larger than 64 MiB
(chunks are 32 MiB). Identical content is stored once (deduplication).

A manifest maps each relative path to a `FileMetadata` entry: `hash`,
`encrypted`, `compressed`, `stored_size`, `stored_hash`, optional `chunks`
(list of `{hash, stored_size, stored_hash}`) and, since v3, `size` (the
plaintext size, used to bound decompression on restore and verify).

## Blob formats

Readers detect the format of every encrypted blob independently, so one
manifest can reference v1, v2 and v3 objects at the same time.

### v1 (legacy, read only)

```
salt (16) | nonce (12) | ciphertext | tag (16)
```

Key = PBKDF2-HMAC-SHA256(password, salt, 600 000 iterations), 32 bytes;
AES-256-GCM with an empty AAD.

### v2 (read only since v3)

```
"RSBENCv2" (8) | iterations u32 (4) | salt (16) | nonce (12) | ciphertext | tag (16)
```

Key = PBKDF2-HMAC-SHA256(password, salt, iterations); AAD = the 12-byte
header. Readers accept 100 000 to 600 000 iterations (600 000 is the only value
ever written). A header outside that range is not parsed as v2, so a malicious
header cannot request a huge iteration count. One decryption context performs
at most 1024 distinct (salt, iterations) derivations
(`CryptoError::KdfLimitExceeded`).

### v3 (written by this version)

```
header = "RSBENCv3" (8) | flags u8 (1) | blob salt (32) | chunk size u32 (4)    = 45 bytes
body   = chunk_0 | chunk_1 | ... | chunk_n                                     (n >= 0)
chunk  = AES-256-GCM ciphertext of the chunk plaintext | tag (16)
```

* **flags**: must be `0x00`. Unknown flags are rejected.
* **blob salt**: 32 random bytes per blob.
* **chunk size**: plaintext bytes per chunk. Writers use 1 MiB (1 048 576).
  Readers accept 16 to 16 MiB, which bounds the memory a reader allocates for
  one chunk whatever the (untrusted) header says.
* **Chunking**: every non-final chunk holds exactly `chunk size` plaintext
  bytes. The final chunk holds 0 to `chunk size` bytes. An empty payload is a
  single, empty, final chunk (header + 16-byte tag = 61 bytes). Stored length:
  `45 + len + 16 * max(1, ceil(len / chunk size))`.
* **Blob key**: `K = HKDF-SHA256(IKM = DEK, salt = blob salt, info = "rsb v3 blob")`,
  32 bytes (RFC 5869). The DEK is the repository key (see below).
* **Nonce** of chunk *i* (12 bytes): `i as u64 (8) | 00 00 00 | last (1)`, where
  `last` is `01` for the final chunk and `00` otherwise. No random prefix is
  needed because every blob has its own key.
* **AAD** of every chunk: `header (45 bytes) | object id (UTF-8)`.
* **Object id**: the key the blob is stored under, minus the directory. For a
  data object it is the content hash (`<hash>` of `data/enc/<hash>`). For a
  manifest it is the full storage key (`snapshots/<name>.toml`).

A reader decides whether a chunk is the final one by looking ahead: a
full-size chunk followed by more bytes is non-final, and anything else is
final. This means that:

| Attack | Result |
|--------|--------|
| Header byte changed (flags, salt, chunk size) | Header bounds error, or tag mismatch (header is AAD and the salt selects the key). |
| Ciphertext or tag byte changed | Tag mismatch. |
| Chunks reordered | Tag mismatch (counter in the nonce). |
| Final chunk removed (truncation at a chunk boundary) | Tag mismatch: the new last chunk was sealed as non-final. |
| Data appended after the final chunk | Tag mismatch: the real final chunk is no longer read as last. |
| Truncated inside a chunk | Tag mismatch, or `Malformed` when fewer than 16 bytes remain. |
| Header only, no chunk | `Malformed` (missing final chunk). |
| Blob copied or renamed to another object id | Tag mismatch (object id is AAD). |

Errors are typed: `CryptoError::AuthenticationFailed` for tag mismatches and
`CryptoError::Malformed` for structural errors. Both map to
`RsbError::Crypto { kind: AuthenticationFailed | Corrupt }`.

**Why the content hash and not the file path.** Binding the content hash
stops an attacker with write access to the repository from swapping two valid
objects without being detected, and still keeps deduplication: identical
content from any path, snapshot or session maps to the same object and opens
with the same id. Restore then checks the plaintext against the content hash
(and every chunk hash), so a substituted object cannot be passed off as
another file. Manifests are bound to their snapshot key, so a manifest cannot
be renamed to pose as a different (e.g. newer) snapshot.

**Streaming.** Backups compress and then encrypt in a pipeline
(zstd, then the v3 chunk encryptor, then a hasher, then a spool). The spool is
held in memory up to 8 MiB and then spills to a temporary file, which is
uploaded with `Storage::write_file` (a plain PutObject of known length on S3,
copy into a temp file plus atomic rename on local storage). Restores decrypt
v3 chunk by chunk. Memory per blob is one ciphertext chunk plus two 1 MiB
buffers, and every chunk is authenticated before it is written. Output goes to
a temp file that replaces the target only after the full-file hash matches,
and the temp file is deleted on any error. v1/v2 blobs are still read whole
(one-shot GCM cannot be verified incrementally).

## Repository key file (`keys/repo.key`)

```json
{
  "format": "rsb-repo-key",
  "version": 3,
  "kdf": {
    "algorithm": "argon2id", "version": 19,
    "m_cost_kib": 65536, "t_cost": 3, "p_cost": 1,
    "salt": "<base64, 16 bytes>"
  },
  "wrapped_dek": {
    "algorithm": "aes-256-gcm",
    "nonce": "<base64, 12 bytes>",
    "ciphertext": "<base64, 32-byte DEK + 16-byte tag>"
  },
  "legacy_secret": { "algorithm": "aes-256-gcm", "nonce": "...", "ciphertext": "..." },
  "created_at": "<RFC 3339>",
  "updated_at": "<RFC 3339, after a password change>"
}
```

* **DEK**: 32 random bytes, generated once per repository. It never changes.
* **KEK** = Argon2id v1.3 (password, salt, m_cost KiB, t_cost, p_cost), 32 bytes.
* **DEK wrap**: AES-256-GCM(KEK, random 12-byte nonce, DEK), with
  **AAD** = `"RSBKEYv3" | 0x00000013 | m_cost u32 | t_cost u32 | p_cost u32 | salt (16)`
  (40 bytes). Changing the stored parameters (for example to weaken them)
  makes the unwrap fail.
* **Parameters**: default m = 64 MiB, t = 3, p = 1. When a key file is created
  or rewrapped, the minimum is m ≥ 19 MiB (19 456 KiB) and t ≥ 2. When a key
  file is read, the parameters must stay within upper bounds against DoS:
  m ≤ 4 GiB, 1 ≤ t ≤ 10, 1 ≤ p ≤ 16. Weaker stored parameters are accepted.
* **Wrong password**: the unwrap fails with
  `RsbError::Crypto { kind: AuthenticationFailed }` before any blob or
  manifest is read (backup, restore, verify, prune). Prune checks this before
  it deletes anything.
* **legacy_secret** (only in repositories migrated from v1/v2): the password
  that encrypted the pre-v3 objects, sealed with AES-256-GCM under
  `HKDF-SHA256(IKM = DEK, salt = "", info = "rsb v3 legacy secret")`, with a
  random nonce and AAD `"RSBKEYv3 legacy secret"`. A v1/v2 key is
  PBKDF2(password, per-session salt) and cannot be rewrapped. Keeping that
  password under the DEK means old objects stay readable after
  `rsb key change-password`.

### Creation

The first encrypted backup of a repository without a key file creates one.
`rsb key init` does the same explicitly. Creation:

1. takes the exclusive repository lock (two first backups cannot create two
   different keys) and checks again whether the key file exists;
2. if the repository already holds encrypted v1/v2 snapshots, checks that the
   password opens the newest one (otherwise it fails with
   `AuthenticationFailed`, so a mistyped password cannot split the repository
   between two passwords) and stores that password as `legacy_secret`. If a
   v3 snapshot exists but the key file is missing, it refuses;
3. writes the file, reads it back and checks that it opens to the same DEK
   before any blob is encrypted with it.

A dry run never creates the file.

### Password change (`rsb key change-password`)

Under the exclusive lock: unwrap with the old password, wrap the same DEK
with a new salt and nonce (and optionally new parameters), write a copy of the
current file to `keys/repo.key.bak-<timestamp>`, write the new file (an atomic
replacement per object on every backend), read it back and unwrap it with the
new password, then delete the copy. If the check fails, the previous file is
written back and the copy is kept. No blob is rewritten.

## Compatibility matrix

| Repository / object | Without `keys/repo.key` | With `keys/repo.key` |
|---------------------|-------------------------|----------------------|
| Clear objects/manifests | read and write | read and write |
| v1 object | read (password) | read (`legacy_secret`, else password) |
| v2 object / manifest | read (password) | read (`legacy_secret`, else password) |
| v3 object / manifest | error `RepoKeyRequired` | read and write (DEK) |
| New encrypted objects | v3 (the key file is created first) | v3 |

Older versions of rs-shield cannot read v3 objects. Dedup reuses existing
v1/v2 objects as they are (they are classified by their framing and never
rewritten), so one manifest can mix formats. Restore, verify and prune handle
every format per object.

## Limits on untrusted data

* Manifests: at most 256 MiB, both stored and decompressed.
* Data objects: decompression stops at `FileMetadata::size`. When that field
  is missing (older manifests), it stops at 4 GiB for a single object and at
  512 MiB per chunk (the largest sizes older versions wrote). Restore stops
  writing and deletes its temp file as soon as the output passes the bound
  (`io::ErrorKind::FileTooLarge`).

## Threat model notes

Protected: the confidentiality and integrity of file contents and manifests
(paths, sizes, hashes, timestamps inside the manifest) against anyone who can
read or modify the storage but does not know the password or the DEK. This
covers tampering, truncation, reordering, object swapping and manifest
renaming.

Not hidden from someone with storage access:

* the number of objects and snapshots, each object's stored size (and so the
  approximate file or chunk size), and snapshot names (timestamps);
* **dedup equality**: object names are plaintext content hashes. Identical
  content produces the same object name across snapshots and repositories,
  and anyone who can guess a file's content can confirm whether the
  repository holds it (BLAKE3 of the plaintext);
* which files are encrypted (`data/enc` vs `data/clear`) when
  `encrypt_patterns` encrypts only some files;
* the access pattern (which objects a backup or restore touches).

Operational notes:

* **Losing `keys/repo.key` makes every v3 object unreadable.** Keep a copy of
  it with the password. It is useless without the password.
* A password change does not rotate the DEK. A copy of the old key file
  (backup copies, S3 object versioning) plus the old password still yields the
  DEK. If the DEK itself may be compromised, start a new repository.
* The DEK and KEK bytes and the passwords are zeroized after use. The AES key
  schedules held inside `ring` are not zeroized (ring does not expose that).
* Argon2id with the defaults takes about 135 ms and 64 MiB per unlock
  (measured on Apple silicon). Each operation unlocks once.
