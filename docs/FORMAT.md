# Repository and encryption format

This document describes the on-storage format of an rs-shield repository,
with a focus on encryption format **v3**. Every backend (local directory,
S3-compatible bucket, in-memory storage) holds the same objects under the same
keys. All integers are big-endian.

## Repository layout

| Key | Content |
|-----|---------|
| `keys/repo.key` | Repository key file (JSON). Only present in v3 repositories. |
| `keys/repo.key.bak-<ts>` | Copy of the previous key file. Temporary while a password change, a migration or a rotation rewrites the key file (kept if that rewrite failed to verify); kept after `rsb key import --force`. |
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

* **flags**: `0x00`, or `0x01` (**key id**). Any other bit is rejected.
* **blob salt**: 32 bytes per blob. Without the key id flag they are all
  random. With it, the first 4 bytes are the **key id** of the DEK that
  encrypted the blob and the other 28 are random.
* **key id** = the first 4 bytes of
  `HKDF-SHA256(IKM = DEK, salt = "", info = "rsb v3 key id")`. It only tells
  a reader which DEK of the key file to use (see key rotation below). It is
  a PRF output, so it reveals nothing useful about the DEK.
* **chunk size**: plaintext bytes per chunk. Writers use 1 MiB (1 048 576).
  Readers accept 16 to 16 MiB, which bounds the memory a reader allocates for
  one chunk whatever the (untrusted) header says.
* **Chunking**: every non-final chunk holds exactly `chunk size` plaintext
  bytes. The final chunk holds 0 to `chunk size` bytes. An empty payload is a
  single, empty, final chunk (header + 16-byte tag = 61 bytes). Stored length:
  `45 + len + 16 * max(1, ceil(len / chunk size))`.
* **Blob key**: `K = HKDF-SHA256(IKM = DEK, salt = blob salt, info = "rsb v3 blob")`,
  32 bytes (RFC 5869). The DEK is the repository key (see below). The DEK is
  selected by the key id (flag `0x01`). A blob without the flag opens with
  the primary DEK of the key file (`wrapped_dek`).
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
| Header byte changed (flags, salt, key id, chunk size) | Header bounds error, unknown key id (reported as a tag mismatch), or tag mismatch (header is AAD and the salt selects the key). |
| Ciphertext or tag byte changed | Tag mismatch. |
| Chunks reordered | Tag mismatch (counter in the nonce). |
| Final chunk removed (truncation at a chunk boundary) | Tag mismatch: the new last chunk was sealed as non-final. |
| Data appended after the final chunk | Tag mismatch: the real final chunk is no longer read as last. |
| Truncated inside a chunk | Tag mismatch, or `Malformed` when fewer than 16 bytes remain. |
| Header only, no chunk | `Malformed` (missing final chunk). |
| Blob copied or renamed to another object id | Tag mismatch (object id is AAD). |

**Key id compatibility.** Writers set the key id flag on every blob since
this change. The header length, the chunk layout and the stored size are the
same with or without it, so readers of this version open blobs written
before the change (flag `0x00`, primary DEK). Readers from before the change
reject flag `0x01` as an unknown flag: once a repository has blobs with key
ids, use this version (or later) to read it.

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
(zstd, then the v3 chunk encryptor, then a hasher, then a spool); clear
objects use the same pipeline without the encryptor. The spool is
held in memory up to 8 MiB and then spills to a temporary file, which is
uploaded with `Storage::write_file` (a plain PutObject of known length on S3,
copy into a temp file plus atomic rename on local storage). Files up to
1 MiB are read once into memory; larger files and the chunks of multipart
files are read in 1 MiB pieces twice: a first pass hashes them (dedup
decision), and only content that must be stored is read again through the
pipeline, with its hash checked against the first pass before anything is
uploaded (a file that changed in between is reported, never stored). Backup
memory is therefore bounded per worker thread (read buffer, zstd context,
one v3 chunk, spool), whatever the file size. Restores decrypt
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
  "key_id": "<hex, 4 bytes: key id of the DEK in wrapped_dek>",
  "rotation": {
    "key_id": "<hex, 4 bytes>",
    "wrapped_dek": { "algorithm": "aes-256-gcm", "nonce": "...", "ciphertext": "..." },
    "started_at": "<RFC 3339>"
  },
  "created_at": "<RFC 3339>",
  "updated_at": "<RFC 3339, after a password change or rotation>"
}
```

* **DEK**: 32 random bytes, generated when the repository is created. It
  only changes with `rsb key rotate`.
* **key_id** (optional): the key id of the DEK in `wrapped_dek`. Files
  written before key ids lack it. When present, a reader checks that it
  matches the unwrapped DEK (`Corrupt` otherwise).
* **rotation** (only while a rotation is unfinished): the new DEK, wrapped
  with the same KEK and a random nonce, with AAD = the DEK wrap AAD followed
  by `"rotation"` (so the two wrapped keys cannot be swapped).
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
* **legacy_secret** (read only; never written by this version): earlier
  versions stored here the password that encrypted the pre-v3 objects,
  sealed with AES-256-GCM under
  `HKDF-SHA256(IKM = DEK, salt = "", info = "rsb v3 legacy secret")`, with a
  random nonce and AAD `"RSBKEYv3 legacy secret"`, so that v1/v2 objects
  stayed readable after a password change. This version still reads it
  (v1/v2 blobs are opened with it) and `rsb key migrate` removes it once
  every v1/v2 object is re-encrypted as v3.

### Creation

The first encrypted backup of a repository without a key file creates one.
`rsb key init` does the same explicitly. Creation:

1. takes the exclusive repository lock (two first backups cannot create two
   different keys) and checks again whether the key file exists;
2. if the repository already holds encrypted v1/v2 snapshots, checks that the
   password opens the newest one (otherwise it fails with
   `AuthenticationFailed`, so a mistyped password cannot split the repository
   between two passwords). The v1/v2 objects keep opening with the same
   password; it is not stored. If a v3 snapshot exists but the key file is
   missing, it refuses (restore the key file with `rsb key import`);
3. writes the file, reads it back and checks that it opens to the same DEK
   before any blob is encrypted with it.

A dry run never creates the file. `rsb key init` then counts the v1/v2
objects (and their size) and offers to run the migration below (`--yes`
runs it without asking).

### Password change (`rsb key change-password`)

Refused while v1/v2 data remains (a v1/v2 manifest, a referenced v1/v2
object, or an unreferenced v1/v2 object that still decrypts, since a later
backup could deduplicate against it) and while a rotation is unfinished. So
the old password is never needed after a password change.

Under the exclusive lock: unwrap with the old password, wrap the same DEK
with a new salt and nonce (and optionally new parameters), write a copy of the
current file to `keys/repo.key.bak-<timestamp>`, write the new file (an atomic
replacement per object on every backend), read it back and unwrap it with the
new password, then delete the copy. If the check fails, the previous file is
written back and the copy is kept. No blob is rewritten. The new file never contains
`legacy_secret`.

### Migration of v1/v2 data (`rsb key migrate`)

Re-encrypts every v1/v2 object and manifest as v3 under the repository DEK,
under the exclusive lock:

1. Read and decrypt every manifest (fail closed: an unreadable manifest
   aborts, since the set of referenced objects would be unknown).
2. For each v1/v2 object under `data/enc/`: decrypt it (with `legacy_secret`
   if the key file has one, else the password), re-encrypt the same
   plaintext as v3 under the same name, write it over the old object (an
   atomic replacement: temp file + rename locally, a single PutObject on
   S3), read it back, authenticate every chunk and compare the plaintext
   BLAKE3 with the original. A failed check retries the write (3 attempts),
   then aborts. Unreferenced v1/v2 objects are re-encrypted too when they
   decrypt (so a later backup cannot deduplicate against a blob that needs
   the old password) and are reported; those that do not decrypt are
   reported and left as they are. Nothing is deleted (prune
   garbage-collects unreferenced objects).
3. Rewrite the manifests last: v1/v2 manifests are re-encrypted as v3, and
   every manifest gets the new `stored_size`/`stored_hash` of the objects it
   references. Objects re-encrypted by an earlier, interrupted run are found
   by their stored size (a v3 blob never has the size of the v1/v2 blob of
   the same payload) and authenticated before their metadata is trusted.
4. Verify every snapshot in full with the v3 key alone (a context that
   refuses v1/v2 blobs): every manifest and every referenced object must
   authenticate and match its content hash.
5. Only then remove `legacy_secret` from the key file (timestamped copy →
   write → read back and unwrap → delete the copy).

A run interrupted at any point (crash, error, Ctrl-C) leaves a readable
repository: readers detect the format of every blob independently, so a mix
of v1/v2/v3 objects restores, verifies and prunes normally. Running the
command again resumes (objects already v3 are skipped). Between the object
and manifest steps, `verify --fast` can report stored size/hash mismatches
(the manifests still describe the old blobs); a full verify passes.

### Export and import (`rsb key export` / `rsb key import`)

The export is the key file itself (the DEK stays wrapped by the KEK), after
checking that the password unwraps it. It is safe at rest without the
password but decrypts everything together with it, so it is written to a
new file with mode 0600, or printed in paper form:

```
RSB-REPO-KEY PAPER v1 bytes=<n> check=<8 hex: BLAKE3 of the content>
01  ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567  K7Q2
...
```

The paper form encodes the compact JSON of the key file in RFC 4648
base32 (no 0/1/8/9), 32 characters (20 bytes) per line in groups of four,
followed by a per-line checksum: base32 of the first 20 bits of
`BLAKE3("rsb paper v1" | line number u16 | the line's 32 characters)`. A
typo is reported with its line number. The header checks the length and the
whole content (missing or swapped lines). Decoding ignores case and spacing
and reads 0/1/8 as O/I/B.

Import parses the file, unwraps it with the password and checks that it
belongs to the repository: it must decrypt the newest v3 manifest (or, if
there is none, a v3 data object; with no v3 data at all, the password must
open the newest v1/v2 manifest). Under the exclusive lock it then writes
`keys/repo.key` and reads it back. An existing, different key file is only
replaced with `--force`, after a copy to `keys/repo.key.bak-<ts>`, which is
kept.

### Key rotation (`rsb key rotate`)

Requires a completed migration (no v1/v2 data that needs the password, no
`legacy_secret`). Under the exclusive lock:

1. Generate a new DEK (with a key id different from the current one) and
   rewrite the key file into the rotating state: `wrapped_dek` keeps the old
   DEK, `rotation` holds the new one (timestamped copy, write, read back).
   From now on new blobs (including backups that run while the rotation is
   interrupted) use the new DEK; readers pick the DEK by key id.
2. Re-encrypt every v3 object whose key id is not the new one: stream
   decrypt (every chunk authenticated) → encrypt under the new DEK into a
   local spool → write over the old object → read back with the new DEK
   alone and compare the plaintext hash (3 attempts). Objects that decrypt
   with neither key are reported when unreferenced and abort the run when
   referenced.
3. Re-encrypt every manifest under the new DEK and refresh the
   `stored_hash` of its objects.
4. Verify every snapshot in full with the new DEK alone.
5. Rewrite the key file with only the new DEK (new KDF salt; same password).

Running `rsb key rotate` again during an interrupted rotation resumes it
with the same new DEK. A password change is refused until it completes.
Object names and stored sizes do not change (the key id lives inside the
salt field), so dedup equality and the size of every object are exactly the
same before and after a rotation.

## Compatibility matrix

| Repository / object | Without `keys/repo.key` | With `keys/repo.key` |
|---------------------|-------------------------|----------------------|
| Clear objects/manifests | read and write | read and write |
| v1 object | read (password) | read (`legacy_secret`, else password); rewritten as v3 by `rsb key migrate` |
| v2 object / manifest | read (password) | read (`legacy_secret`, else password); rewritten as v3 by `rsb key migrate` |
| v3 object / manifest, no key id | error `RepoKeyRequired` | read (primary DEK) |
| v3 object / manifest, key id | error `RepoKeyRequired` | read (DEK with that key id) and write (active DEK) |
| New encrypted objects | v3 (the key file is created first) | v3 |

Older versions of rs-shield cannot read v3 objects, and versions from before
key ids cannot read v3 blobs with the key id flag. Dedup reuses existing
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
  (backup copies, exports, S3 object versioning) plus the old password still
  yields the DEK. **Mitigated by `rsb key rotate`**, which replaces the DEK
  and re-encrypts all data. It protects against a leaked old key file + old
  password only **once it completes**: until step 5 the old DEK still
  decrypts every object not yet rewritten (and the key file itself holds
  it). After the rotation, discard old exports. Rotation does not change
  object names or stored sizes, so what storage access reveals (object
  count and sizes, dedup equality) is the same before and after; it does
  not help against someone who copied the data while they held the old
  key.
* **Mitigated: legacy password stored in the key file.** Earlier versions
  kept the v1/v2 password in `legacy_secret` so v1/v2 objects stayed
  readable after a password change; anyone with the DEK could recover that
  password. `rsb key migrate` re-encrypts all v1/v2 data and removes it, new
  key files never contain it, and a password change is refused while v1/v2
  data remains.
* **Mitigated: a lost key file.** `rsb key export` (file or paper) and
  `rsb key import` (with a check that the key decrypts the repository)
  provide a backup path.
* The DEK and KEK bytes and the passwords are zeroized after use. The AES key
  schedules held inside `ring` are not zeroized (ring does not expose that).
* Argon2id with the defaults takes about 135 ms and 64 MiB per unlock
  (measured on Apple silicon). Each operation unlocks once.
