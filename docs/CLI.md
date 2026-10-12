# RS Shield CLI Reference

Complete command-line interface documentation for RS Shield.

## Table of Contents

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Commands](#commands)
   - [Profile Management](#profile-management)
   - [Backup & Restore](#backup--restore)
   - [Snapshot Management](#snapshot-management)
   - [Maintenance](#maintenance)
   - [Authentication](#authentication)
4. [Portability Guide](#portability-guide)
5. [Deduplication](#deduplication)
6. [Exit Codes](#exit-codes)

---

## Installation

### From Source

```bash
git clone https://github.com/yourusername/rs-shield.git
cd rs-shield
cargo install --path ./crates/rsb-cli
```

### Verify Installation

```bash
rsb --version
rsb --help
```

---

## Configuration

### Profile Format

Profiles are TOML configuration files defining backup parameters:

```toml
[backup]
source_path = "/home/user/documents"
destination_path = "/backup/storage"
mode = "incremental"                    # or "full"
compression_level = 3                   # 0-11 (0=none, 11=max)
exclude_patterns = ["*.tmp", "node_modules/"]

[encryption]
enabled = true
password = "your_password"

[s3]
enabled = false
# bucket = "my-bucket"
# region = "us-east-1"
# endpoint = "https://s3.amazonaws.com"
```

### Creating a Profile

```bash
# Interactive profile creation
rsb create-profile

# Or use command-line options
rsb create-profile \
  --name mybackup \
  --source ~/Documents \
  --dest /backup/docs \
  --mode incremental \
  --compression 6 \
  --encrypt
```

---

## Commands

### Profile Management

#### Create Profile

```bash
rsb create-profile [OPTIONS]

OPTIONS:
  --name <NAME>                 Profile name
  --source <SOURCE>             Source directory to backup
  --dest <DEST>                 Destination directory
  -m, --mode <MODE>             Backup mode: incremental | full [default: incremental]
  -c, --compression <LEVEL>     Compression level 0-11 [default: 3]
  -e, --encrypt                 Enable encryption
  --s3-bucket <BUCKET>          S3 bucket name
  --s3-region <REGION>          S3 region
  --s3-endpoint <ENDPOINT>      S3 endpoint
```

#### List Profiles

```bash
rsb list-profiles [OPTIONS]

OPTIONS:
  -f, --format <FORMAT>         Output format: table | json [default: table]
  -q, --quiet                   Minimal output
```

### Backup & Restore

#### Backup

Perform a backup operation.

```bash
rsb backup [OPTIONS] [CONFIG]

ARGUMENTS:
  [CONFIG]                      Path to config.toml (optional)

OPTIONS:
  -c, --config <CONFIG>         Path to config.toml file
  -b, --backup <BACKUP>         Backup destination (portable mode, no config needed)
  -m, --mode <MODE>             Override backup mode: full | incremental
  -k, --key <KEY>               Encryption password
  -d, --dry-run                 Preview changes without modifying files
  --no-resume                   Don't resume interrupted backups
  -v, --verify                  Verify backup integrity after completion
  --no-compress                 Disable compression for this backup
  -t, --threads <THREADS>       Number of parallel threads [default: 4]
  -r, --report                  Generate HTML backup report
  -H, --healthcheck-url <URL>   Healthchecks.io URL for monitoring
```

**Usage Examples:**

```bash
# Standard backup (using config file)
rsb backup mybackup.toml

# Portable backup (no config needed, direct path)
rsb backup --backup /media/external/backup

# With verification
rsb backup mybackup.toml --verify

# Dry run to preview
rsb backup mybackup.toml --dry-run

# Full backup (override incremental setting)
rsb backup mybackup.toml --mode full

# With custom threads
rsb backup mybackup.toml --threads 8

# Generate HTML report
rsb backup mybackup.toml --report
```

#### Restore

Restore files from a backup.

```bash
rsb restore [CONFIG] --target <DIR> [OPTIONS]

OPTIONS:
  [CONFIG]                      Path to config.toml (or use --backup)
  -b, --backup <BACKUP>         Path to backup directory (portable mode)
  -t, --target <DIR>            Restore destination directory (required)
  -s, --snapshot <ID>           Restore a specific snapshot (default: latest)
  -d, --date <WHEN>             Restore the latest snapshot taken at or before WHEN
  -i, --files <PATTERN>...      Restore only matching files (repeatable)
  -k, --key <KEY>               Decryption password (prefer RSB_ENCRYPTION_KEY)
  -f, --force                   Overwrite existing files
  -V, --versioned               Restore into <DIR>/restore_<timestamp>
  -v, --verify                  Verify the snapshot after restoring
  -r, --report                  Generate an HTML report
```

**Examples:**

```bash
# Restore using config file
rsb restore mybackup.toml --target ~/restored

# Restore using backup path (portable)
rsb restore --backup /backup/docs --target ~/restored

# Restore specific snapshot
rsb restore mybackup.toml --snapshot 2026-05-25T103000.000Z --target ~/restored

# Restore with verification
rsb restore mybackup.toml --target ~/restored --verify

# Only some files: an exact path, a whole folder and a glob
rsb restore --backup /backup/docs --target ~/restored \
  --files notes/todo.txt --files photos/ --files '**/*.pdf'

# The backup as it was on 1 October 2026 (latest snapshot of that day)
rsb restore --backup /backup/docs --target ~/restored --date 2026-10-01

# ...as it was at noon, local time, or at an exact instant
rsb restore --backup /backup/docs --target ~/restored --date "2026-10-01 12:00"
rsb restore --backup /backup/docs --target ~/restored --date 2026-10-01T12:00:00Z
```

**Selecting files (`--files`).** Patterns are matched against the paths
stored in the snapshot: relative to the backup source, with `/` separators on
every platform (`\` is accepted and read as `/`). Restored files keep their
relative paths under `--target`.

| Pattern | Restores |
|---------|----------|
| `docs/report.pdf` | that file |
| `docs` | everything under `docs/` (and a file named `docs`, if any) |
| `docs/` | everything under `docs/` |
| `docs/*.pdf` | PDFs directly in `docs/` (`*` and `?` never cross `/`) |
| `*.txt` | `.txt` files at the top level only |
| `**/*.txt` | `.txt` files at any depth |
| `photos/202[45]` | everything under `photos/2024/` and `photos/2025/` |

* Globs use the `glob` crate syntax (`*`, `?`, `[...]`, `**`) and are anchored
  at the backup root; a glob that matches a folder restores the whole folder.
  Quote globs so the shell does not expand them.
* Matching is case sensitive and does not normalize Unicode.
* Absolute paths (`/etc`, `C:\...`) and `..` components are rejected.
* `--files` takes several values (`--files a b`) and can be repeated. Put the
  config path before `--files` (or use `--backup`), otherwise it is read as a
  pattern.
* If no pattern matches any file of the snapshot, the restore fails (non-zero
  exit) and nothing is written. A pattern that matches nothing while others do
  is reported as a warning.

**Choosing a snapshot by date (`--date`).** Restores the most recent snapshot
taken at or before WHEN (a snapshot taken exactly at WHEN qualifies). The
chosen snapshot id is printed and `--verify` checks that same snapshot.

| WHEN | Meaning |
|------|---------|
| `2026-10-01T12:00:00Z`, `2026-10-01T14:00:00+02:00` | that exact instant (RFC 3339) |
| `2026-10-01` | the end of that day (23:59:59.999), **local time** |
| `"2026-10-01 12:00"` | the end of that minute (12:00:59.999), local time |
| `"2026-10-01 12:00:30"` | the end of that second, local time |

Local times use the time zone of the machine running `rsb` (`T` may replace
the space). If every snapshot is newer than WHEN the command fails and names
the oldest available snapshot. `--date` and `--snapshot` cannot be combined.
Snapshot times come from the snapshot names (UTC), as listed by
`rsb snapshots list`.

#### Verify

Verify backup integrity.

```bash
rsb verify [OPTIONS]

OPTIONS:
  -c, --config <CONFIG>         Path to config.toml
  -b, --backup <BACKUP>         Path to backup directory
  -s, --snapshot <ID>           Verify specific snapshot
  -k, --key <KEY>               Decryption password
  --quick                       Quick verification (hash only, skip decryption)
  --fast                        Fast verification (hash-only, no decryption)
  -q, --quiet                   Suppress output
  -r, --report                  Generate HTML verification report
```

**Examples:**

```bash
# Verify using config
rsb verify --config mybackup.toml

# Verify using backup path
rsb verify --backup /backup/docs

# Quick verification (hash only)
rsb verify --backup /backup/docs --quick

# Verify specific snapshot
rsb verify --config mybackup.toml --snapshot 2026-05-25T10:30:00

# Generate report
rsb verify --config mybackup.toml --report
```

### Repository Key (format v3)

Encrypted repositories keep a random data key (DEK) in `keys/repo.key`,
wrapped with your password (Argon2id). The first encrypted backup creates it
automatically. See [FORMAT.md](FORMAT.md) for details. Every `rsb key`
command requires an authenticated session (`rsb login`) and only reads
passwords from an interactive prompt (never from arguments or the
environment).

```bash
# Create keys/repo.key explicitly (upgrades an existing v1/v2 repository;
# enter the password of the existing backups). If v1/v2 data exists, it
# shows the object count/size and offers to re-encrypt it as v3 right away
# (`--yes` skips the question, e.g. in scripts).
rsb key init mybackup.toml
rsb key init --repo /path/to/backup --yes

# Re-encrypt every v1/v2 (pre-v3) object and manifest as v3, verify the
# whole repository, then drop the old password from the key file.
# Resumable: after an interruption (crash, Ctrl-C) just run it again.
rsb key migrate mybackup.toml

# Change the password (rewraps the key; no backup data is rewritten).
# Refused while v1/v2 data remains: run `rsb key migrate` first.
rsb key change-password mybackup.toml

# Optional Argon2 tuning (minimums: --m-cost-kib 19456, --t-cost 2)
rsb key change-password mybackup.toml --m-cost-kib 131072 --t-cost 3

# Back up the key file: to a file created with mode 0600 ...
rsb key export mybackup.toml --output ~/safe/repo.key
# ... or as a printable page (base32 groups, a checksum per line)
rsb key export mybackup.toml --paper

# Restore a lost or damaged key file (JSON or the retyped paper form).
# Checks the password and that the key decrypts this repository; refuses to
# replace a different existing key file unless --force (which backs it up
# to keys/repo.key.bak-<timestamp> first).
rsb key import ~/safe/repo.key mybackup.toml
rsb key import paper-key.txt --repo /path/to/backup --force

# Generate a new DEK and re-encrypt every object and manifest under it
# (requires a completed `rsb key migrate`). Resumable: run it again after
# an interruption. Old exports of the key file stop working afterwards.
rsb key rotate mybackup.toml
```

| Command | Rewrites data | Needs exclusive lock | Resumable |
|---------|---------------|----------------------|-----------|
| `init` | no (unless it runs the migration) | yes | — |
| `migrate` | v1/v2 objects and manifests | yes | yes |
| `change-password` | no | yes | — |
| `export` | no | no | — |
| `import` | no (writes `keys/repo.key`) | yes | — |
| `rotate` | every encrypted object and manifest | yes | yes |

Notes:

* An export holds the DEK wrapped by the password: it is useless without the
  password, but together with it decrypts every backup. Store it like the
  password. The unwrapped DEK is never printed.
* While `migrate` or `rotate` is interrupted, backups, restores, verify and
  prune keep working (every object is either fully old or fully new).
  `verify --fast` may report stored-hash mismatches until the command is
  run again, because manifests are updated last; a full `verify` passes.
* After a rotation, keep the new key file (`rsb key export`) and discard old
  exports and copies: they no longer open the data.

> ⚠️ Keep a copy of `keys/repo.key` (`rsb key export`): without it, v3
> backups cannot be decrypted, even with the password.

### Snapshot Management

Manage backup snapshots and versions.

#### List Snapshots

```bash
rsb snapshots list [OPTIONS]

OPTIONS:
  -c, --config <CONFIG>         Path to config.toml (optional if .toml in current dir)
  -b, --backup <BACKUP>         Path to backup directory (portable mode)
  -k, --key <KEY>               Decryption key for encrypted manifests
```

**Examples:**

```bash
# List snapshots from config
rsb snapshots list --config mybackup.toml

# List snapshots from backup path
rsb snapshots list --backup /backup/docs

# List encrypted snapshots
rsb snapshots list --backup /backup/docs --key mypassword
```

#### Show Snapshot Details

```bash
rsb snapshots show [OPTIONS] <ID>

ARGUMENTS:
  <ID>                          Snapshot identifier

OPTIONS:
  -c, --config <CONFIG>         Path to config.toml
  -b, --backup <BACKUP>         Path to backup directory
  -k, --key <KEY>               Decryption key
```

**Examples:**

```bash
# Show snapshot details
rsb snapshots show 2026-05-25T10:30:00 --config mybackup.toml

# Show details from backup path
rsb snapshots show 2026-05-25T10:30:00 --backup /backup/docs
```

#### Compare Snapshots (NEW)

Compare two snapshots to see what changed.

```bash
rsb snapshots diff [OPTIONS] <FROM> <TO>

ARGUMENTS:
  <FROM>                        First snapshot ID
  <TO>                          Second snapshot ID

OPTIONS:
  -c, --config <CONFIG>         Path to config.toml
  -b, --backup <BACKUP>         Path to backup directory (portable mode)
  -k, --key <KEY>               Decryption key
```

**Examples:**

```bash
# Compare two snapshots
rsb snapshots diff 2026-05-20T10:00:00 2026-05-25T10:00:00 --config mybackup.toml

# Compare using portable backup path
rsb snapshots diff snap1 snap2 --backup /backup/docs

# Output shows:
# ✅ Added (N files)
# ❌ Removed (N files)  
# 🔄 Modified (N files)
```

#### Delete Snapshot

```bash
rsb snapshots delete [OPTIONS] <ID>

ARGUMENTS:
  <ID>                          Snapshot identifier

OPTIONS:
  -c, --config <CONFIG>         Path to config.toml
  -b, --backup <BACKUP>         Path to backup directory
```

### Maintenance

#### Prune

Remove old backups and optimize storage.

```bash
rsb prune [OPTIONS]

OPTIONS:
  -c, --config <CONFIG>         Path to config.toml (optional)
  -b, --backup <BACKUP>         Path to backup directory (portable mode)
  -l, --keep-last <COUNT>       Keep last N backups (the short flag was -k
                                before 0.1.0-alpha.9)
  -r, --retention <POLICY>      Retention policy: "30d", "6m", "1y", or number
  -d, --dry-run                 Preview deletions without removing
  --confirm                     Required to actually delete (unless --dry-run)
  -q, --quiet                   Suppress output
  -H, --healthcheck-url <URL>   Healthchecks.io URL
```

**Examples:**

```bash
# Preview what would be deleted
rsb prune --config mybackup.toml --retention 30d --dry-run

# Keep last 6 months
rsb prune --config mybackup.toml --retention 6m --confirm

# Keep last 10 backups
rsb prune --config mybackup.toml --keep-last 10 --confirm

# Using backup path (portable)
rsb prune --backup /backup/docs --retention 90d --confirm
```

#### Schedule

Display scheduling instructions for automated backups.

```bash
rsb schedule [OPTIONS]

OPTIONS:
  -c, --config <CONFIG>         Path to config.toml (optional)
  -b, --backup <BACKUP>         Backup directory (portable mode)
  -f, --format <FORMAT>         Output format: cron | systemd [default: cron]
```

**Examples:**

```bash
# Get cron format
rsb schedule --config mybackup.toml --format cron
# Output: 0 3 * * * "/usr/local/bin/rsb-cli" backup "mybackup.toml" --key "PASSWORD"

# Get systemd format
rsb schedule --config mybackup.toml --format systemd
```

#### Watch

Enable real-time file synchronization and automated backups.

```bash
rsb watch [OPTIONS]

OPTIONS:
  -c, --config <CONFIG>         Path to config.toml (optional)
  -b, --backup <BACKUP>         Backup directory (portable mode)
  --sync-to <PATH>              Directory to sync changes to
  -k, --key <KEY>               Encryption password
  -i, --interval <SECONDS>      Check interval [default: 2]
  -H, --healthcheck-url <URL>   Healthchecks.io URL for monitoring
```

**Examples:**

```bash
# Watch and auto-backup
rsb watch --config mybackup.toml --sync-to /tmp/sync --key mypassword

# With healthcheck monitoring
rsb watch --config mybackup.toml --sync-to /tmp/sync \
  --healthcheck-url https://healthchecks.io/ping/your-uuid
```

### Authentication

#### Login

Authenticate with FIDO2 security key.

```bash
rsb login [OPTIONS]

OPTIONS:
  --user-id <ID>                User email or username
  --recovery                    Use recovery code instead of FIDO2
```

#### Server

Start WebAuthn authentication server.

```bash
rsb server [OPTIONS]

OPTIONS:
  -p, --port <PORT>             Server port [default: 3000]
```

---

## Portability Guide

### What is Portable Mode?

Portable mode allows you to:
- Create backups without a config file
- Use `--backup` flag to specify destination directory directly
- Restore backups on different computers
- Move backups to external drives

### Portable Backup Workflow

```bash
# 1. Create backup without config file (portable mode)
rsb backup --backup /media/external/mybackup

# 2. Verify on same computer
rsb verify --backup /media/external/mybackup

# 3. Move to another computer and restore
# On computer B:
rsb restore --backup /media/external/mybackup --output ~/restored

# 4. Compare snapshots across systems
rsb snapshots diff snap1 snap2 --backup /media/external/mybackup
```

### Config vs Portable Mode

| Feature | Config Mode | Portable Mode |
|---------|------------|---------------|
| Command | `rsb backup config.toml` | `rsb backup --backup /path` |
| Requires config file | ✅ Yes | ❌ No |
| Cross-computer | ❌ Limited | ✅ Yes |
| Profile saved | ✅ Yes | ❌ No |
| Use case | Regular backups | External drives, cross-platform |

### Auto-Discovery

All commands look for `.toml` files in the current directory:

```bash
# If mybackup.toml is in current directory:
rsb backup          # Auto-discovers mybackup.toml
rsb verify          # Auto-discovers mybackup.toml
rsb snapshots list  # Auto-discovers mybackup.toml
```

---

## Deduplication

RS Shield automatically deduplicates backup files to save storage space.

### How It Works

1. **Content-based hashing**: Each file is hashed using its content
2. **Duplicate detection**: If a file with the same hash exists, it's skipped
3. **Automatic optimization**: Duplicate files aren't stored twice

### Benefits

- **Reduced storage**: Identical files take no extra space
- **Faster backups**: Duplicate files skip compression and encryption
- **Cross-backup deduplication**: Works across multiple snapshots

### Example

```bash
# First backup of documents folder
rsb backup mybackup.toml
# → 100 files backed up

# Backup again after adding only 10 new files
rsb backup mybackup.toml
# → 10 files backed up (90 duplicates skipped ✓)
# → Total storage used: ~105 files worth (with overhead)
```

---

## Exit Codes

| Code | Meaning | Example |
|------|---------|---------|
| 0 | Success | Backup completed successfully |
| 1 | General error | Configuration file not found |
| 2 | I/O error | Cannot read source directory |
| 3 | Encryption error | Invalid decryption password |
| 4 | Verification failed | Backup integrity check failed |
| 5 | Permission denied | Insufficient access to source/destination |
  --encrypt \
  --compression 6

# With S3
rsb create-profile --name cloud \
  --source ~/Documents \
  --dest s3://my-backups \
  --s3-bucket my-backups \
  --s3-region us-east-1 \
  --encrypt
```

### Backup

Perform a backup operation.

```bash
rsb backup [OPTIONS] --profile <FILE>

OPTIONS:
  -p, --profile <FILE>           Profile configuration file
  -m, --mode <MODE>              Override backup mode (full/incremental)
  -c, --password <PASSWORD>      Encryption password
  -d, --dry-run                  Preview changes without backing up
  -v, --verify                   Verify backup after completion
  --no-compress                  Disable compression
  --threads <COUNT>              Number of parallel threads
  -q, --quiet                    Suppress progress output
```

**Examples:**

```bash
# Simple backup
rsb backup --profile docs.toml

# Dry run to preview
rsb backup --profile docs.toml --dry-run

# With verification
rsb backup --profile docs.toml --verify

# Full backup (override incremental)
rsb backup --profile docs.toml --mode full

# Custom thread count
rsb backup --profile docs.toml --threads 4
```

### Restore

Restore from a backup.

```bash
rsb restore [CONFIG] --target <PATH> [OPTIONS]

OPTIONS:
  -b, --backup <PATH>            Backup source path
  -t, --target <PATH>            Restore destination
  -k, --key <KEY>                Decryption password
  -i, --files <PATTERN>...       Restore only matching files (path, folder or glob)
  -d, --date <WHEN>              Latest snapshot at or before WHEN (YYYY-MM-DD = end of day, local time)
  -v, --verify                   Verify the snapshot after restoring
```

See [Restore](#restore) above for the pattern and date rules.

**Examples:**

```bash
# Full restore
rsb restore --backup /backup/docs --target ~/restored

# Specific files only
rsb restore --backup /backup/docs --target ~/restored --files '**/*.pdf'

# Restore the backup as of a date
rsb restore --backup /backup/docs --target ~/restored --date 2026-02-01

# From S3
rsb restore --backup s3://my-backups/docs --target ~/restored
```

#### Verify

Verify backup integrity (by config file or direct path).

```bash
rsb verify [OPTIONS]

OPTIONS (use one of):
  -c, --config <FILE>            Path to profile configuration file
  -b, --backup <PATH>            Direct path to backup folder
  -s, --snapshot <ID>            Specific snapshot ID to verify
  -k, --key <PASSWORD>           Decryption password (if encrypted)
  --quick                        Quick verification (hash only, skip decryption)
  -f, --fast                     Fast verification (hash only, no decryption)
  -q, --quiet                    Suppress output
  -r, --report                   Generate HTML report
```

**Examples:**

```bash
# Verify via profile
rsb verify --config docs.toml

# Verify direct backup path
rsb verify --backup /backup/docs

# Quick check without decryption
rsb verify --backup /backup/docs --quick

# Verify specific snapshot
rsb verify --backup /backup/docs --snapshot snap-2026-05-25

# Generate report
rsb verify --backup /backup/docs --report

# Verify S3 backup
rsb verify --backup s3://my-backups/docs --key mypassword
```

#### Prune

Remove old backup files and optimize storage.

```bash
rsb prune [OPTIONS] --retention <POLICY>

OPTIONS:
  -p, --backup <PATH>            Backup directory to prune
  -r, --retention <POLICY>       Retention policy (e.g., "30d", "6m", "1y")
  --dry-run                      Preview what would be deleted
  -q, --quiet                    Suppress output
```

**Examples:**

```bash
# Keep last 30 days
rsb prune --backup /backup/docs --retention 30d --dry-run

# Keep last 6 months
rsb prune --backup /backup/docs --retention 6m

# Keep last 1 year
rsb prune --backup /backup/docs --retention 1y
```

### Verification & Diagnostics Commands

#### Diagnose

Diagnose and repair backup issues.

```bash
rsb diagnose [OPTIONS] --backup <PATH>

OPTIONS:
  -b, --backup <PATH>            Backup path to diagnose
  -k, --key <PASSWORD>           Decryption password
  -v, --verbose                  Detailed diagnostics output
  -j, --json                     Output in JSON format
  --repair                       Attempt to repair detected issues
```

**Examples:**

```bash
# Run diagnostics
rsb diagnose --backup /backup/docs

# Verbose output
rsb diagnose --backup /backup/docs --verbose

# JSON output for automation
rsb diagnose --backup /backup/docs --json

# Attempt repairs
rsb diagnose --backup /backup/docs --repair

# Diagnose encrypted backup
rsb diagnose --backup /backup/docs --key mypassword --verbose
```

### Snapshots

Manage backup snapshots and versions.

```bash
rsb snapshots [OPTIONS] <COMMAND>

COMMANDS:
  list          List all snapshots in a backup
  info          Show detailed snapshot information
  diff          Compare two snapshots
  delete        Remove a snapshot
```

#### List Snapshots

```bash
rsb snapshots list --backup <PATH>

OPTIONS:
  -b, --backup <PATH>            Backup path
  -f, --format <FORMAT>          Output format: table, json [default: table]
```

**Examples:**

```bash
# List all snapshots
rsb snapshots list --backup /backup/docs

# JSON output
rsb snapshots list --backup /backup/docs --format json
```

#### Snapshot Info

```bash
rsb snapshots info --backup <PATH> --snapshot <ID>

OPTIONS:
  -b, --backup <PATH>            Backup path
  -s, --snapshot <ID>            Snapshot ID
```

**Examples:**

```bash
# Show snapshot details
rsb snapshots info --backup /backup/docs --snapshot snap-2026-05-25
```

#### Compare Snapshots

```bash
rsb snapshots diff --backup <PATH> --from <ID> --to <ID>

OPTIONS:
  -b, --backup <PATH>            Backup path
  --from <ID>                    First snapshot ID
  --to <ID>                      Second snapshot ID
```

**Examples:**

```bash
# Compare two snapshots
rsb snapshots diff --backup /backup/docs --from snap-2026-05-20 --to snap-2026-05-25
```

### Management Commands

#### Schedule

Display scheduling instructions for automated backups.

```bash
rsb schedule [OPTIONS] --config <FILE>

OPTIONS:
  -c, --config <FILE>            Profile configuration file
  -f, --format <FORMAT>          Format: cron, systemd [default: cron]
```

**Examples:**

```bash
# Get cron instruction
rsb schedule --config docs.toml --format cron

# Output:
# 0 3 * * * "/usr/local/bin/rsb" backup "/home/user/docs.toml" --key "PASSWORD"

# Get systemd timer instruction
rsb schedule --config docs.toml --format systemd
```

### Watch

Enable real-time file synchronization and automated backups.

```bash
rsb watch [OPTIONS] --config <FILE> --sync-to <PATH>

OPTIONS:
  -c, --config <FILE>            Profile configuration file
  --sync-to <PATH>               Directory to sync changes to
  -k, --key <PASSWORD>           Encryption password
  -i, --interval <SECONDS>       Check interval [default: 2]
  --healthcheck-url <URL>        Healthcheck endpoint for monitoring
```

**Examples:**

```bash
# Watch folder and auto-backup
rsb watch --config docs.toml --sync-to /tmp/sync --key mypassword

# With healthcheck
rsb watch --config docs.toml --sync-to /tmp/sync --key mypassword \
  --healthcheck-url https://healthchecks.io/ping/your-uuid
```

### Authentication Commands

#### Login

Authenticate with FIDO2 security key or recovery code.

```bash
rsb login [OPTIONS] --user-id <ID>

OPTIONS:
  -u, --user-id <ID>             User identifier (email or username)
  --recovery                     Use recovery code instead of FIDO2
```

**Examples:**

```bash
# Login with FIDO2 key
rsb login --user-id user@example.com

# Login with recovery code
rsb login --user-id user@example.com --recovery
# Then enter recovery code when prompted
```

#### Server

Start authentication server for FIDO2/WebAuthn.

```bash
rsb server [OPTIONS]

OPTIONS:
  -p, --port <PORT>              Server port [default: 3000]
```

**Examples:**

```bash
# Start on default port 3000
rsb server

# Start on custom port
rsb server --port 8080

# Access at http://localhost:3000
```

### Management Commands

#### List Profiles

List all available backup profiles.

```bash
rsb list-profiles [OPTIONS]

OPTIONS:
  -d, --directory <PATH>         Profile directory [default: ~/.config/rs-shield]
  -f, --format <FORMAT>          Output format: table, json, csv [default: table]
```

**Examples:**

```bash
# List profiles
rsb list-profiles

# JSON output
rsb list-profiles --format json

# Custom directory
rsb list-profiles --directory ~/.backup/profiles
```

#### Configuration

Manage credentials and settings.

```bash
rsb config [OPTIONS] <COMMAND>

COMMANDS:
  set-password              Set master password
  s3-credentials           Configure S3 credentials
  list                     List current configuration
  reset                    Reset all settings [WARNING: destructive]
```

**Examples:**

```bash
# Set master password
rsb config set-password

# Configure S3
rsb config s3-credentials --bucket my-backups --region us-east-1

# List config
rsb config list

# Reset (danger!)
rsb config reset --confirm
```

#### FIDO2 Security Key Management

Manage hardware security keys and FIDO2/WebAuthn credentials for phishing-resistant authentication.

```bash
rsb fido2 <COMMAND> [OPTIONS]

COMMANDS:
  register    Register a new Security Keysecurity key
  authenticate   Authenticate using a registered Security Keykey
  list        List all registered Security Keycredentials
  revoke      Remove a Security Keycredential
```

#### Register a Security Key

```bash
rsb fido2 register --user-id <USER_ID> --name <NAME>

OPTIONS:
  -u, --user-id <USER_ID>        User identifier (email or username)
  -n, --name <NAME>              Display name for the credential
```

**Examples:**

```bash
# Register YubiKey
rsb fido2 register --user-id user@example.com --name "My YubiKey"

# Register Windows Hello
rsb fido2 register --user-id admin --name "Windows Hello"

# Register Biometric (fingerprint)
rsb fido2 register --user-id marciozebedeu --name "Fingerprint Sensor"
```

#### Authenticate with Security Key

```bash
rsb fido2 authenticate --user-id <USER_ID>

OPTIONS:
  -u, --user-id <USER_ID>        User identifier to authenticate
```

**Examples:**

```bash
# Authenticate user
rsb fido2 authenticate --user-id user@example.com

# Output:
# ✅ Authentication challenge created
#    Counter: 5
```

#### List Registered Credentials

```bash
rsb fido2 list
```

**Output:**

```
📱 Security KeyCredentials Registered

┌─────────────────────┬──────────────────────┬─────────────────────────┐
│ User ID             │ Created At           │ Last Used               │
├─────────────────────┼──────────────────────┼─────────────────────────┤
│ user@example.com    │ 2026-04-29 14:23:45  │ 2026-04-29 16:45:12    │
│ admin               │ 2026-04-25 10:15:30  │ 2026-04-29 09:00:00    │
└─────────────────────┴──────────────────────┴─────────────────────────┘
```

#### Revoke a Credential

```bash
rsb fido2 revoke --user-id <USER_ID>

OPTIONS:
  -u, --user-id <USER_ID>        User ID of credential to revoke
```

**Examples:**

```bash
# Remove credential (will ask for confirmation)
rsb fido2 revoke --user-id user@example.com

# Output:
# 🗑️ Revoking Security KeyCredential
# Continue? (y/n): y
# ✅ Credential revoked successfully
```

---

### Version & Help

Display version and help information.

```bash
rsb --version              Print version
rsb --help                 Print general help
rsb <COMMAND> --help       Print command help
rsb help <COMMAND>         Print command help (alternative)
```

**Examples:**

```bash
rsb --version
rsb backup --help
rsb help restore
```

---

## Examples

### Daily Automated Backup

Create cron job:

```bash
# Edit crontab
crontab -e

# Add entry for daily 2 AM backup
0 2 * * * /usr/local/bin/rsb backup --profile docs.toml --quiet
```

### Encrypted Cloud Backup

```bash
# Create profile with S3
rsb create-profile --name cloud-backup \
  --source ~/Documents \
  --dest s3://my-backups \
  --s3-bucket my-backups \
  --s3-region us-east-1 \
  --s3-endpoint https://s3.amazonaws.com \
  --encrypt

# Run backup
rsb backup --profile cloud-backup.toml

# Restore later
rsb restore --backup s3://my-backups --output ~/restored
```

### Backup with Verification

```bash
# Backup and verify
rsb backup --profile docs.toml --verify

# Later, verify without restore
rsb verify --backup /backup/docs
```

### Selective Restore

```bash
# Restore specific file types, at any depth
rsb restore --backup /backup/docs --target ~/restored --files '**/*.pdf' '**/*.doc*'

# Restore one folder as it was last Friday
rsb restore --backup /backup/docs --target ~/restored --files projects/site/ --date 2026-10-09
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | File not found |
| 4 | Permission denied |
| 5 | Invalid credentials |
| 6 | Backup verification failed |
| 127 | Command not found |

---

## Tips & Tricks

### Dry Run Pattern

Always use `--dry-run` first:

```bash
rsb restore --backup /backup --output ~/restored --dry-run
# Review output, then run without --dry-run
rsb restore --backup /backup --output ~/restored
```

### Verbose Debugging

Enable debug logging:

```bash
RUST_LOG=debug rsb backup --profile docs.toml --verbose
```

### Parallel Processing

Increase threads for faster backup:

```bash
rsb backup --profile docs.toml --threads 8
```

### Compression Trade-offs

```bash
rsb backup --profile docs.toml --compression 3  # Fast (default)
rsb backup --profile docs.toml --compression 9  # Slow but small
rsb backup --profile docs.toml --no-compress    # Fastest
```

---

## Troubleshooting

### "Permission denied"

```bash
# Fix backup directory permissions
chmod 700 /backup/docs

# Run with elevated privileges if necessary
sudo rsb backup --profile docs.toml
```

### "Profile not found"

```bash
# List available profiles
rsb list-profiles

# Create if missing
rsb create-profile --name docs --source ~/Documents --dest /backup
```

### "Incorrect password"

```bash
# Try again (passwords are case-sensitive)
rsb restore --backup /backup/docs --output ~/restored
# (get prompted for password)
```

### Out of Memory

```bash
# Reduce thread count
rsb backup --profile docs.toml --threads 2

# Or use smaller profiles
# Split into multiple profiles and backup separately
```

---

## Support

- 📧 Email: marciozebedeu@rsbshield.co.ao
- 🌐 Website: [rsbshield.co.ao](https://rsbshield.co.ao)
- 🐛 Issues: [github.com/zebedeu/rs-shield](https://github.com/zebedeu/rs-shield)

## Related

- [User Guide](/docs/USER_GUIDE.md)
- [Developer Guide](/docs/DEVELOPER_GUIDE.md)
- [Security Policy](/SECURITY.md)

---

*Last Updated: February 2026*
