# Changelog

All notable changes to RS Shield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `rsb restore --files <PATTERN>...`: restore only matching files (exact
  path, folder prefix or glob such as `**/*.pdf`, matched against the
  `/`-separated snapshot paths). Absolute paths and `..` are rejected; a
  selection that matches nothing fails without writing anything.
- `rsb restore --date <WHEN>`: restore the latest snapshot taken at or before
  WHEN (RFC 3339, `YYYY-MM-DD` = end of that day in local time, or
  `YYYY-MM-DD HH:MM` local time). Conflicts with `--snapshot`; fails naming
  the oldest snapshot when none is old enough.
- SDK: `RestoreOptions::include` / `RestoreOptions::at_or_before` and the
  `core::restore_select` module (pattern selector, date parser,
  snapshot-by-date lookup); the desktop restore screen exposes both.
- Real-time file synchronization with auto-backup
- Desktop dashboard with live metrics
- System notifications for backup events
- Smart ignore pattern configuration (regex-based)
- Multi-bucket S3 support
- Battery and CPU monitoring
- Email notifications

### Changed
- Refactored backup engine for better performance
- Updated UI with Dioxus framework
- Improved encryption key management

### Fixed
- Resolved S3 upload timeout issues
- Fixed path expansion for ~ and environment variables
- Corrected incremental backup deduplication logic

## [0.1.0] - 2025-12-01

### Added
- Initial release of RS Shield
- Core backup/restore functionality
- AES-256-GCM encryption
- S3-compatible storage support
- Incremental backup mode
- Command-line interface
- Basic desktop application
- Configuration file support (TOML)
- Zstd compression
- File integrity verification with BLAKE3

### Features
- Local filesystem backups
- AWS S3 integration
- MinIO support
- DigitalOcean Spaces support
- Wasabi support
- CloudFlare R2 support
- Automated prune operations
- Detailed backup reports
- Multi-threaded processing

---

## Versioning

RS Shield follows Semantic Versioning:
- **MAJOR** - Breaking changes
- **MINOR** - New features (backward compatible)
- **PATCH** - Bug fixes

## Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
