# RSB Core (Rust Shield Backup)

**RSB Core** is the fundamental library powering the Rust Shield Backup ecosystem. It provides the backend logic for incremental backup operations, secure encryption, deduplication, and communication with storage (Local and S3).

## 🧠 Main Features

### 1. Encryption and Security
- **Algorithm**: AES-256-GCM (Galois/Counter Mode).
- **Key Derivation**: PBKDF2 with HMAC-SHA256 and **600,000 iterations** for high resistance to brute force.
- **Integrity**: BLAKE3 hashing for file verification and deduplication.
- **Salt/Nonce**: Randomly generated via `ring::rand::SystemRandom` for each file/chunk.

### 2. Data Management
- **Smart Chunking**: Files larger than 4GB are automatically split into **512MB** chunks.
- **Deduplication**: Identical files or chunks are not re-uploaded, saving bandwidth and storage.
- **Compression**: Zstd support (configurable level, default 3) before encryption.

### 3. Storage
- **Local**: Standard file system.
- **Cloud (S3)**: Native support for AWS S3, MinIO, Cloudflare R2, and other compatible services.
- **Verification**: `s3_check` utility to validate credentials and connectivity.

### 4. Resource Monitoring
- **Battery**: Automatic pause if battery is below the configured threshold (e.g., 20%).
- **CPU**: Automatic pause if CPU usage exceeds the limit (e.g., 90%) to prevent system freeze.

## 📦 Module Structure

- `core`: Main logic for `perform_backup`, `perform_restore`, `perform_verify`.
- `crypto`: Implementation of `encrypt_data`, `decrypt_data`, and hashing.
- `storage`: Abstraction (`Storage` trait) for Local and S3 backends.
- `config`: Configuration structure definitions (TOML).

## 🛠️ Usage Example (Library)

```rust
use rsb_core::config::Config;
use rsb_core::core::perform_backup;

let config = Config {
    source_path: "/data/source".into(),
    destination_path: "/data/backup".into(),
    encryption_key: Some("secure-password".into()),
    compression_level: Some(3),
    ..Default::default()
};

// Perform incremental backup
let report = perform_backup(&config, "incremental", config.encryption_key.as_deref(), false, true, None).await?;
println!("Files processed: {}", report.files_processed);
```

## 📊 Estrutura de Dados

Os dados são armazenados em:
- `snapshots/`: Manifestos TOML contendo metadados dos arquivos.
- `data/clear/`: Conteúdo de arquivos não criptografados (hash-addressed).
- `data/enc/`: Conteúdo criptografado (hash-addressed).

## 🧪 Testes

O core inclui testes unitários para:
- Lógica de encriptação seletiva (baseada em padrões).
- Verificação rápida vs completa.
- Integridade de dados multipart.

---
*Desenvolvido em Rust com foco em performance e segurança.*