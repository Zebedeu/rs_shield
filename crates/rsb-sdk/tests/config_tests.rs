use std::fs;
use tempfile::TempDir;

#[test]
fn test_create_config_profile() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let source = temp_dir.path().join("source");
    let dest = temp_dir.path().join("dest");

    fs::create_dir_all(&source).expect("Failed to create source dir");
    fs::create_dir_all(&dest).expect("Failed to create dest dir");

    let config_file = temp_dir.path().join("test_profile.toml");

    // Create a test config
    let config_content = r#"
source_path = "/path/to/source"
destination_path = "/path/to/dest"
exclude_patterns = ["*.tmp", "node_modules"]
backup_mode = "incremental"
compression_level = 3
pause_on_low_battery = 20
pause_on_high_cpu = 20
"#;

    fs::write(&config_file, config_content).expect("Failed to write config");

    // Verify the file was created
    assert!(config_file.exists(), "Config file should exist");

    let content = fs::read_to_string(&config_file).expect("Failed to read config");
    assert!(
        content.contains("incremental"),
        "Config should contain backup mode"
    );
    assert!(
        content.contains("node_modules"),
        "Config should contain exclude patterns"
    );
}

#[test]
fn test_s3_config_serialization() {
    let config_content = r#"
source_path = "/source"
destination_path = "/dest"
backup_mode = "full"
exclude_patterns = ["*.tmp"]

[s3]
bucket = "my-bucket"
region = "us-east-1"
endpoint = "https://s3.amazonaws.com"
access_key = "test-key"
secret_key = "test-secret"
"#;

    let config: Result<rsb_sdk::config::Config, _> = toml::from_str(config_content);
    assert!(config.is_ok(), "Config with S3 should parse correctly");

    let cfg = config.unwrap();
    assert_eq!(cfg.backup_mode, "full");
    assert!(cfg.s3.is_some(), "S3 config should be present");

    let s3 = cfg.s3.unwrap();
    assert_eq!(s3.bucket.unwrap(), "my-bucket");
    assert_eq!(s3.region.unwrap(), "us-east-1");
}

#[test]
fn test_config_with_encryption() {
    let config_content = r#"
source_path = "/source"
destination_path = "/dest"
backup_mode = "incremental"
exclude_patterns = ["*.tmp", "node_modules"]
encryption_key = "super-secret-key"
encrypt_patterns = ["*.pdf", "*.doc"]
"#;

    let config: rsb_sdk::config::Config =
        toml::from_str(config_content).expect("Failed to parse config");
    assert!(
        config.encryption_key.is_some(),
        "Encryption key should be present"
    );
    assert!(
        config.encrypt_patterns.is_some(),
        "Encrypt patterns should be present"
    );

    let patterns = config.encrypt_patterns.unwrap();
    assert_eq!(patterns.len(), 2);
    assert!(patterns.contains(&"*.pdf".to_string()));
}

#[test]
fn test_config_default_values() {
    let config_content = r#"
source_path = "/source"
destination_path = "/dest"
backup_mode = "incremental"
exclude_patterns = ["*.tmp"]
"#;

    let config: rsb_sdk::config::Config =
        toml::from_str(config_content).expect("Failed to parse config");
    assert!(
        config.encryption_key.is_none(),
        "Encryption key should be None by default"
    );
    assert!(
        config.pause_on_low_battery.is_none(),
        "Battery pause should be None by default"
    );
    assert!(config.s3.is_none(), "S3 config should be None by default");
}

/// Um perfil TOML no formato existente (com todos os campos, incluindo os
/// legados) continua a ser lido exatamente como antes, e um perfil mínimo
/// recebe os mesmos valores que `Config::default()`.
#[test]
fn test_existing_profile_toml_loads_identically() {
    use rsb_sdk::config::{Config, DEFAULT_EXCLUDE_PATTERNS};

    let full = r#"
source_path = "/home/user/docs"
destination_path = "/mnt/backup"
exclude_patterns = ["*.tmp", "node_modules"]
backup_mode = "full"
s3_bucket = "flat-bucket"
s3_region = "eu-west-1"
s3_endpoint = "https://s3.example.com"
encrypt_patterns = ["*"]
pause_on_low_battery = 20
pause_on_high_cpu = 65
compression_level = 3
max_threads = 4
channel_buffer_size = 4096

[s3]
bucket = "nested-bucket"
region = "us-east-1"
endpoint = "http://localhost:9000"

[[s3_buckets]]
name = "nested-bucket"
region = "us-east-1"
endpoint = "http://localhost:9000"
"#;
    let c: Config = toml::from_str(full).expect("full profile must parse");
    assert_eq!(c.source_path, "/home/user/docs");
    assert_eq!(c.destination_path, "/mnt/backup");
    assert_eq!(c.exclude_patterns, vec!["*.tmp", "node_modules"]);
    assert!(c.encryption_key.is_none());
    assert_eq!(c.backup_mode, "full");
    assert_eq!(c.s3_bucket.as_deref(), Some("flat-bucket"));
    assert_eq!(c.s3_region.as_deref(), Some("eu-west-1"));
    assert_eq!(c.s3_endpoint.as_deref(), Some("https://s3.example.com"));
    let s3 = c.s3.as_ref().expect("nested s3");
    assert_eq!(s3.bucket.as_deref(), Some("nested-bucket"));
    assert_eq!(s3.region.as_deref(), Some("us-east-1"));
    assert_eq!(s3.endpoint.as_deref(), Some("http://localhost:9000"));
    assert!(s3.access_key.is_none() && s3.secret_key.is_none());
    let buckets = c.s3_buckets.as_ref().expect("s3_buckets");
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].name, "nested-bucket");
    assert_eq!(c.encrypt_patterns, Some(vec!["*".to_string()]));
    assert_eq!(c.pause_on_low_battery, Some(20));
    assert_eq!(c.pause_on_high_cpu, Some(65));
    assert_eq!(c.compression_level, Some(3));
    assert_eq!(c.max_threads, Some(4));
    assert_eq!(c.channel_buffer_size, 4096);

    // Round-trip: serializar e voltar a ler preserva tudo.
    let again: Config = toml::from_str(&toml::to_string_pretty(&c).unwrap()).unwrap();
    assert_eq!(format!("{:?}", again), format!("{:?}", c));

    // Perfil mínimo: os defaults de serde coincidem com Config::default().
    let minimal = r#"
source_path = "/src"
destination_path = "/dst"
"#;
    let m: Config = toml::from_str(minimal).expect("minimal profile must parse");
    let d = Config::new("/src", "/dst");
    assert_eq!(format!("{:?}", m), format!("{:?}", d));
    assert_eq!(m.backup_mode, "incremental");
    assert_eq!(m.channel_buffer_size, 8192);
    assert_eq!(
        m.exclude_patterns,
        DEFAULT_EXCLUDE_PATTERNS
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    );

    // Serializar Config::default() não introduz chaves novas: o resultado
    // volta a ser lido como o mesmo Config.
    let s = toml::to_string(&d).unwrap();
    let back: Config = toml::from_str(&s).unwrap();
    assert_eq!(format!("{:?}", back), format!("{:?}", d));
}
