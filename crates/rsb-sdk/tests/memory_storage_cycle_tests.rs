// Ciclo completo backup → restore → verify → prune num `MemoryStorage`
// injetado: prova que as operações usam o storage recebido em vez de
// construir um a partir do `Config` (o destino em disco nunca é criado).

use rsb_sdk::backup::perform_backup;
use rsb_sdk::config::Config;
use rsb_sdk::core::{
    perform_prune_with_storage, perform_restore, plan_prune_by_count_with_storage,
};
use rsb_sdk::integrity::perform_verify;
use rsb_sdk::storage::{MemoryStorage, Storage};
use rsb_sdk::{BackupOptions, RestoreOptions, VerifyOptions};
use std::path::Path;
use std::sync::Arc;

fn snapshots(storage: &MemoryStorage) -> Vec<String> {
    storage
        .keys()
        .into_iter()
        .filter(|k| k.starts_with("snapshots/") && k.ends_with(".toml"))
        .collect()
}

fn data_objects(storage: &MemoryStorage, kind: &str) -> usize {
    let prefix = format!("data/{}/", kind);
    storage
        .keys()
        .iter()
        .filter(|k| k.starts_with(&prefix))
        .count()
}

async fn cycle(key: Option<&str>) {
    let src = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    // Destino que nunca deve ser criado: tudo vai para o MemoryStorage.
    let fake_dest = work.path().join("must-not-exist");
    let config = Config {
        source_path: src.path().to_string_lossy().into_owned(),
        destination_path: fake_dest.to_string_lossy().into_owned(),
        exclude_patterns: vec![],
        encryption_key: key.map(str::to_string),
        compression_level: Some(3),
        max_threads: Some(2),
        ..Default::default()
    };
    let mem = Arc::new(MemoryStorage::new());
    let storage: Arc<dyn Storage> = mem.clone();
    let kind = if key.is_some() { "enc" } else { "clear" };

    let backup = |mode: &str| {
        BackupOptions {
            mode: Some(mode.to_string()),
            max_threads: Some(2),
            storage: Some(storage.clone()),
            ..Default::default()
        }
        .with_encryption_key(key)
    };
    let verify = || VerifyOptions {
        quiet: true,
        storage: Some(storage.clone()),
        ..Default::default()
    };

    // 1) Primeiro backup.
    std::fs::write(src.path().join("a.txt"), b"alpha ".repeat(200)).unwrap();
    std::fs::create_dir_all(src.path().join("sub")).unwrap();
    std::fs::write(src.path().join("sub/b.txt"), b"bravo").unwrap();
    let report = perform_backup(&config, backup("full")).await.unwrap();
    assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);
    assert_eq!(report.files_processed, 2);
    assert_eq!(snapshots(&mem).len(), 1);
    assert_eq!(data_objects(&mem, kind), 2);

    // 2) Verify completo.
    let report = perform_verify(&config, verify()).await.unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(report.files_processed, 2);

    // 3) Segundo backup com um ficheiro alterado (o antigo objeto fica
    //    referenciado só pelo primeiro snapshot).
    std::fs::write(src.path().join("sub/b.txt"), b"bravo v2").unwrap();
    perform_backup(&config, backup("incremental"))
        .await
        .unwrap();
    assert_eq!(snapshots(&mem).len(), 2);
    assert_eq!(data_objects(&mem, kind), 3);

    // 4) Restore do snapshot mais recente para disco.
    let out = tempfile::tempdir().unwrap();
    let opts = RestoreOptions {
        force: true,
        storage: Some(storage.clone()),
        ..RestoreOptions::new(out.path())
    }
    .with_encryption_key(key);
    let report = perform_restore(&config, opts).await.unwrap();
    assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);
    assert_restored(out.path(), b"bravo v2");

    // 5) Prune: mantém só o último snapshot e recolhe o objeto órfão.
    let plan = plan_prune_by_count_with_storage(&*storage, 1)
        .await
        .unwrap();
    assert_eq!(plan.len(), 1);
    perform_prune_with_storage(storage.clone(), key, 1)
        .await
        .unwrap();
    assert_eq!(snapshots(&mem).len(), 1);
    assert_eq!(data_objects(&mem, kind), 2);
    assert!(
        mem.keys().iter().all(|k| !k.starts_with("locks/")),
        "repository lock left behind: {:?}",
        mem.keys()
    );

    // 6) O repositório continua íntegro e restaurável depois do prune.
    let report = perform_verify(&config, verify()).await.unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let out2 = tempfile::tempdir().unwrap();
    let opts = RestoreOptions {
        storage: Some(storage.clone()),
        ..RestoreOptions::new(out2.path())
    }
    .with_encryption_key(key);
    perform_restore(&config, opts).await.unwrap();
    assert_restored(out2.path(), b"bravo v2");

    assert!(
        !fake_dest.exists(),
        "operations must not fall back to the config destination"
    );
}

fn assert_restored(root: &Path, b_content: &[u8]) {
    assert_eq!(
        std::fs::read(root.join("a.txt")).unwrap(),
        b"alpha ".repeat(200)
    );
    assert_eq!(std::fs::read(root.join("sub/b.txt")).unwrap(), b_content);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_cycle_on_memory_storage_clear() {
    cycle(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_cycle_on_memory_storage_encrypted() {
    cycle(Some("correct horse battery staple")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_key_fails_on_memory_storage() {
    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("a.txt"), b"alpha").unwrap();
    let config = Config {
        source_path: src.path().to_string_lossy().into_owned(),
        exclude_patterns: vec![],
        ..Default::default()
    };
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    perform_backup(
        &config,
        BackupOptions {
            storage: Some(storage.clone()),
            ..Default::default()
        }
        .with_encryption_key(Some("right")),
    )
    .await
    .unwrap();

    let out = tempfile::tempdir().unwrap();
    let opts = RestoreOptions {
        storage: Some(storage.clone()),
        ..RestoreOptions::new(out.path())
    }
    .with_encryption_key(Some("wrong"));
    assert!(perform_restore(&config, opts).await.is_err());
    assert!(!out.path().join("a.txt").exists());
}
