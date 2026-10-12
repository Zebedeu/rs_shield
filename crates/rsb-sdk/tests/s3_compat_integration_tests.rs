// Testes de integração contra um servidor S3-compatível real (MinIO, R2,
// B2, Wasabi, Ceph RGW, Garage, ...). Só correm quando estas variáveis de
// ambiente estão definidas; caso contrário são ignorados (passam sem fazer
// nada):
//
//   RSB_TEST_S3_ENDPOINT    ex.: http://localhost:9000
//   RSB_TEST_S3_BUCKET      bucket DEDICADO a testes (deve estar vazio)
//   RSB_TEST_S3_ACCESS_KEY
//   RSB_TEST_S3_SECRET_KEY
//   RSB_TEST_S3_REGION      opcional (por omissão us-east-1; R2 usa "auto")
//
// Exemplo com MinIO local:
//   docker run -p 9000:9000 -e MINIO_ROOT_USER=minio -e MINIO_ROOT_PASSWORD=minio123 \
//     minio/minio server /data
//   (criar o bucket `rsb-test`) e depois
//   RSB_TEST_S3_ENDPOINT=http://localhost:9000 RSB_TEST_S3_BUCKET=rsb-test \
//   RSB_TEST_S3_ACCESS_KEY=minio RSB_TEST_S3_SECRET_KEY=minio123 \
//   cargo test -p rsb-sdk --test s3_compat_integration_tests

use rsb_sdk::backup::perform_backup;
use rsb_sdk::config::Config;
use rsb_sdk::core::{perform_prune_with_storage, perform_restore};
use rsb_sdk::integrity::perform_verify;
use rsb_sdk::storage::{LockKind, RepoLock, S3Storage, Storage};
use rsb_sdk::{BackupOptions, RestoreOptions, VerifyOptions};
use std::io::ErrorKind;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

struct Env {
    endpoint: String,
    bucket: String,
    region: Option<String>,
    access_key: String,
    secret_key: String,
}

fn env() -> Option<Env> {
    let get = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    let env = Env {
        endpoint: get("RSB_TEST_S3_ENDPOINT")?,
        bucket: get("RSB_TEST_S3_BUCKET")?,
        region: get("RSB_TEST_S3_REGION"),
        access_key: get("RSB_TEST_S3_ACCESS_KEY")?,
        secret_key: get("RSB_TEST_S3_SECRET_KEY")?,
    };
    Some(env)
}

async fn storage(env: &Env) -> Arc<dyn Storage> {
    let creds = aws_credential_types::Credentials::new(
        env.access_key.clone(),
        env.secret_key.clone(),
        None,
        None,
        "rsb-test",
    );
    Arc::new(
        S3Storage::new(
            &env.bucket,
            env.region.clone(),
            Some(env.endpoint.clone()),
            creds,
        )
        .await,
    )
}

#[tokio::test]
async fn s3_basic_operations_are_provider_compatible() {
    let Some(env) = env() else {
        eprintln!("skipped: RSB_TEST_S3_* not set");
        return;
    };
    let s = storage(&env).await;
    let base = format!("rsb-compat-test-{}", uuid::Uuid::new_v4().simple());
    let a = format!("{}/dir/a.bin", base);
    let b = format!("{}/dir/b.bin", base);
    let other = format!("{}/dirX/c.bin", base);
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();

    s.write(&a, &payload).await.unwrap();
    s.write(&b, b"bee").await.unwrap();
    s.write(&other, b"x").await.unwrap();

    assert_eq!(s.read(&a).await.unwrap(), payload);
    let mut r = s.read_stream(&a).await.unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, payload);

    assert_eq!(s.size(&b).await.unwrap(), Some(3));
    assert!(s.exists(&b).await.unwrap());
    assert!(s.exists(&format!("{}/dir/", base)).await.unwrap());

    // HEAD/GET de objeto inexistente: 404 (sem corpo no HEAD) ⇒ None/NotFound.
    let missing = format!("{}/dir/missing", base);
    assert_eq!(s.size(&missing).await.unwrap(), None);
    assert!(!s.exists(&missing).await.unwrap());
    assert_eq!(
        s.read(&missing).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert!(!s.exists(&format!("{}/nodir/", base)).await.unwrap());

    // list com semântica de diretório: "dir" não apanha "dirX".
    let mut listed = s.list(&format!("{}/dir", base)).await.unwrap();
    listed.sort();
    assert_eq!(listed, vec![a.clone(), b.clone()]);

    for k in [&a, &b, &other] {
        s.delete(k).await.unwrap();
    }
    assert!(s.list(&base).await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_full_cycle_and_lock() {
    let Some(env) = env() else {
        eprintln!("skipped: RSB_TEST_S3_* not set");
        return;
    };
    let s = storage(&env).await;
    // O ciclo escreve na raiz do bucket (snapshots/, data/, locks/) e faz
    // prune: recusa correr num bucket que já tenha um repositório.
    for dir in ["snapshots", "data", "locks"] {
        assert!(
            s.list(dir).await.unwrap().is_empty(),
            "RSB_TEST_S3_BUCKET must be a dedicated, empty test bucket ('{}/' is not empty)",
            dir
        );
    }

    // Lock do repositório só com PUT/LIST/GET/DELETE (sem escritas
    // condicionais).
    let shared = RepoLock::acquire(s.clone(), LockKind::Shared, "backup")
        .await
        .unwrap();
    assert!(
        RepoLock::acquire(s.clone(), LockKind::Exclusive, "prune")
            .await
            .is_err()
    );
    shared.release().await.unwrap();

    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("a.txt"), b"alpha ".repeat(100)).unwrap();
    std::fs::write(src.path().join("b.txt"), b"bravo").unwrap();
    let key = Some("s3 compat key");
    let config = Config {
        source_path: src.path().to_string_lossy().into_owned(),
        exclude_patterns: vec![],
        encryption_key: key.map(str::to_string),
        ..Default::default()
    };
    let backup = || {
        BackupOptions {
            storage: Some(s.clone()),
            max_threads: Some(2),
            ..Default::default()
        }
        .with_encryption_key(key)
    };

    perform_backup(&config, backup()).await.unwrap();
    std::fs::write(src.path().join("b.txt"), b"bravo v2").unwrap();
    perform_backup(&config, backup()).await.unwrap();

    let report = perform_verify(
        &config,
        VerifyOptions {
            storage: Some(s.clone()),
            quiet: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);

    let out = tempfile::tempdir().unwrap();
    let report = perform_restore(
        &config,
        RestoreOptions {
            storage: Some(s.clone()),
            ..RestoreOptions::new(out.path())
        }
        .with_encryption_key(key),
    )
    .await
    .unwrap();
    assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);
    assert_eq!(
        std::fs::read(out.path().join("b.txt")).unwrap(),
        b"bravo v2"
    );

    perform_prune_with_storage(s.clone(), key, 1).await.unwrap();
    assert_eq!(s.list("snapshots").await.unwrap().len(), 1);

    // Limpeza.
    for dir in ["snapshots", "data/clear", "data/enc", "locks"] {
        for k in s.list(dir).await.unwrap() {
            s.delete(&k).await.unwrap();
        }
    }
}
