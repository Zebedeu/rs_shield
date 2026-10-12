//! One-shot performance probe: wall time, throughput, peak RSS and storage
//! calls for every fixture, clear and encrypted, on local storage and on
//! local storage behind a latency-injected wrapper (models S3).
//!
//! ```text
//! cargo bench -p rsb-sdk --bench perf_probe            # full profile
//! RSB_BENCH_PROFILE=quick cargo bench -p rsb-sdk --bench perf_probe
//! cargo bench -p rsb-sdk --bench perf_probe -- --only large --enc 1
//! ```
//!
//! Every measured operation runs in its own child process (this binary
//! re-executed with `child ...`), so the peak RSS reported is that of the
//! operation alone (fixture generation happens in the parent).
//!
//! Options: `--only small|large|incr|small-lat|large-lat` (repeatable),
//! `--enc 0|1`, `--latency-ms N` (default 20), `--dir PATH` (work dir,
//! default a temp dir). Environment: `RSB_BENCH_THREADS` (backup threads),
//! `RSB_BENCH_*` fixture sizes (see `support`).

mod support;

use rsb_sdk::storage::{InstrumentedStorage, LocalStorage, Storage};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use support::*;

struct Args {
    only: Vec<String>,
    enc: Option<bool>,
    latency_ms: u64,
    dir: Option<PathBuf>,
}

fn parse_args() -> (Vec<String>, Args) {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut args = Args {
        only: vec![],
        enc: None,
        latency_ms: 20,
        dir: None,
    };
    let mut positional = vec![];
    let mut it = raw.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--only" => args.only.push(it.next().unwrap()),
            "--enc" => args.enc = Some(it.next().unwrap() == "1"),
            "--latency-ms" => args.latency_ms = it.next().unwrap().parse().unwrap(),
            "--dir" => args.dir = Some(PathBuf::from(it.next().unwrap())),
            // Passed by `cargo bench`.
            "--bench" => {}
            _ => positional.push(a),
        }
    }
    (positional, args)
}

fn main() {
    let (positional, args) = parse_args();
    if positional.first().map(String::as_str) == Some("child") {
        child(&positional[1..]);
        return;
    }
    parent(args);
}

// ------------------------------------------------------------------ child

/// `child <backup|restore> <src-or-out> <repo> <enc 0|1> <latency ms>`
/// Prints one line: `RESULT wall_ms rss_bytes put get head list list_pages delete`.
fn child(a: &[String]) {
    let op = a[0].as_str();
    let path = PathBuf::from(&a[1]);
    // Fixture helpers, for profiling a single operation by hand:
    // `child gen <small|large|small-lat> <dir>`, `child mutate <small|small-lat> <dir> <round>`.
    let spec_of = |name: &str| match name {
        "small" => small_files(Profile::from_env()),
        "small-lat" => small_files_latency(Profile::from_env()),
        _ => large_files(Profile::from_env()),
    };
    match op {
        "gen" => return generate(&spec_of(&a[1]), Path::new(&a[2])),
        "mutate" => {
            mutate_one_percent(&spec_of(&a[1]), Path::new(&a[2]), a[3].parse().unwrap());
            return;
        }
        _ => {}
    }
    let repo = a[2].clone();
    let enc = a[3] == "1";
    let latency = Duration::from_millis(a[4].parse().unwrap());
    let key = enc.then_some(PASSWORD);
    let rt = runtime();
    let storage = Arc::new(InstrumentedStorage::with_latency(
        Arc::new(LocalStorage::new(&repo)),
        latency,
    ));
    let start = Instant::now();
    rt.block_on(async {
        match op {
            "backup" => {
                backup(&path, storage.clone() as Arc<dyn Storage>, key).await;
            }
            "restore" => {
                restore(&*storage, &path, key).await;
            }
            _ => panic!("unknown op {op}"),
        }
    });
    let wall = start.elapsed();
    let c = storage.counts();
    println!(
        "RESULT {} {} {} {} {} {} {} {}",
        wall.as_millis(),
        peak_rss_bytes(),
        c.put,
        c.get,
        c.head,
        c.list,
        c.list_pages,
        c.delete
    );
}

// ----------------------------------------------------------------- parent

struct Measure {
    wall_ms: u64,
    rss: u64,
    calls: [u64; 6],
}

fn run_child(op: &str, path: &Path, repo: &Path, enc: bool, latency_ms: u64) -> Measure {
    let exe = std::env::current_exe().unwrap();
    let out = Command::new(exe)
        .arg("child")
        .arg(op)
        .arg(path)
        .arg(repo)
        .arg(if enc { "1" } else { "0" })
        .arg(latency_ms.to_string())
        .output()
        .expect("spawn child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "child {op} failed:\n{}\n{}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    let line = stdout
        .lines()
        .find(|l| l.starts_with("RESULT "))
        .expect("child result");
    let v: Vec<u64> = line[7..]
        .split_whitespace()
        .map(|x| x.parse().unwrap())
        .collect();
    Measure {
        wall_ms: v[0],
        rss: v[1],
        calls: [v[2], v[3], v[4], v[5], v[6], v[7]],
    }
}

fn row(name: &str, op: &str, enc: bool, storage: &str, bytes: u64, m: &Measure) {
    let secs = (m.wall_ms.max(1)) as f64 / 1000.0;
    let mibs = bytes as f64 / (1024.0 * 1024.0) / secs;
    println!(
        "| {name} | {op} | {} | {storage} | {:.2} | {:.1} | {} | PUT {} / GET {} / HEAD {} / LIST {} |",
        if enc { "enc" } else { "clear" },
        secs,
        mibs,
        m.rss / (1024 * 1024),
        m.calls[0],
        m.calls[1],
        m.calls[2],
        m.calls[4],
    );
}

fn parent(args: Args) {
    let profile = Profile::from_env();
    let tmp;
    let work = match &args.dir {
        Some(d) => {
            std::fs::create_dir_all(d).unwrap();
            d.clone()
        }
        None => {
            tmp = tempfile::tempdir().unwrap();
            tmp.path().to_path_buf()
        }
    };
    // Children keep their dedup index files in the work dir, not in the
    // user's cache dir.
    if std::env::var_os("RSB_BENCH_INDEX_DIR").is_none() {
        // SAFETY: single-threaded here (no child process or runtime yet).
        unsafe { std::env::set_var("RSB_BENCH_INDEX_DIR", work.join("index-cache")) };
    }
    let want = |n: &str| args.only.is_empty() || args.only.iter().any(|o| o == n);
    let encs: Vec<bool> = match args.enc {
        Some(e) => vec![e],
        None => vec![false, true],
    };

    println!("profile: {:?}, latency: {} ms", profile, args.latency_ms);
    println!("| fixture | op | mode | storage | wall s | MiB/s | peak RSS MiB | storage calls |");
    println!("|---|---|---|---|---|---|---|---|");

    let lat = args.latency_ms;
    let cases: Vec<(FixtureSpec, &str, u64)> = vec![
        (small_files(profile), "small", 0),
        (large_files(profile), "large", 0),
        (small_files_latency(profile), "small-lat", lat),
        (large_files(profile), "large-lat", lat),
    ];
    for (spec, name, latency) in cases {
        if !want(name) {
            continue;
        }
        let src = work.join(format!("src-{name}"));
        generate(&spec, &src);
        let storage_name = if latency > 0 { "latency" } else { "local" };
        for &enc in &encs {
            let repo = work.join("repo");
            let out = work.join("out");
            let _ = std::fs::remove_dir_all(&repo);
            let _ = std::fs::remove_dir_all(&out);
            let b = run_child("backup", &src, &repo, enc, latency);
            row(name, "backup", enc, storage_name, spec.total_bytes(), &b);
            let r = run_child("restore", &out, &repo, enc, latency);
            row(name, "restore", enc, storage_name, spec.total_bytes(), &r);
            let _ = std::fs::remove_dir_all(&out);
            let _ = std::fs::remove_dir_all(&repo);
        }
        let _ = std::fs::remove_dir_all(&src);
    }

    // (c) incremental: 1% of the small files changed since the last backup.
    for (name, latency, spec) in [
        ("incr", 0, small_files(profile)),
        ("incr-lat", lat, small_files_latency(profile)),
    ] {
        if !want(name) {
            continue;
        }
        let src = work.join(format!("src-{name}"));
        generate(&spec, &src);
        let storage_name = if latency > 0 { "latency" } else { "local" };
        for &enc in &encs {
            let repo = work.join("repo");
            let _ = std::fs::remove_dir_all(&repo);
            run_child("backup", &src, &repo, enc, 0);
            // A different round per mode: each mode sees 1% of new content.
            let changed = mutate_one_percent(&spec, &src, 1 + enc as u64);
            let m = run_child("backup", &src, &repo, enc, latency);
            row(
                name,
                "backup 1%",
                enc,
                storage_name,
                changed as u64 * spec.file_size,
                &m,
            );
            let _ = std::fs::remove_dir_all(&repo);
        }
        let _ = std::fs::remove_dir_all(&src);
    }
}
