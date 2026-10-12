// Testes para rsb-core/src/core/resource_monitor.rs

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

#[test]
fn test_resource_monitor_initialization() {
    // Test that we can create the atomic flags
    let should_pause = Arc::new(AtomicBool::new(false));
    let running = Arc::new(AtomicBool::new(true));

    assert!(!should_pause.load(Ordering::Relaxed));
    assert!(running.load(Ordering::Relaxed));
}

#[test]
fn test_atomic_bool_pause_flag() {
    let should_pause = Arc::new(AtomicBool::new(false));

    // Initially should not be paused
    assert!(!should_pause.load(Ordering::Relaxed));

    // Set to pause
    should_pause.store(true, Ordering::Relaxed);
    assert!(should_pause.load(Ordering::Relaxed));

    // Resume
    should_pause.store(false, Ordering::Relaxed);
    assert!(!should_pause.load(Ordering::Relaxed));
}

#[test]
fn test_atomic_bool_running_flag() {
    let running = Arc::new(AtomicBool::new(true));

    // Initially should be running
    assert!(running.load(Ordering::Relaxed));

    // Stop
    running.store(false, Ordering::Relaxed);
    assert!(!running.load(Ordering::Relaxed));

    // Resume
    running.store(true, Ordering::Relaxed);
    assert!(running.load(Ordering::Relaxed));
}

#[test]
fn test_atomic_bool_swap_operation() {
    let flag = Arc::new(AtomicBool::new(false));

    // Swap from false to true
    let previous = flag.swap(true, Ordering::Relaxed);
    assert!(!previous);
    assert!(flag.load(Ordering::Relaxed));

    // Swap from true to false
    let previous = flag.swap(false, Ordering::Relaxed);
    assert!(previous);
    assert!(!flag.load(Ordering::Relaxed));
}

#[test]
fn test_shared_pause_flag_between_threads() {
    let should_pause = Arc::new(AtomicBool::new(false));
    let should_pause_clone = should_pause.clone();
    // Two rendezvous: after the thread's first read, and after the store.
    let sync = Arc::new(std::sync::Barrier::new(2));
    let sync_clone = sync.clone();

    let thread_handle = thread::spawn(move || {
        // Thread sees initial state
        assert!(!should_pause_clone.load(Ordering::Relaxed));
        sync_clone.wait();
        sync_clone.wait();

        // Check if pause was set from main thread
        should_pause_clone.load(Ordering::Relaxed)
    });

    // Set pause from main thread
    sync.wait();
    should_pause.store(true, Ordering::Relaxed);
    sync.wait();

    let thread_saw_pause = thread_handle.join().unwrap();
    assert!(thread_saw_pause);
}

#[test]
fn test_shared_running_flag_between_threads() {
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    let (started_tx, started_rx) = std::sync::mpsc::channel();

    // Loops until told to stop: the test only finishes if the store is seen.
    let thread_handle = thread::spawn(move || {
        let mut iterations = 0u64;
        while running_clone.load(Ordering::Relaxed) {
            iterations += 1;
            if iterations == 1 {
                started_tx.send(()).unwrap();
            }
            thread::sleep(Duration::from_millis(1));
        }
        iterations
    });

    // Let thread run at least once
    started_rx.recv().unwrap();

    // Stop the thread
    running.store(false, Ordering::Relaxed);

    let iterations = thread_handle.join().unwrap();
    assert!(iterations > 0);
}

#[test]
fn test_pause_and_resume_cycle() {
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    let should_pause = Arc::new(AtomicBool::new(false));
    let running = Arc::new(AtomicBool::new(true));
    let paused_count = Arc::new(AtomicUsize::new(0));
    let resumed_count = Arc::new(AtomicUsize::new(0));

    let thread_handle = {
        let should_pause = should_pause.clone();
        let running = running.clone();
        let paused_count = paused_count.clone();
        let resumed_count = resumed_count.clone();
        thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                if should_pause.load(Ordering::Relaxed) {
                    paused_count.fetch_add(1, Ordering::Relaxed);
                } else {
                    resumed_count.fetch_add(1, Ordering::Relaxed);
                }
                thread::sleep(Duration::from_millis(1));
            }
        })
    };

    // Waits for the worker to observe a state instead of sleeping a fixed
    // time (fixed sleeps raced on loaded CI runners).
    let wait_until = |counter: &AtomicUsize, above: usize| {
        let deadline = Instant::now() + Duration::from_secs(10);
        while counter.load(Ordering::Relaxed) <= above {
            assert!(Instant::now() < deadline, "worker did not observe state");
            thread::sleep(Duration::from_millis(1));
        }
    };

    // Pause
    should_pause.store(true, Ordering::Relaxed);
    wait_until(&paused_count, 0);

    // Resume
    let resumed_before = resumed_count.load(Ordering::Relaxed);
    should_pause.store(false, Ordering::Relaxed);
    wait_until(&resumed_count, resumed_before);

    // Stop
    running.store(false, Ordering::Relaxed);
    thread_handle.join().unwrap();

    assert!(
        paused_count.load(Ordering::Relaxed) > 0,
        "Thread should have seen paused state"
    );
    assert!(
        resumed_count.load(Ordering::Relaxed) > resumed_before,
        "Thread should have seen resumed state"
    );
}

#[test]
fn test_rapid_pause_resume() {
    let should_pause = Arc::new(AtomicBool::new(false));

    // Rapidly toggle pause state
    for _ in 0..100 {
        should_pause.store(true, Ordering::Relaxed);
        should_pause.store(false, Ordering::Relaxed);
    }

    assert!(!should_pause.load(Ordering::Relaxed));
}

#[test]
fn test_multiple_thread_access() {
    let should_pause = Arc::new(AtomicBool::new(false));
    // The barrier orders the store before every load (sleeps raced on
    // loaded CI runners).
    let flag_set = Arc::new(std::sync::Barrier::new(6));
    let mut handles = vec![];

    for _ in 0..5 {
        let flag = should_pause.clone();
        let flag_set = flag_set.clone();
        let handle = thread::spawn(move || {
            flag_set.wait();
            flag.load(Ordering::Relaxed)
        });
        handles.push(handle);
    }

    // Set the flag while threads are running, then release them
    should_pause.store(true, Ordering::Relaxed);
    flag_set.wait();

    // All threads should see the updated value
    for handle in handles {
        let saw_pause = handle.join().unwrap();
        assert!(saw_pause);
    }
}

#[test]
fn test_pause_transition_detection() {
    let should_pause = Arc::new(AtomicBool::new(false));

    // Detect pause transition
    let was_paused = should_pause.swap(true, Ordering::Relaxed);
    assert!(!was_paused);

    // Detect resume transition
    let was_paused = should_pause.swap(false, Ordering::Relaxed);
    assert!(was_paused);
}

#[test]
fn test_atomic_operations_consistency() {
    let flag = Arc::new(AtomicBool::new(false));
    let flag_clone = flag.clone();

    let thread_handle = thread::spawn(move || {
        // Store true from thread
        flag_clone.store(true, Ordering::Relaxed);
    });

    thread_handle.join().unwrap();

    // Main thread should see the change
    assert!(flag.load(Ordering::Relaxed));
}

#[test]
fn test_long_running_monitoring_simulation() {
    let should_pause = Arc::new(AtomicBool::new(false));
    let running = Arc::new(AtomicBool::new(true));

    let should_pause_clone = should_pause.clone();
    let running_clone = running.clone();

    let thread_handle = thread::spawn(move || {
        let mut iterations = 0;
        // At least one cycle runs even if the stop lands before the thread
        // is scheduled.
        loop {
            if should_pause_clone.load(Ordering::Relaxed) {
                // Simulating paused state
                thread::sleep(Duration::from_millis(2));
            } else {
                // Simulating active work
                thread::sleep(Duration::from_millis(1));
            }
            iterations += 1;
            if !running_clone.load(Ordering::Relaxed) {
                break;
            }
        }
        iterations
    });

    // Simulate monitoring cycle: work, pause, work, stop
    thread::sleep(Duration::from_millis(25));
    should_pause.store(true, Ordering::Relaxed);
    thread::sleep(Duration::from_millis(25));
    should_pause.store(false, Ordering::Relaxed);
    thread::sleep(Duration::from_millis(25));
    running.store(false, Ordering::Relaxed);

    let iterations = thread_handle.join().unwrap();
    assert!(iterations > 0);
}
