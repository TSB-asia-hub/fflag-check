pub mod process_scanner;
pub mod file_scanner;
pub mod client_settings_scanner;
pub mod prefetch_scanner;
pub mod memory_scanner;

use crate::models::ScanFinding;

/// Run all scanners and collect findings. Each scanner is dispatched via
/// `spawn_blocking` so its synchronous I/O (sysinfo, WalkDir, std::fs,
/// winapi) does not stall the tokio runtime worker — this also gives us
/// real concurrency, not the implicit serialization that `tokio::join!` of
/// blocking-bodied async fns would produce.
pub async fn run_all_scans() -> Vec<ScanFinding> {
    let process_handle =
        tokio::task::spawn_blocking(|| futures_block_on(process_scanner::scan()));
    let file_handle = tokio::task::spawn_blocking(|| futures_block_on(file_scanner::scan()));
    let client_handle =
        tokio::task::spawn_blocking(|| futures_block_on(client_settings_scanner::scan()));
    let prefetch_handle =
        tokio::task::spawn_blocking(|| futures_block_on(prefetch_scanner::scan()));
    let memory_handle =
        tokio::task::spawn_blocking(|| futures_block_on(memory_scanner::scan()));

    let mut all_findings = Vec::new();
    for handle in [
        process_handle,
        file_handle,
        client_handle,
        prefetch_handle,
        memory_handle,
    ] {
        match handle.await {
            Ok(mut findings) => all_findings.append(&mut findings),
            Err(e) => {
                all_findings.push(ScanFinding::new(
                    "scanner_runtime",
                    crate::models::ScanVerdict::Suspicious,
                    format!("Scanner task panicked: {}", e),
                    None,
                ));
            }
        }
    }
    all_findings
}

/// The scanner functions themselves are still `async fn` (their bodies are
/// synchronous but the signatures must stay compatible with the existing
/// trait). We block on each future synchronously inside the spawn_blocking
/// closure using a tiny one-task runtime — this avoids dragging the heavy
/// tokio runtime features in just to drive a synchronous body.
fn futures_block_on<F: std::future::Future>(fut: F) -> F::Output {
    use std::pin::Pin;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;
    impl Wake for NoopWaker {
        fn wake(self: std::sync::Arc<Self>) {}
    }
    let waker = Waker::from(std::sync::Arc::new(NoopWaker));
    let mut cx = Context::from_waker(&waker);
    let mut fut: Pin<Box<F>> = Box::pin(fut);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        // The scanners never yield to the runtime, so a Ready arrives on the
        // first poll. The loop is defensive only.
    }
}
