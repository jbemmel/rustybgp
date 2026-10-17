//! Single-threaded benchmark support. Counts allocations only inside timed loops.
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

pub struct CountingAllocator;
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: all operations delegate unchanged to System; the counter owns no memory.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, size) }
    }
}

pub fn measure(label: &str, mut operation: impl FnMut(usize) -> u64, zero_allocations: bool) {
    let iterations = std::env::var("AS_PATH_BENCH_ITERATIONS")
        .map(|s| s.parse::<usize>().expect("positive iteration count"))
        .unwrap_or(100_000);
    assert!(iterations > 0);
    for i in 0..10_000 {
        black_box(operation(black_box(i)));
    }
    let mut samples = Vec::new();
    let mut expected = None;
    let mut allocations_per_op = 0.;
    for _ in 0..7 {
        ALLOCATIONS.store(0, Ordering::Relaxed);
        let start = Instant::now();
        let mut checksum = 0u64;
        for i in 0..iterations {
            checksum = checksum.wrapping_add(black_box(operation(black_box(i))));
        }
        let elapsed = start.elapsed();
        let allocations = ALLOCATIONS.load(Ordering::Relaxed);
        if zero_allocations {
            assert_eq!(allocations, 0, "unexpected allocation in {label}");
        }
        assert_eq!(*expected.get_or_insert(checksum), checksum);
        allocations_per_op = allocations as f64 / iterations as f64;
        samples.push(elapsed.as_nanos() as f64 / iterations as f64);
    }
    samples.sort_by(f64::total_cmp);
    println!(
        "{label},{:.2},{allocations_per_op:.3},{},{}",
        samples[3], samples[0], samples[6]
    );
}
