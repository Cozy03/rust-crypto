// benches/multiplication.rs
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use bigint::BigInt;

fn bench_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("Multiplication");
    
    // Test with different input sizes
    let sizes = [8, 16, 32, 64, 128, 256, 512, 1024];
    
    for size in sizes.iter() {
        // Create test numbers with specified number of hex digits
        let a = BigInt::from_hex(&"F".repeat(*size)).unwrap();
        let b = BigInt::from_hex(&"F".repeat(*size)).unwrap();

        // Benchmark schoolbook multiplication
        group.bench_with_input(
            BenchmarkId::new("schoolbook", size), 
            size,
            |bencher, _| {
                bencher.iter(|| a.mul_schoolbook(&b));
            }
        );

        // Benchmark Karatsuba multiplication
        group.bench_with_input(
            BenchmarkId::new("karatsuba", size), 
            size,
            |bencher, _| {
                bencher.iter(|| a.mul_karatsuba(&b));
            }
        );
    }

    group.finish();
}

criterion_group!(benches, bench_multiplication);
criterion_main!(benches);
