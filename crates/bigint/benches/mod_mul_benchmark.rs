use criterion::{black_box, criterion_group, criterion_main, Criterion};
use bigint::{barrett::barrett::BarrettContext, montgomery::montgomery::MontgomeryContext, BigInt};

fn normal_mod_mul(a: &BigInt, b: &BigInt, m: &BigInt) -> BigInt {
    // Simple mod-multiply: (a * b) % m
    (a * b).rem(m)
}

fn barrett_mod_mul(a: &BigInt, b: &BigInt, ctx: &BarrettContext) -> BigInt {
    // Use Barrett's barrett_mul
    bigint::barrett::barrett::barrett_mul(a, b, ctx)
}

fn montgomery_mod_mul(a: &BigInt, b: &BigInt, ctx: &MontgomeryContext) -> BigInt {
    // Convert a, b into Montgomery form, multiply, return the (already reduced) product.
    let a_mont = ctx.to_montgomery(a);
    let b_mont = ctx.to_montgomery(b);
    ctx.mont_mul(&a_mont, &b_mont)
}

fn bench_mod_mul(c: &mut Criterion) {
    // Some sample moduli
    // * Assuming `from_i64` exists (with special i64::MIN handling).
    // * Assuming `from_str` handles decimal strings.
    let moduli = [
        BigInt::from_i32(1234567891),
        BigInt::from_i64(1234567890123456789),
        // If from_str() fails for an extremely large number, handle the Result properly
        BigInt::from_str(
            "123456789012345678901234567890123456789012345678901234567890123456789\
             012345678901234567890123456789"
        ).expect("Invalid decimal"),
    ];

    // Example 'a' and 'b'
    let a = BigInt::from_i32(123456789);
    let b = BigInt::from_i32(987654321);

    for modulus in &moduli {
        // Build contexts
        let barrett_ctx = BarrettContext::new(modulus.clone());
        let montgomery_ctx = MontgomeryContext::new(modulus.clone());

        // For display in the benchmark name, we might just show a shortened version (like hex),
        // because printing the entire decimal for huge moduli is unwieldy.
        // We'll do .to_hex() and limit the length.
        let mod_hex = modulus.to_hex();
        let mod_summary = if mod_hex.len() > 20 {
            format!("{}..(len:{})", &mod_hex[..20], mod_hex.len())
        } else {
            mod_hex
        };

        let bench_name = format!("Normal Mod Mul (mod {})", mod_summary);
        c.bench_function(&bench_name, |bench| {
            bench.iter(|| normal_mod_mul(black_box(&a), black_box(&b), black_box(modulus)))
        });

        let bench_name = format!("Barrett Mod Mul (mod {})", mod_summary);
        c.bench_function(&bench_name, |bench| {
            bench.iter(|| barrett_mod_mul(black_box(&a), black_box(&b), black_box(&barrett_ctx)))
        });

        let bench_name = format!("Montgomery Mod Mul (mod {})", mod_summary);
        c.bench_function(&bench_name, |bench| {
            bench.iter(|| montgomery_mod_mul(black_box(&a), black_box(&b), black_box(&montgomery_ctx)))
        });
    }
}

criterion_group!(benches, bench_mod_mul);
criterion_main!(benches);
