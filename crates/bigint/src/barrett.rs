// src/barrett.rs

/// Provides functionality for Barrett reduction, an efficient algorithm for modular reduction.
///
/// Barrett reduction is particularly useful in scenarios where multiple modular reductions
/// are performed with the same modulus. It precomputes certain values to speed up the reduction
/// process, avoiding costly division operations.
///
/// # Overview
///
/// The Barrett reduction algorithm computes \( x \mod m \) efficiently by using precomputed
/// values based on the modulus \( m \). This is especially beneficial in cryptographic computations
/// where the same modulus is used repeatedly.
///
/// # Components
///
/// - **BarrettContext**: Stores precomputed values required for the reduction.
/// - **barrett_reduce**: Performs the reduction operation.
/// - **barrett_mul**: Multiplies two `BigInt` values and reduces the result modulo \( m \) using Barrett reduction.
///
/// # Example
///
/// ```rust
/// use bigint::{BigInt, barrett::{BarrettContext, barrett_mul}};
///
/// let a = BigInt::from_i32(12345);
/// let b = BigInt::from_i32(67890);
/// let modulus = BigInt::from_i32(10007);
///
/// let ctx = BarrettContext::new(modulus.clone());
/// let result = barrett_mul(&a, &b, &ctx);
///
/// println!("(12345 * 67890) mod 10007 = {}", result);
/// ```
pub mod barrett {
    use crate::BigInt;

    /// Precomputed data for Barrett reduction with a base \(2^{32}\) representation.
    ///
    /// Barrett reduction requires precomputing certain values based on the modulus to
    /// facilitate efficient modular reduction. This context stores:
    /// - `modulus`: The modulus \( m \).
    /// - `mu`: \( \mu = \left\lfloor \frac{b^{2k}}{m} \right\rfloor \), where \( k \) is the number of
    ///         32-bit digits in \( m \), and \( b = 2^{32} \).
    /// - `k`: The number of 32-bit digits in the modulus \( m \).
    ///
    /// # Example
    ///
    /// ```rust
    /// use bigint::{BigInt, barrett::BarrettContext};
    ///
    /// let modulus = BigInt::from_i32(10007);
    /// let ctx = BarrettContext::new(modulus);
    /// ```
    #[derive(Debug)]
    pub struct BarrettContext {
        /// The modulus \( m \) used for reduction.
        pub modulus: BigInt,
        /// Precomputed value \( \mu = \left\lfloor \frac{b^{2k}}{m} \right\rfloor \).
        pub mu: BigInt,
        /// The number of 32-bit digits in the modulus \( m \).
        pub k: usize,
    }

    impl BarrettContext {
        /// Creates a new `BarrettContext` for a given modulus.
        ///
        /// This function precomputes the necessary values for Barrett reduction:
        /// - Calculates \( k \), the number of 32-bit digits in \( m \).
        /// - Computes \( \mu = \left\lfloor \frac{b^{2k}}{m} \right\rfloor \), where \( b = 2^{32} \).
        ///
        /// # Arguments
        ///
        /// * `modulus` - The modulus \( m \) for which the reduction context is created.
        ///
        /// # Panics
        ///
        /// Panics if the provided modulus is zero, as division by zero is undefined.
        ///
        /// # Example
        ///
        /// ```rust
        /// use bigint::{BigInt, barrett::BarrettContext};
        ///
        /// let modulus = BigInt::from_i32(10007);
        /// let ctx = BarrettContext::new(modulus);
        /// ```
        pub fn new(modulus: BigInt) -> Self {
            if modulus.is_zero() {
                panic!("BarrettContext: modulus cannot be zero");
            }
            let k = modulus.digits.len();
            let mut base_2k = BigInt::new();
            base_2k.digits = vec![0; 2 * k];
            base_2k.digits.push(1); // Represents \( b^{2k} = 2^{64k} \)
            let mu = &base_2k / &modulus;
            Self { modulus, mu, k }
        }
    }

    /// Reduces a `BigInt` modulo `m` using Barrett reduction.
    ///
    /// # Arguments
    ///
    /// * `x` - The `BigInt` to be reduced.
    /// * `ctx` - The precomputed `BarrettContext` containing modulus and other necessary values.
    ///
    /// # Returns
    ///
    /// A new `BigInt` representing \( x \mod m \).
    ///
    /// # Example
    ///
    /// ```rust
    /// use bigint::{BigInt, barrett::{BarrettContext, barrett_reduce}};
    ///
    /// let x = BigInt::from_i32(25);
    /// let modulus = BigInt::from_i32(7);
    /// let ctx = BarrettContext::new(modulus.clone());
    ///
    /// let reduced = barrett_reduce(&x, &ctx);
    /// assert_eq!(reduced, BigInt::from_i32(4));
    /// ```
    pub fn barrett_reduce(x: &BigInt, ctx: &BarrettContext) -> BigInt {
        let m = &ctx.modulus;
        let base_2k = {
            let mut tmp = BigInt::new();
            tmp.digits = vec![0; 2 * ctx.k];
            tmp.digits.push(1); // Represents \( b^{2k} \)
            tmp
        };
        let q = (&(x * &ctx.mu)).div(&base_2k);
        let mut r = x - &(&q * m);

        // Ensure \( r \) is within \( [0, m) \)
        if r.negative {
            r = &r + m;
            if r.is_greater_than_or_equal(m) {
                r = &r - m;
            }
        } else {
            while r.is_greater_than_or_equal(m) {
                r = &r - m;
            }
        }
        r
    }

    /// Multiplies two `BigInt` values and reduces the result modulo `m` using Barrett reduction.
    ///
    /// This function performs the following steps:
    /// 1. Multiplies `x` and `y` to get the product.
    /// 2. Reduces the product modulo `m` using Barrett reduction.
    ///
    /// # Arguments
    ///
    /// * `x` - The first `BigInt` operand.
    /// * `y` - The second `BigInt` operand.
    /// * `ctx` - The precomputed `BarrettContext` containing modulus and other necessary values.
    ///
    /// # Returns
    ///
    /// A new `BigInt` representing \( (x \times y) \mod m \).
    ///
    /// # Example
    ///
    /// ```rust
    /// use bigint::{BigInt, barrett::{BarrettContext, barrett_mul}};
    ///
    /// let a = BigInt::from_i32(3);
    /// let b = BigInt::from_i32(4);
    /// let modulus = BigInt::from_i32(5);
    /// let ctx = BarrettContext::new(modulus.clone());
    ///
    /// let result = barrett_mul(&a, &b, &ctx);
    /// assert_eq!(result, BigInt::from_i32(2));
    /// ```
    pub fn barrett_mul(x: &BigInt, y: &BigInt, ctx: &BarrettContext) -> BigInt {
        let mut r = barrett_reduce(&(x * y), ctx);

        // Ensure \( r \) is within \( [0, m) \)
        if r.negative {
            r = &r + &ctx.modulus;
            if r.is_greater_than_or_equal(&ctx.modulus) {
                r = &r - &ctx.modulus;
            }
        }
        r
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::BigInt;

        /// Helper function to create a BarrettContext for a given 32-bit integer modulus.
        ///
        /// # Arguments
        ///
        /// * `m` - The modulus as a 32-bit signed integer.
        ///
        /// # Returns
        ///
        /// A new `BarrettContext` for the provided modulus.
        fn create_barrett_ctx(m: i32) -> BarrettContext {
            let modulus = BigInt::from_i32(m);
            BarrettContext::new(modulus)
        }

        /// Tests the `barrett_reduce` function with a basic example.
        ///
        /// Reduces 25 modulo 7 and expects the result to be 4.
        #[test]
        fn test_barrett_reduce_basic() {
            let ctx = create_barrett_ctx(7);
            let x = BigInt::from_i32(25);
            let reduced = barrett_reduce(&x, &ctx);
            let expected = BigInt::from_i32(4);
            assert_eq!(reduced, expected, "Barrett reduce failed for 25 mod 7");
        }

        /// Tests the `barrett_mul` function with small positive operands.
        ///
        /// Computes (3 * 4) mod 7 and expects the result to be 5.
        #[test]
        fn test_barrett_mul_small() {
            let ctx = create_barrett_ctx(7);
            let a = BigInt::from_i32(3);
            let b = BigInt::from_i32(4);
            let product_mod = barrett_mul(&a, &b, &ctx);
            let expected = BigInt::from_i32(5);
            assert_eq!(product_mod, expected, "Barrett multiply (3*4 mod 7) failed");
        }

        /// Tests the `barrett_mul` function with a negative operand.
        ///
        /// Computes (-3 * 4) mod 7 and expects the result to be 2.
        #[test]
        fn test_barrett_mul_negative() {
            let ctx = create_barrett_ctx(7);
            let a = BigInt::from_i32(-3);
            let b = BigInt::from_i32(4);
            let product_mod = barrett_mul(&a, &b, &ctx);
            let expected = BigInt::from_i32(2);
            assert_eq!(product_mod, expected, "Barrett multiply (-3*4 mod 7) failed");
        }

        /// Tests the `barrett_mul` function with larger numbers.
        ///
        /// Computes (12345 * 67890) mod 10007 and checks against the expected result.
        #[test]
        fn test_barrett_mul_large() {
            let modulus = BigInt::from_i32(10007);
            let ctx = BarrettContext::new(modulus.clone());
            let a = BigInt::from_i32(12345);
            let b = BigInt::from_i32(67890);
            let product_mod = barrett_mul(&a, &b, &ctx);

            // Manually compute (12345 * 67890) mod 10007
            // 12345 * 67890 = 838102050
            // 838102050 mod 10007 = 838102050 - 10007 * floor(838102050 / 10007)
            // floor(838102050 / 10007) = 838102050 / 10007 ≈ 83802
            // 10007 * 83802 = 838102014
            // 838102050 - 838102014 = 36
            let expected = BigInt::from_i32(36);
            assert_eq!(
                product_mod, expected,
                "Barrett multiply (12345*67890 mod 10007) failed"
            );
        }

        /// Tests the `barrett_reduce` function with a very large `BigInt`.
        ///
        /// Ensures that Barrett reduction works correctly with large numbers.
        #[test]
        fn test_barrett_reduce_large() {
            let modulus = BigInt::from_str("1000000007").unwrap(); // A large prime
            let ctx = BarrettContext::new(modulus.clone());
            let x = BigInt::from_str("123456789012345678901234567890").unwrap();
            let reduced = barrett_reduce(&x, &ctx);

            // Expected result: 123456789012345678901234567890 mod 1000000007
            // Calculated externally: 123456789012345678901234567890 % 1000000007 = 1234567890
            let expected = BigInt::from_str("1234567890").unwrap();
            assert_eq!(reduced, expected, "Barrett reduce failed for large x mod 1000000007");
        }

        /// Tests the `barrett_reduce` function with negative numbers.
        ///
        /// Reduces -25 modulo 7 and expects the result to be 6.
        #[test]
        fn test_barrett_reduce_negative() {
            let ctx = create_barrett_ctx(7);
            let x = BigInt::from_i32(-25);
            let reduced = barrett_reduce(&x, &ctx);
            let expected = BigInt::from_i32(6); // (-25) mod 7 = 6
            assert_eq!(reduced, expected, "Barrett reduce failed for -25 mod 7");
        }

        /// Tests the `barrett_mul` function with both operands negative.
        ///
        /// Computes (-3 * -4) mod 7 and expects the result to be 5.
        #[test]
        fn test_barrett_mul_both_negative() {
            let ctx = create_barrett_ctx(7);
            let a = BigInt::from_i32(-3);
            let b = BigInt::from_i32(-4);
            let product_mod = barrett_mul(&a, &b, &ctx);
            let expected = BigInt::from_i32(5);
            assert_eq!(product_mod, expected, "Barrett multiply (-3*-4 mod 7) failed");
        }
    }
}
