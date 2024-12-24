// src/montgomery.rs

/// Provides functionality for Montgomery multiplication, an efficient algorithm for modular multiplication.
/// 
/// Montgomery multiplication is particularly useful in cryptographic computations, such as RSA and
/// Elliptic Curve Cryptography, where multiple modular multiplications with the same modulus are required.
/// It allows for faster computations by avoiding explicit division operations.
///
/// # Overview
///
/// The Montgomery reduction algorithm transforms numbers into a special representation (Montgomery form),
/// performs multiplications in this form, and then transforms the results back. This method is efficient
/// when multiple multiplications are performed with the same modulus.
///
/// # Components
///
/// - **MontgomeryContext**: Stores precomputed values required for Montgomery multiplication.
/// - **to_montgomery**: Converts a `BigInt` to its Montgomery form.
/// - **from_montgomery**: Converts a `BigInt` from its Montgomery form back to the standard form.
/// - **mont_mul**: Performs Montgomery multiplication of two `BigInt` numbers in Montgomery form.
///
/// # Example
///
/// ```rust
/// use bigint::{BigInt, montgomery::{MontgomeryContext, mont_mul}};
///
/// let a = BigInt::from_i32(3);
/// let b = BigInt::from_i32(4);
/// let modulus = BigInt::from_i32(7);
///
/// let ctx = MontgomeryContext::new(modulus.clone());
///
/// let a_mont = ctx.to_montgomery(&a);
/// let b_mont = ctx.to_montgomery(&b);
///
/// let product_mont = ctx.mont_mul(&a_mont, &b_mont);
/// let product = ctx.from_montgomery(&product_mont);
///
/// assert_eq!(product, BigInt::from_i32(5)); // (3 * 4) mod 7 = 12 mod 7 = 5
/// ```
pub mod montgomery {
    use crate::BigInt;

    /// Holds precomputed data for performing Montgomery multiplication modulo `modulus`.
    ///
    /// Montgomery multiplication requires certain precomputations to facilitate efficient
    /// multiplication and reduction without explicit division operations. This context stores:
    /// - `modulus`: The modulus \( m \) used for multiplication and reduction.
    /// - `r`: A power of \( 2^k \) where \( k \) is at least the bit length of \( m \).
    /// - `r_inv`: The modular inverse of \( r \) modulo \( m \), satisfying \( r \times r_{\text{inv}} \equiv 1 \pmod{m} \).
    /// - `m_dash`: A constant satisfying \( m \times m_{\text{dash}} \equiv -1 \pmod{r} \).
    ///
    /// **Note**: This implementation uses a base of \( 2^{32} \), meaning each digit in the `BigInt` represents
    /// a 32-bit chunk. The current approach for finding \( r \) and its inverse is simplified for demonstration
    /// purposes and may need to be optimized for production use.
    #[derive(Debug)]
    pub struct MontgomeryContext {
        /// The modulus \( m \) for which Montgomery multiplication is performed.
        pub modulus: BigInt,
        /// \( R = 2^{k} \), where \( k \) is the number of bits in the modulus.
        pub r: BigInt,
        /// \( R^{-1} \mod m \), the modular inverse of \( R \) modulo \( m \).
        pub r_inv: BigInt,
        /// \( m' \), satisfying \( m \times m' \equiv -1 \pmod{R} \).
        ///
        /// **Note**: In this simplified implementation, `m_dash` is not actively used, but it is included
        /// for completeness and potential future optimizations.
        pub m_dash: BigInt,
    }

    impl MontgomeryContext {
        /// Creates a new `MontgomeryContext` for a given modulus.
        ///
        /// This function performs the necessary precomputations required for Montgomery multiplication:
        /// - Determines the value of \( R = 2^{k} \), where \( k \) is the bit length of the modulus \( m \).
        /// - Computes \( R^{-1} \mod m \).
        /// - Computes \( m' \), satisfying \( m \times m' \equiv -1 \pmod{R} \).
        ///
        /// # Arguments
        ///
        /// * `modulus` - The modulus \( m \) for which the Montgomery context is created.
        ///
        /// # Panics
        ///
        /// Panics if the provided modulus is zero or if the modular inverse of \( R \) modulo \( m \) does not exist.
        ///
        /// # Example
        ///
        /// ```rust
        /// use bigint::{BigInt, montgomery::MontgomeryContext};
        ///
        /// let modulus = BigInt::from_i32(7);
        /// let ctx = MontgomeryContext::new(modulus.clone());
        /// ```
        pub fn new(modulus: BigInt) -> Self {
            if modulus.is_zero() {
                panic!("MontgomeryContext: modulus cannot be zero");
            }

            // Determine the bit length of the modulus.
            let bit_len = modulus.digits.len() * 32;
            // Compute R = 2^bit_len.
            let r = one_shifted_left(bit_len);

            // Compute R_inv = R^{-1} mod m.
            let r_inv = mod_inverse(&r, &modulus)
                .unwrap_or_else(|| panic!("No modular inverse found for R mod m."));

            // Compute m_dash = m^{-1} mod R.
            // This step is optional in this simplified implementation.
            let m_dash = BigInt::new(); // Placeholder; actual computation can be added if needed.

            Self {
                modulus,
                r,
                r_inv,
                m_dash,
            }
        }

        /// Converts a `BigInt` to its Montgomery form.
        ///
        /// The Montgomery form of a number \( x \) is defined as \( x \times R \mod m \).
        ///
        /// # Arguments
        ///
        /// * `x` - The `BigInt` to convert to Montgomery form.
        ///
        /// # Returns
        ///
        /// A new `BigInt` representing \( x \) in Montgomery form.
        ///
        /// # Example
        ///
        /// ```rust
        /// use bigint::{BigInt, montgomery::{MontgomeryContext, mont_mul}};
        ///
        /// let a = BigInt::from_i32(3);
        /// let modulus = BigInt::from_i32(7);
        /// let ctx = MontgomeryContext::new(modulus.clone());
        ///
        /// let a_mont = ctx.to_montgomery(&a);
        /// ```
        pub fn to_montgomery(&self, x: &BigInt) -> BigInt {
            (x * &self.r).rem(&self.modulus)
        }

        /// Converts a `BigInt` from its Montgomery form back to the standard form.
        ///
        /// The standard form of a Montgomery number \( x' \) is defined as \( x' \times R^{-1} \mod m \).
        ///
        /// # Arguments
        ///
        /// * `x_mont` - The `BigInt` in Montgomery form to convert back.
        ///
        /// # Returns
        ///
        /// A new `BigInt` representing \( x \) in standard form.
        ///
        /// # Example
        ///
        /// ```rust
        /// use bigint::{BigInt, montgomery::{MontgomeryContext, mont_mul}};
        ///
        /// let a = BigInt::from_i32(3);
        /// let modulus = BigInt::from_i32(7);
        /// let ctx = MontgomeryContext::new(modulus.clone());
        ///
        /// let a_mont = ctx.to_montgomery(&a);
        /// let a_normal = ctx.from_montgomery(&a_mont);
        /// ```
        pub fn from_montgomery(&self, x_mont: &BigInt) -> BigInt {
            (x_mont * &self.r_inv).rem(&self.modulus)
        }

        /// Performs Montgomery multiplication of two numbers in Montgomery form.
        ///
        /// Given two numbers \( x' \) and \( y' \) in Montgomery form, this function computes
        /// \( z' = x' \times y' \times R^{-1} \mod m \), resulting in a new number in Montgomery form.
        ///
        /// # Arguments
        ///
        /// * `x_mont` - The first operand in Montgomery form.
        /// * `y_mont` - The second operand in Montgomery form.
        ///
        /// # Returns
        ///
        /// A new `BigInt` representing the product \( z' \) in Montgomery form.
        ///
        /// # Example
        ///
        /// ```rust
        /// use bigint::{BigInt, montgomery::{MontgomeryContext, mont_mul}};
        ///
        /// let a = BigInt::from_i32(3);
        /// let b = BigInt::from_i32(4);
        /// let modulus = BigInt::from_i32(7);
        ///
        /// let ctx = MontgomeryContext::new(modulus.clone());
///
/// let a_mont = ctx.to_montgomery(&a);
/// let b_mont = ctx.to_montgomery(&b);
///
/// let product_mont = ctx.mont_mul(&a_mont, &b_mont);
/// ```
        pub fn mont_mul(&self, x_mont: &BigInt, y_mont: &BigInt) -> BigInt {
            self.mont_reduce(&(x_mont * y_mont))
        }

        /// Performs Montgomery reduction on a `BigInt`.
        ///
        /// Given a number \( z \), this function computes \( z \times R^{-1} \mod m \),
        /// effectively reducing \( z \) from Montgomery form back into the standard form.
        ///
        /// # Arguments
        ///
        /// * `z` - The `BigInt` to reduce.
        ///
        /// # Returns
        ///
        /// A new `BigInt` representing \( z \times R^{-1} \mod m \).
        ///
        /// # Example
        ///
        /// ```rust
        /// use bigint::{BigInt, montgomery::{MontgomeryContext, mont_mul}};
        ///
        /// let a = BigInt::from_i32(3);
        /// let modulus = BigInt::from_i32(7);
        /// let ctx = MontgomeryContext::new(modulus.clone());
        ///
        /// let a_mont = ctx.to_montgomery(&a);
        /// let reduced = ctx.mont_reduce(&a_mont);
        /// ```
        fn mont_reduce(&self, z: &BigInt) -> BigInt {
            (z * &self.r_inv).rem(&self.modulus)
        }
    }

    /// Shifts the number left by a given number of bits, effectively computing \( 1 \times 2^{\text{shift\_bits}} \).
    ///
    /// This function is used to compute \( R = 2^{k} \), where \( k \) is the bit length of the modulus.
    ///
    /// # Arguments
    ///
    /// * `shift_bits` - The number of bits to shift left.
    ///
    /// # Returns
    ///
    /// A new `BigInt` representing \( 2^{\text{shift\_bits}} \).
    ///
    /// # Example
    ///
    /// ```rust
    /// use bigint::{BigInt, montgomery::one_shifted_left};
    ///
    /// let r = one_shifted_left(32);
    /// assert_eq!(r.to_hex(), "100000000"); // 2^32 in hexadecimal
    /// ```
    fn one_shifted_left(shift_bits: usize) -> BigInt {
        let full_words = shift_bits / 32;
        let leftover = shift_bits % 32;

        let mut digits = vec![0; full_words];
        digits.push(1 << leftover);

        BigInt {
            digits,
            negative: false,
        }
    }

    /// Computes the Extended Euclidean Algorithm on two `BigInt` numbers.
    ///
    /// This function finds integers \( x \) and \( y \) such that:
    /// 
    /// \[
    /// a \times x + b \times y = \gcd(a, b)
    /// \]
    ///
    /// # Arguments
    ///
    /// * `a` - The first `BigInt`.
    /// * `b` - The second `BigInt`.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - \( \gcd(a, b) \)
    /// - \( x \)
    /// - \( y \)
    ///
    /// # Example
    ///
    /// ```rust
    /// use bigint::{BigInt, montgomery::extended_gcd};
    ///
    /// let a = BigInt::from_i32(30);
    /// let b = BigInt::from_i32(20);
    /// let (gcd, x, y) = extended_gcd(&a, &b);
    /// assert_eq!(gcd, BigInt::from_i32(10));
    /// assert_eq!(x, BigInt::from_i32(1));
    /// assert_eq!(y, BigInt::from_i32(-1));
    /// ```
    fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
        if b.is_zero() {
            return (a.clone(), BigInt::from_i32(1), BigInt::new());
        }

        let (q, r) = a.div_rem(b);
        let (g, x1, y1) = extended_gcd(b, &r);

        let new_y = &x1 - &(&y1 * &q);

        (g, y1, new_y)
    }

    /// Computes the modular inverse of `a` modulo `m`.
    ///
    /// The modular inverse \( a^{-1} \) is an integer such that:
    /// 
    /// \[
    /// a \times a^{-1} \equiv 1 \pmod{m}
    /// \]
    ///
    /// # Arguments
    ///
    /// * `a` - The `BigInt` whose inverse is to be computed.
    /// * `m` - The modulus `BigInt`.
    ///
    /// # Returns
    ///
    /// * `Some(BigInt)` - The modular inverse if it exists.
    /// * `None` - If the modular inverse does not exist (i.e., `a` and `m` are not coprime).
    ///
    /// # Example
    ///
    /// ```rust
    /// use bigint::{BigInt, montgomery::mod_inverse};
    ///
    /// let a = BigInt::from_i32(3);
    /// let m = BigInt::from_i32(7);
    /// let inv = mod_inverse(&a, &m).unwrap();
    /// assert_eq!(inv, BigInt::from_i32(5)); // 3 * 5 ≡ 15 ≡ 1 mod 7
    /// ```
    fn mod_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
        let (g, x, _) = extended_gcd(a, m);
        if g != BigInt::from_i32(1) {
            return None;
        }
        Some(x.rem(m))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::BigInt;

        /// Helper function to create a `MontgomeryContext` for a given 32-bit integer modulus.
        ///
        /// # Arguments
        ///
        /// * `m` - The modulus as a 32-bit signed integer.
        ///
        /// # Returns
        ///
        /// A new `MontgomeryContext` for the provided modulus.
        fn create_montgomery_ctx(m: i32) -> MontgomeryContext {
            let modulus = BigInt::from_i32(m);
            MontgomeryContext::new(modulus)
        }

        /// Tests basic Montgomery multiplication.
        ///
        /// Performs \( (3 \times 4) \mod 7 = 12 \mod 7 = 5 \) using Montgomery multiplication.
        #[test]
        fn test_montgomery_basic() {
            let ctx = create_montgomery_ctx(7);

            let a = BigInt::from_i32(3);
            let b = BigInt::from_i32(4);

            // Convert to Montgomery form
            let a_mont = ctx.to_montgomery(&a);
            let b_mont = ctx.to_montgomery(&b);

            // Perform Montgomery multiplication
            let ab_mont = ctx.mont_mul(&a_mont, &b_mont);

            // Convert back to standard form
            let ab_normal = ctx.from_montgomery(&ab_mont);

            assert_eq!(ab_normal, BigInt::from_i32(5), "Montgomery multiply for 3*4 mod 7 failed");
        }

        /// Tests the Montgomery multiplication identity property.
        ///
        /// Verifies that multiplying by 1 in Montgomery form yields the original number.
        #[test]
        fn test_montgomery_identity() {
            let ctx = create_montgomery_ctx(7);

            let x = BigInt::from_i32(5);
            let x_mont = ctx.to_montgomery(&x);

            let one_mont = ctx.to_montgomery(&BigInt::from_i32(1));

            let prod_mont = ctx.mont_mul(&x_mont, &one_mont);
            let prod_normal = ctx.from_montgomery(&prod_mont);

            assert_eq!(prod_normal, x, "x * 1 (Montgomery) should yield x");
        }

        /// Tests Montgomery multiplication with a negative operand.
        ///
        /// Performs \( (-3 \times 4) \mod 7 = -12 \mod 7 = 2 \) using Montgomery multiplication.
        #[test]
        fn test_montgomery_negative_operand() {
            let ctx = create_montgomery_ctx(7);

            let a = BigInt::from_i32(-3);
            let b = BigInt::from_i32(4);

            let a_mont = ctx.to_montgomery(&a);
            let b_mont = ctx.to_montgomery(&b);

            let ab_mont = ctx.mont_mul(&a_mont, &b_mont);
            let ab_normal = ctx.from_montgomery(&ab_mont);

            assert_eq!(ab_normal, BigInt::from_i32(2), "Montgomery multiply (-3*4 mod 7) failed");
        }

        /// Tests Montgomery multiplication with both operands negative.
        ///
        /// Performs \( (-3 \times -4) \mod 7 = 12 \mod 7 = 5 \) using Montgomery multiplication.
        #[test]
        fn test_montgomery_both_negative_operands() {
            let ctx = create_montgomery_ctx(7);

            let a = BigInt::from_i32(-3);
            let b = BigInt::from_i32(-4);

            let a_mont = ctx.to_montgomery(&a);
            let b_mont = ctx.to_montgomery(&b);

            let ab_mont = ctx.mont_mul(&a_mont, &b_mont);
            let ab_normal = ctx.from_montgomery(&ab_mont);

            assert_eq!(ab_normal, BigInt::from_i32(5), "Montgomery multiply (-3*-4 mod 7) failed");
        }

        /// Tests Montgomery multiplication with large numbers.
        ///
        /// Ensures that Montgomery multiplication works correctly with large `BigInt` values.
        #[test]
        fn test_montgomery_large_numbers() {
            let modulus = BigInt::from_i32(10007);
            let ctx = MontgomeryContext::new(modulus.clone());

            let a = BigInt::from_i32(12345);
            let b = BigInt::from_i32(67890);

            let a_mont = ctx.to_montgomery(&a);
            let b_mont = ctx.to_montgomery(&b);

            let ab_mont = ctx.mont_mul(&a_mont, &b_mont);
            let ab_normal = ctx.from_montgomery(&ab_mont);

            // Compute (12345 * 67890) mod 10007
            // 12345 * 67890 = 838102050
            // 838102050 mod 10007 = 838102050 - 10007 * floor(838102050 / 10007)
            // floor(838102050 / 10007) = 83802
            // 10007 * 83802 = 838102014
            // 838102050 - 838102014 = 36
            let expected = BigInt::from_i32(36);
            assert_eq!(
                ab_normal, expected,
                "Montgomery multiply (12345*67890 mod 10007) failed"
            );
        }

        /// Tests Montgomery reduction with a very large `BigInt`.
        ///
        /// Ensures that Montgomery reduction works correctly with large numbers.
        #[test]
        fn test_montgomery_reduce_large() {
            let modulus = BigInt::from_str("1000000007").unwrap(); // A large prime
            let ctx = MontgomeryContext::new(modulus.clone());
            let x = BigInt::from_str("123456789012345678901234567890").unwrap();
            let reduced = ctx.from_montgomery(&ctx.mont_mul(&ctx.to_montgomery(&x), &ctx.to_montgomery(&BigInt::from_i32(1))));

            // Expected result: 123456789012345678901234567890 mod 1000000007 = 1234567890
            let expected = BigInt::from_str("1234567890").unwrap();
            assert_eq!(reduced, expected, "Montgomery reduce failed for large x mod 1000000007");
        }

        /// Tests Montgomery reduction with a negative number.
        ///
        /// Performs \( (-25 \times R^{-1}) \mod 7 \) and expects the result to be 6.
        #[test]
        fn test_montgomery_reduce_negative() {
            let ctx = create_montgomery_ctx(7);

            let x = BigInt::from_i32(-25);
            let x_mont = ctx.to_montgomery(&x);

            let reduced = ctx.from_montgomery(&x_mont);
            let expected = BigInt::from_i32(6); // (-25) mod 7 = 6
            assert_eq!(reduced, expected, "Montgomery reduce failed for -25 mod 7");
        }

        /// Tests that converting to Montgomery form and back yields the original number.
        ///
        /// Ensures that the `to_montgomery` and `from_montgomery` functions are inverses.
        #[test]
        fn test_montgomery_conversion_identity() {
            let ctx = create_montgomery_ctx(7);

            let x = BigInt::from_i32(5);
            let x_mont = ctx.to_montgomery(&x);
            let x_normal = ctx.from_montgomery(&x_mont);

            assert_eq!(x_normal, x, "Montgomery conversion identity failed");
        }
    }
}
