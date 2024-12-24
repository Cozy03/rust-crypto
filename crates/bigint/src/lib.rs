// crates/bigint/src/lib.rs

// src/lib.rs

//! # BigInt
//!
//! `BigInt` is a high-performance, arbitrary-precision integer library written in Rust.
//! It provides efficient implementations of basic arithmetic operations, modular arithmetic,
//! and advanced algorithms suitable for cryptographic applications.
//!
//! ## Features
//!
//! - **Arbitrary Precision**: Handle integers of any size limited only by system memory.
//! - **Basic Arithmetic**: Addition, subtraction, multiplication, and division.
//! - **Modular Arithmetic**: Efficient modular operations using Barrett and Montgomery reductions.
//! - **Advanced Algorithms**: Karatsuba multiplication for large numbers, Extended Euclidean Algorithm, and more.
//! - **Conversion Utilities**: Convert between different number formats (hexadecimal, binary, decimal strings).
//! - **Optimizations**: Memory-efficient storage, SIMD operations (planned), and constant-time operations for security.
//!
//! ## Installation
//!
//! Add `bigint` to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! bigint = "0.1.0"
//! ```
//!
//! ## Usage
//!
//! ### Creating `BigInt` Instances
//!
//! ```rust
//! use bigint::BigInt;
//!
//! // Initialize to zero
//! let zero = BigInt::new();
//!
//! // From 32-bit integer
//! let five = BigInt::from_i32(5);
//!
//! // From 64-bit integer
//! let big_num = BigInt::from_i64(1234567890123456789);
//!
//! // From a decimal string
//! let num_str = BigInt::from_str("987654321098765432109876543210").unwrap();
//!
//! // From a hexadecimal string
//! let hex_num = BigInt::from_hex("FFEE1234").unwrap();
//! ```
//!
//! ### Basic Arithmetic
//!
//! ```rust
//! use bigint::BigInt;
//!
//! let a = BigInt::from_i32(10);
//! let b = BigInt::from_i32(20);
//!
//! let sum = &a + &b;
//! let difference = &a - &b;
//! let product = &a * &b;
//! let quotient = &a / &b;
//! let remainder = &a % &b;
//! ```
//!
//! ### Modular Arithmetic
//!
//! ```rust
//! use bigint::{BigInt, montgomery::MontgomeryContext};
//!
//! let a = BigInt::from_i32(12345);
//! let b = BigInt::from_i32(67890);
//! let modulus = BigInt::from_i32(10007);
//!
//! // Using standard modular multiplication
//! let standard_mod_mul = a.mod_mul(&b, &modulus);
//!
//! // Using Barrett reduction for larger moduli
//! let ctx = bigint::barrett::BarrettContext::new(modulus.clone());
//! let barrett_mod_mul = bigint::barrett::barrett_mul(&a, &b, &ctx);
//! ```
//!
//! ## Modules
//!
//! - [`bigint::BigInt`](crate::BigInt): The main arbitrary-precision integer type.
//! - [`bigint::barrett`](crate::barrett): Implementation of Barrett reduction for modular arithmetic.
//! - [`bigint::montgomery`](crate::montgomery): Implementation of Montgomery multiplication for modular arithmetic.
//! - ... (add more modules as they are implemented)
//!

use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, Neg, Rem, RemAssign, Sub, SubAssign};

pub mod barrett;
pub mod montgomery;

pub use barrett::{barrett::barrett_mul, barrett::barrett_reduce, barrett::BarrettContext};
pub use montgomery::montgomery::MontgomeryContext;

/// Represents an arbitrary-precision integer.
///
/// The number is stored as a sequence of 32-bit digits in little-endian format
/// (least significant digit first) along with a sign flag.
///
/// # Examples
///
/// ```
/// use bigint::BigInt;
///
/// let a = BigInt::new();  // Creates zero
/// let b = BigInt::from_i32(42);  // Creates from i32
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BigInt {
    // Store digits in base 2^32 for efficient arithmetic
    digits: Vec<u32>,
    // true for negative numbers
    negative: bool,
}

impl BigInt {
    /// Creates a new BigInt initialized to zero.
    ///
    /// # Returns
    ///
    /// Returns a `BigInt` instance representing zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let num = BigInt::new();
    /// ```
    pub fn new() -> Self {
        BigInt {
            digits: vec![0],
            negative: false,
        }
    }

    /// Creates a BigInt from a 32-bit signed integer.
    ///
    /// # Arguments
    ///
    /// * `value` - The i32 value to convert into a BigInt
    ///
    /// # Returns
    ///
    /// Returns a `BigInt` instance representing the given value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let positive = BigInt::from_i32(42);
    /// let negative = BigInt::from_i32(-42);
    /// ```
    pub fn from_i32(value: i32) -> Self {
        let mut digits = Vec::new();
        let mut abs_value = value.abs() as u32;

        if abs_value == 0 {
            digits.push(0);
        } else {
            while abs_value > 0 {
                digits.push(abs_value);
                abs_value = 0;
            }
        }

        let mut result = BigInt {
            digits,
            negative: value < 0,
        };
        result.normalize();
        result
    }

    /// Creates a BigInt from a 64-bit signed integer.
    ///
    /// # Arguments
    ///
    /// * `value` - The i64 value to convert into a BigInt
    ///
    /// # Returns
    ///
    /// Returns a `BigInt` instance representing the given value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let small = BigInt::from_i64(9999999999);
    /// let negative = BigInt::from_i64(-1234567890123);
    /// ```
    pub fn from_i64(value: i64) -> Self {
        // If zero, just return an empty BigInt
        if value == 0 {
            return BigInt::new();
        }

        // Special-case i64::MIN
        // Because i64::MIN has no positive counterpart in i64,
        // we will treat it by manually constructing the absolute value in a u64.
        let (negative, mut abs_value) = if value == i64::MIN {
            // 2^63 is 1 << 63
            (true, 1u64 << 63)
        } else {
            // Normal case
            (value < 0, value.abs() as u64)
        };

        let mut digits = Vec::new();
        while abs_value > 0 {
            // Extract lower 32 bits
            let lower = (abs_value & 0xFFFF_FFFF) as u32;
            digits.push(lower);
            // Shift abs_value down by 32 bits
            abs_value >>= 32;
        }

        let mut result = BigInt { digits, negative };
        result.normalize();
        result
    }

    /// Creates a `BigInt` by parsing a base-10 decimal string.
    ///
    /// The input string may optionally start with '-' for negative.
    ///
    /// # Arguments
    ///
    /// * `value` - A string slice in base 10 (e.g., "12345" or "-999999999")
    ///
    /// # Returns
    ///
    /// Returns a `Result<BigInt, String>` indicating success or an error message if parsing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// // Positive example
    /// let big_num = BigInt::from_str("1234567890123456789").unwrap();
    ///
    /// // Negative example
    /// let neg_num = BigInt::from_str("-9999999").unwrap();
    ///
    /// // Error handling
    /// assert!(BigInt::from_str("12ab3").is_err());
    /// ```
    pub fn from_str(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("Cannot parse empty string as BigInt".to_string());
        }

        // Handle sign
        let negative = value.starts_with('-');
        let digits_str = if negative { &value[1..] } else { value };

        if digits_str.is_empty() {
            // e.g., the input was "-" only
            return Err("No digits found after sign.".to_string());
        }

        // Validate digits are only 0-9
        if !digits_str.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("Invalid decimal digit in '{}'", digits_str));
        }

        // We'll parse it by manually doing "result = result * 10 + next_digit"
        let mut result = BigInt::new(); // start at 0
        let ten = BigInt::from_i32(10);

        for ch in digits_str.chars() {
            let digit_val = ch.to_digit(10).unwrap() as i32; // safe due to prior check
                                                             // result *= 10
            result = &result * &ten;
            // result += digit_val
            // We'll convert digit_val to a BigInt
            let digit_bi = BigInt::from_i32(digit_val);
            result = &result + &digit_bi;
        }

        // Now set sign if needed
        result.negative = negative && !result.is_zero();
        Ok(result)
    }

    /// Gets the absolute value of this BigInt.
    ///
    /// # Returns
    ///
    /// Returns a new BigInt representing the absolute value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let num = BigInt::from_i32(-42);
    /// let abs = num.abs();
    /// ```
    pub fn abs(&self) -> BigInt {
        let mut result = self.clone();
        result.negative = false;
        result
    }

    /// Normalizes the internal representation by:
    /// 1. Removing leading zeros
    /// 2. Ensuring zero is always positive
    ///
    /// This method is automatically called after arithmetic operations
    /// to maintain canonical form.
    fn normalize(&mut self) {
        while self.digits.len() > 1 && self.digits.last() == Some(&0) {
            self.digits.pop();
        }

        if self.digits.len() == 1 && self.digits[0] == 0 {
            self.negative = false;
        }
    }

    /// Returns true if this BigInt is zero.
    ///
    /// # Returns
    ///
    /// Returns a boolean indicating whether the value is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let num = BigInt::new();
    /// assert!(num.is_zero());
    /// ```
    pub fn is_zero(&self) -> bool {
        self.digits.len() == 1 && self.digits[0] == 0
    }

    /// Adds two BigInt numbers without considering signs.
    /// Helper method for the main addition implementation.
    ///
    /// # Arguments
    ///
    /// * `other` - The BigInt to add to this one
    ///
    /// # Returns
    ///
    /// Returns a new BigInt containing the sum
    fn add_absolute(&self, other: &BigInt) -> BigInt {
        let mut result =
            Vec::with_capacity(std::cmp::max(self.digits.len(), other.digits.len()) + 1);
        let mut carry = 0u32;

        // Add corresponding digits from both numbers
        for i in 0..std::cmp::max(self.digits.len(), other.digits.len()) {
            let a = self.digits.get(i).unwrap_or(&0);
            let b = other.digits.get(i).unwrap_or(&0);

            let sum = *a as u64 + *b as u64 + carry as u64;
            result.push(sum as u32);
            carry = (sum >> 32) as u32;
        }
        if carry > 0 {
            result.push(carry);
        }

        let mut big_int = BigInt {
            digits: result,
            negative: false,
        };
        big_int.normalize();
        big_int
    }

    /// Returns the number with its sign negated.
    ///
    /// # Returns
    ///
    /// A new `BigInt` instance with the same absolute value but the opposite sign.
    /// If the original number is zero, the result remains zero (not negative zero).
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let num = BigInt::from_i32(42);
    /// let negated = num.negate();
    /// assert_eq!(negated, BigInt::from_i32(-42));
    ///
    /// let zero = BigInt::new();
    /// assert_eq!(zero.negate(), BigInt::new());
    /// ```
    pub fn negate(&self) -> BigInt {
        let mut result = self.clone();
        result.negative = !result.negative && !result.is_zero();
        result
    }

    /// Compares the absolute values of two BigInts
    ///
    /// # Returns
    ///
    /// - Some(true) if |self| > |other|
    /// - Some(false) if |self| < |other|
    /// - None if |self| == |other|
    fn compare_abs(&self, other: &BigInt) -> Option<bool> {
        if self.digits.len() != other.digits.len() {
            return Some(self.digits.len() > other.digits.len());
        }

        // Compare digits from most significant to least significant
        for i in (0..self.digits.len()).rev() {
            if self.digits[i] != other.digits[i] {
                return Some(self.digits[i] > other.digits[i]);
            }
        }

        None // Numbers are equal
    }

    /// Subtracts the absolute value of another `BigInt` from this one.
    /// Assumes `self` is greater than or equal to `other` in absolute value.
    /// If `self` is smaller than `other`, it swaps the operands and adjusts the sign.
    ///
    /// # Arguments
    ///
    /// * `other` - The `BigInt` to subtract from this one.
    ///
    /// # Returns
    ///
    /// Returns a new `BigInt` containing the result of the subtraction.
    ///
    /// # Implementation Notes
    ///
    /// - Uses little-endian representation of digits.
    /// - Handles borrow during subtraction to ensure correct results for multi-digit numbers.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(15);
    /// let b = BigInt::from_i32(5);
    /// let result = a.sub_absolute(&b);
    /// assert_eq!(result, BigInt::from_i32(10));
    ///
    /// let a = BigInt::from_i32(5);
    /// let b = BigInt::from_i32(15);
    /// let result = a.sub_absolute(&b);
    /// assert_eq!(result, BigInt::from_i32(-10));
    /// ```
    pub fn sub_absolute(&self, other: &BigInt) -> BigInt {
        // Ensure self is the larger number
        if let Some(false) = self.compare_abs(other) {
            let mut result = other.sub_absolute(self);
            result.negative = !result.negative;
            return result;
        }

        let mut result = Vec::with_capacity(self.digits.len());
        let mut borrow = 0i64;

        for i in 0..self.digits.len() {
            let a = self.digits[i] as i64;
            let b = *other.digits.get(i).unwrap_or(&0) as i64; // Added dereference operator *

            let mut diff = a - b - borrow;
            if diff < 0 {
                diff += 1 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }

            result.push(diff as u32);
        }

        let mut big_int = BigInt {
            digits: result,
            negative: false,
        };
        big_int.normalize();
        big_int
    }

    /// Converts the BigInt to a hexadecimal string representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    /// let num = BigInt::from_i32(255);
    /// assert_eq!(num.to_hex(), "FF");
    /// ```

    pub fn to_hex(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }

        let mut hex = String::new();
        if self.negative {
            hex.push('-');
        }

        // Process digits in reverse order (most significant first)
        let mut started = false;
        for &digit in self.digits.iter().rev() {
            if started {
                hex.push_str(&format!("{:08X}", digit));
            } else if digit != 0 || &digit == self.digits.first().unwrap() {
                // First significant digit or last digit
                hex.push_str(&format!("{:X}", digit));
                started = true;
            }
        }

        hex
    }
    /// Creates a `BigInt` from a hexadecimal string representation.
    ///
    /// The input string can optionally start with a `0x` prefix and/or a negative sign (`-`).
    /// The hexadecimal string is parsed from the least significant digit to the most significant
    /// for little-endian internal representation.
    ///
    /// # Arguments
    ///
    /// * `hex` - A string slice representing the hexadecimal value to convert into a `BigInt`.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the `BigInt` if the conversion is successful,
    /// or a `String` error message if the input contains invalid characters.
    ///
    /// # Implementation Details
    ///
    /// - Supports both prefixed (`0x`) and non-prefixed hex strings.
    /// - Handles negative numbers by checking for a leading `-` sign.
    /// - Groups bits into 32-bit chunks for internal representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// // Positive number without prefix
    /// let num = BigInt::from_hex("1F4").unwrap();
    /// assert_eq!(num.to_hex(), "1F4");
    ///
    /// // Negative number with prefix
    /// let num = BigInt::from_hex("-0x1F4").unwrap();
    /// assert_eq!(num.to_hex(), "-1F4");
    ///
    /// // Invalid input
    /// assert!(BigInt::from_hex("XYZ").is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// - Returns an error if the input string contains non-hexadecimal characters.
    /// - Example: `BigInt::from_hex("XYZ")` will return `Err("Invalid hex character: X")`.
    pub fn from_hex(hex: &str) -> Result<Self, String> {
        let mut hex = hex.trim();
        let negative = hex.starts_with('-');
        if negative {
            hex = &hex[1..];
        }
        if hex.starts_with("0x") {
            hex = &hex[2..];
        }

        let mut digits = Vec::new();
        let mut current = 0u32;
        let mut shift = 0;

        for c in hex.chars().rev() {
            let digit = c
                .to_digit(16)
                .ok_or_else(|| format!("Invalid hex character: {}", c))?;
            current |= digit << shift;
            shift += 4;

            if shift == 32 {
                digits.push(current);
                current = 0;
                shift = 0;
            }
        }

        if shift > 0 {
            digits.push(current);
        }

        if digits.is_empty() {
            digits.push(0);
        }

        let mut result = BigInt { digits, negative };
        result.normalize();
        Ok(result)
    }

    /// Converts the BigInt to a binary string representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    /// let num = BigInt::from_i32(5);
    /// assert_eq!(num.to_binary(), "101");
    /// ```
    pub fn to_binary(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }

        let mut binary = String::new();
        if self.negative {
            binary.push('-');
        }

        // Convert to binary, starting with most significant digit
        let mut started = false;
        for &digit in self.digits.iter().rev() {
            if started {
                binary.push_str(&format!("{:032b}", digit));
            } else {
                let formatted = format!("{:b}", digit);
                if formatted != "0" {
                    binary.push_str(&formatted);
                    started = true;
                }
            }
        }

        // Handle case where the number is zero
        if !started {
            binary.push('0');
        }

        binary
    }
    /// Returns true if this number is less than the other.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    /// let a = BigInt::from_i32(3);
    /// let b = BigInt::from_i32(5);
    /// assert!(a.is_less_than(&b));
    /// ```
    pub fn is_less_than(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Less
    }

    /// Returns true if this number is greater than the other.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    /// let a = BigInt::from_i32(5);
    /// let b = BigInt::from_i32(3);
    /// assert!(a.is_greater_than(&b));
    /// ```
    pub fn is_greater_than(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Greater
    }

    /// Returns true if this number is less than or equal to the other.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    /// let a = BigInt::from_i32(3);
    /// let b = BigInt::from_i32(3);
    /// assert!(a.is_less_than_or_equal(&b));
    /// ```
    pub fn is_less_than_or_equal(&self, other: &Self) -> bool {
        self.cmp(other) != Ordering::Greater
    }

    /// Returns true if this number is greater than or equal to the other.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    /// let a = BigInt::from_i32(5);
    /// let b = BigInt::from_i32(5);
    /// assert!(a.is_greater_than_or_equal(&b));
    /// ```
    pub fn is_greater_than_or_equal(&self, other: &Self) -> bool {
        self.cmp(other) != Ordering::Less
    }

    /// Multiplies two BigInt numbers without considering signs.
    /// Uses the classical schoolbook multiplication algorithm.
    ///
    /// # Arguments
    ///
    /// * `other` - The BigInt to multiply with this one
    ///
    /// # Returns
    ///
    /// Returns a new BigInt containing the product
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    /// let a = BigInt::from_i32(12);
    /// let b = BigInt::from_i32(10);
    /// assert_eq!(a.mul_schoolbook(&b), BigInt::from_i32(120));
    /// ```
    pub fn mul_schoolbook(&self, other: &BigInt) -> BigInt {
        if self.is_zero() || other.is_zero() {
            return BigInt::new();
        }

        let mut result = vec![0u32; self.digits.len() + other.digits.len()];

        // Perform schoolbook multiplication
        for i in 0..self.digits.len() {
            let mut carry = 0u64;
            for j in 0..other.digits.len() {
                let product =
                    result[i + j] as u64 + (self.digits[i] as u64 * other.digits[j] as u64) + carry;
                result[i + j] = product as u32;
                carry = product >> 32;
            }
            if carry > 0 {
                result[i + other.digits.len()] = carry as u32;
            }
        }

        let mut product = BigInt {
            digits: result,
            negative: self.negative != other.negative,
        };
        product.normalize();
        product
    }

    /// Multiplies two BigInt numbers using Karatsuba algorithm.
    /// This algorithm is more efficient for large numbers.
    ///
    /// # Arguments
    ///
    /// * `other` - The BigInt to multiply with this one
    ///
    /// # Returns
    ///
    /// Returns a new BigInt containing the product
    pub fn mul_karatsuba(&self, other: &BigInt) -> BigInt {
        // Use schoolbook multiplication for small numbers
        if self.digits.len() <= 32 || other.digits.len() <= 32 {
            return self.mul_schoolbook(other);
        }

        // Find the mid point for splitting
        let m = std::cmp::max(self.digits.len(), other.digits.len()) / 2;

        // Split the numbers into high and low parts
        let (low1, high1) = self.split_at(m);
        let (low2, high2) = other.split_at(m);

        // Compute the three products needed for Karatsuba
        let z0 = low1.mul_karatsuba(&low2); // low1 * low2
        let z2 = high1.mul_karatsuba(&high2); // high1 * high2

        // (high1 + low1) * (high2 + low2)
        let z1_temp = (&high1 + &low1).mul_karatsuba(&(&high2 + &low2));

        // z1 = z1 - z2 - z0
        let z1 = z1_temp - z2.clone() - z0.clone();

        // Combine the results: z2 * b^(2m) + z1 * b^m + z0
        let mut result = z2.shift_left(2 * m);
        result = &result + &z1.shift_left(m);
        result = &result + &z0;

        result
    }

    /// Splits the number at given position into low and high parts.
    ///
    /// # Arguments
    ///
    /// * `pos` - Position to split at
    ///
    /// # Returns
    ///
    /// Returns a tuple of (low, high) parts as BigInts
    fn split_at(&self, pos: usize) -> (BigInt, BigInt) {
        if pos >= self.digits.len() {
            return (self.clone(), BigInt::new());
        }

        let low = BigInt {
            digits: self.digits[..pos].to_vec(),
            negative: false,
        };

        let high = BigInt {
            digits: self.digits[pos..].to_vec(),
            negative: false,
        };

        (low, high)
    }

    /// Shifts the number left by given number of positions (multiplies by 2^(32*shift)).
    /// Each shift position represents 32 bits, so shifting left by 1 multiplies by 2^32.
    ///
    /// # Arguments
    ///
    /// * `shift` - Number of positions to shift left (each position is 32 bits)
    ///
    /// # Returns
    ///
    /// Returns a new BigInt representing this * 2^(32*shift)
    ///
    /// # Implementation Note
    ///
    /// In our little-endian representation:
    /// - Least significant digits are at index 0
    /// - Most significant digits are at the end
    /// - Left shift means adding zeros at the beginning
    /// - Example: [FF] -> [00, FF] for one position shift
    pub fn shift_left(&self, shift: usize) -> BigInt {
        // If zero or no shift requested, just return self
        if self.is_zero() || shift == 0 {
            return self.clone();
        }

        // We are effectively doing "multiply by 256^shift",
        // which is "multiply by 2^(8 * shift)".
        //
        // A slow-and-simple way is to loop shift times and multiply by 256:
        //   let base = BigInt::from_i32(256);
        //   let mut result = self.clone();
        //   for _ in 0..shift {
        //       result = &result * &base;
        //   }
        //   return result;
        //
        // But we can do it in one pass by building 256^shift as a BigInt:
        //
        //   256^shift is the same as 1 << (8*shift) in binary.
        //   But we store digits in base 2^32, so we can handle partial bits.

        let total_bits = 8 * shift; // total bits we must shift
        let full_words = total_bits / 32; // how many full 32-bit words
        let leftover = total_bits % 32; // how many leftover bits

        // Step 1: shift by full_words at the "digit" level
        //         (just like your old code that appended `full_words` zeros in little endian)
        let mut new_digits = vec![0; full_words];
        new_digits.extend_from_slice(&self.digits);

        // Step 2: shift the entire vector by leftover bits, if leftover != 0
        if leftover != 0 {
            let mut carry: u64 = 0;
            for d in new_digits.iter_mut() {
                // Combine leftover shift with carry
                let tmp = ((*d as u64) << leftover) | carry;
                *d = tmp as u32; // lower 32 bits
                carry = tmp >> 32; // carry is anything above 32 bits
            }
            // If there's still carry at the end, push it
            if carry != 0 {
                new_digits.push(carry as u32);
            }
        }

        let mut shifted = BigInt {
            digits: new_digits,
            negative: self.negative,
        };
        shifted.normalize();
        shifted
    }

    /// Decides which multiplication algorithm to use based on input size and performs
    /// the multiplication.
    ///
    /// # Algorithm Selection
    /// - Uses schoolbook multiplication for numbers with ≤32 digits (based on benchmarks)
    /// - Uses Karatsuba multiplication for larger numbers
    ///
    /// The threshold of 32 digits was chosen based on performance benchmarks:
    /// ```text
    /// Digits   | Schoolbook | Karatsuba  | Winner
    /// ---------|------------|------------|--------
    /// 8        | 16.979 ns  | 18.539 ns  | Schoolbook
    /// 16       | 20.997 ns  | 21.306 ns  | Schoolbook
    /// 32       | 28.466 ns  | 28.908 ns  | Schoolbook
    /// 64       | 60.389 ns  | 59.898 ns  | Karatsuba
    /// 128      | 193.67 ns  | 192.05 ns  | Karatsuba
    /// 256      | 907.87 ns  | 887.60 ns  | Karatsuba
    /// ```
    ///
    /// # Arguments
    ///
    /// * `other` - The BigInt to multiply with this one
    ///
    /// # Returns
    ///
    /// Returns a new BigInt containing the product
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// // Small number multiplication (uses schoolbook)
    /// let a = BigInt::from_i32(123);
    /// let b = BigInt::from_i32(456);
    /// let product = a.multiply(&b);  // Uses schoolbook multiplication
    ///
    /// // Large number multiplication (uses Karatsuba)
    /// let big_a = BigInt::from_hex("FFFFFFFFFFFFFFFF").unwrap();
    /// let big_b = BigInt::from_hex("FFFFFFFFFFFFFFFF").unwrap();
    /// let big_product = big_a.multiply(&big_b);  // Uses Karatsuba multiplication
    /// ```
    ///
    /// # Performance
    /// - Schoolbook multiplication: O(n²) time complexity
    /// - Karatsuba multiplication: O(n^log₂(3)) ≈ O(n^1.585) time complexity
    ///
    /// Where n is the number of digits in the larger input number.
    pub fn multiply(&self, other: &BigInt) -> BigInt {
        if self.digits.len() <= 32 || other.digits.len() <= 32 {
            self.mul_schoolbook(other)
        } else {
            self.mul_karatsuba(other)
        }
    }

    /// Computes the modulo operation (self % modulus).
    ///
    /// # Arguments
    ///
    /// * `modulus` - The modulus to compute against
    ///
    /// # Returns
    ///
    /// Returns a new BigInt containing the result
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    /// let a = BigInt::from_i32(17);
    /// let m = BigInt::from_i32(5);
    /// assert_eq!(a.modulo(&m).to_hex(), "2"); // 17 mod 5 = 2
    /// ```
    pub fn modulo(&self, modulus: &BigInt) -> BigInt {
        if modulus.is_zero() {
            panic!("Modulo by zero");
        }

        // Handle negative numbers
        let mut result = self.abs();
        let m = modulus.abs();

        // Use repeated subtraction for now
        // (We'll optimize this later with division-based approach)
        while result.is_greater_than_or_equal(&m) {
            result = &result - &m;
        }

        // Adjust sign if input was negative
        if self.negative && !result.is_zero() {
            result = &m - &result;
        }

        result
    }

    /// Computes modular addition (self + other) % modulus
    ///
    /// # Arguments
    ///
    /// * `other` - Number to add
    /// * `modulus` - The modulus to compute against
    ///
    /// # Returns
    ///
    /// Returns a new BigInt containing (self + other) % modulus
    pub fn mod_add(&self, other: &BigInt, modulus: &BigInt) -> BigInt {
        let sum = self + other;
        sum.modulo(modulus)
    }

    /// Computes modular subtraction (self - other) % modulus
    ///
    /// # Arguments
    ///
    /// * `other` - Number to subtract
    /// * `modulus` - The modulus to compute against
    ///
    /// # Returns
    ///
    /// Returns a new BigInt containing (self - other) % modulus
    pub fn mod_sub(&self, other: &BigInt, modulus: &BigInt) -> BigInt {
        let diff = self - other;
        diff.modulo(modulus)
    }

    fn multiply_by_u32(&mut self, value: u32) {
        let mut carry: u64 = 0;
        for digit in self.digits.iter_mut() {
            // Use 64-bit multiplication to avoid overflow.
            let product = *digit as u64 * value as u64 + carry;
            *digit = product as u32; // Low 32 bits
            carry = product >> 32; // High 32 bits become next carry
        }
        // If there's any carry left after the last digit, push a new digit.
        if carry != 0 {
            self.digits.push(carry as u32);
        }
        self.normalize();
    }

    /// Computes modular multiplication: (self * other) % modulus
    ///
    /// This method uses Barrett reduction for larger moduli to optimize performance.
    /// For smaller moduli, it defaults to the standard modulo operation.
    ///
    /// # Arguments
    ///
    /// * `other` - The BigInt to multiply with `self`
    /// * `modulus` - The modulus to compute against
    ///
    /// # Returns
    ///
    /// A new `BigInt` equal to `(self * other) mod modulus`.
    ///
    /// # Panics
    ///
    /// Panics if `modulus` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(3);
    /// let b = BigInt::from_i32(4);
    /// let m = BigInt::from_i32(5);
    ///
    /// let result = a.mod_mul(&b, &m); // (3 * 4) mod 5 = 12 mod 5 = 2
    /// assert_eq!(result, BigInt::from_i32(2));
    /// ```
    pub fn mod_mul(&self, other: &BigInt, modulus: &BigInt) -> BigInt {
        if modulus.is_zero() {
            panic!("Modulo by zero");
        }

        // Define a threshold for using Barrett reduction.
        // Here, we use a modulus size of more than 2 digits (i.e., > 64 bits).
        // Adjust this threshold based on your performance benchmarks.
        let barrett_threshold_digits = 2;

        // Determine if modulus is "big" based on the number of digits
        let use_barrett = modulus.digits.len() > barrett_threshold_digits;

        if use_barrett {
            // Create a BarrettContext for the modulus
            let ctx = BarrettContext::new(modulus.clone());

            // Use Barrett multiplication: (self * other) mod modulus
            // `barrett_mul` internally handles the multiplication and reduction
            barrett_mul(self, other, &ctx)
        } else {
            // Use standard multiplication followed by modulo
            let product = self * other;
            product.modulo(modulus)
        }
    }

    /// Performs integer division with remainder.
    ///
    /// Given `self` (the dividend) and `divisor`, this method computes both
    /// the *quotient* and *remainder* simultaneously. Mathematically, it finds
    /// `quotient` and `remainder` such that:
    ///
    /// ```text
    /// self = quotient * divisor + remainder
    /// ```
    ///
    /// The returned tuple is `(quotient, remainder)`.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero, as division by zero is undefined.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(17);
    /// let b = BigInt::from_i32(5);
    /// let (q, r) = a.div_rem(&b);
    ///
    /// assert_eq!(q, BigInt::from_i32(3)); // 17 / 5 = 3
    /// assert_eq!(r, BigInt::from_i32(2)); // 17 % 5 = 2
    /// ```
    pub fn div_rem(&self, divisor: &BigInt) -> (BigInt, BigInt) {
        if divisor.is_zero() {
            panic!("Division by zero");
        }

        // Handle special cases
        if self.is_zero() {
            return (BigInt::new(), BigInt::new());
        }

        // Get absolute values for the division.
        let dividend = self.abs();
        let divisor_abs = divisor.abs();

        // If |self| < |divisor|, the quotient is 0, and remainder is self.
        if let Some(false) = dividend.compare_abs(&divisor_abs) {
            return (BigInt::new(), self.clone());
        }

        let mut quotient = BigInt::new();
        let mut remainder = BigInt::new();

        // Perform digit-by-digit division from most significant to least significant.
        for i in (0..dividend.digits.len()).rev() {
            // Shift the remainder "up" by one digit (base 2^32).
            if !remainder.is_zero() {
                remainder.digits.insert(0, 0);
            }

            // Incorporate the next digit from dividend into remainder.
            remainder.digits[0] = dividend.digits[i];
            remainder.normalize();

            // Binary search to find the largest digit q such that: divisor_abs * q <= remainder.
            let mut q = 0u32;
            let mut left = 0u32;
            let mut right = u32::MAX;

            while left <= right {
                let mid = left + (right - left) / 2;
                let mut temp = divisor_abs.clone();

                if mid > 0 {
                    temp.multiply_by_u32(mid);
                    temp.normalize();
                }

                if temp.is_less_than_or_equal(&remainder) {
                    q = mid;
                    left = mid + 1;
                } else {
                    if mid == 0 {
                        break;
                    }
                    right = mid - 1;
                }
            }

            // Subtract (divisor_abs * q) from the remainder
            if q > 0 {
                let mut temp = divisor_abs.clone();
                temp.multiply_by_u32(q);
                temp.normalize();
                remainder = &remainder - &temp;
            }

            // Insert q as the next digit of the quotient (from most significant to least significant).
            if q > 0 || !quotient.is_zero() {
                quotient.digits.insert(0, q);
            }
        }

        // Apply signs: if signs differ, quotient is negative; remainder shares self's sign.
        quotient.negative = self.negative != divisor.negative;
        remainder.negative = self.negative;

        // Normalize to remove leading zeros if any.
        quotient.normalize();
        remainder.normalize();

        (quotient, remainder)
    }

    /// Performs integer division.
    ///
    /// Returns the *quotient* of dividing `self` by `other`. This is essentially
    /// a convenience wrapper around [`div_rem`](Self::div_rem), discarding the remainder.
    ///
    /// # Panics
    ///
    /// Panics if `other` (the divisor) is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(17);
    /// let b = BigInt::from_i32(5);
    /// let quotient = a.div(&b);
    ///
    /// assert_eq!(quotient, BigInt::from_i32(3)); // 17 / 5 = 3
    /// ```
    pub fn div(&self, other: &BigInt) -> BigInt {
        self.div_rem(other).0
    }

    /// Computes the remainder of integer division.
    ///
    /// Equivalent to `self % other`. This is a convenience wrapper around
    /// [`div_rem`](Self::div_rem), discarding the quotient and returning only
    /// the *remainder*.
    ///
    /// # Panics
    ///
    /// Panics if `other` (the divisor) is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(17);
    /// let b = BigInt::from_i32(5);
    /// let remainder = a.rem(&b);
    ///
    /// assert_eq!(remainder, BigInt::from_i32(2));  // 17 % 5 = 2
    /// ```
    pub fn rem(&self, other: &BigInt) -> BigInt {
        self.div_rem(other).1
    }
}

impl fmt::Display for BigInt {
    /// Formats the `BigInt` as a decimal string.
    ///
    /// If the number is negative, a `-` sign is prefixed. This implementation
    /// currently prints only the least significant digit stored in `digits[0]`
    /// for demonstration. In a real-world scenario, you might print the entire
    /// number (all digits).
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let num = BigInt::from_i32(-123);
    /// assert_eq!(format!("{}", num), "-123");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.negative {
            write!(f, "-")?;
        }
        write!(f, "{}", self.digits[0])
    }
}

impl PartialOrd for BigInt {
    /// Provides partial comparison for `BigInt`s.
    ///
    /// This delegates to the [`Ord::cmp`] implementation by returning `Some(self.cmp(other))`.
    /// For `BigInt`, partial comparison is effectively the same as total comparison; there
    /// are no undefined comparisons because all integer values are comparable.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(5);
    /// let b = BigInt::from_i32(3);
    ///
    /// // PartialOrd allows use of comparison operators like >
    /// assert!(a > b);
    /// ```
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigInt {
    /// Provides total ordering for `BigInt`s, comparing both sign and magnitude.
    ///
    /// - Negative values are always considered less than positive values.
    /// - For two negative values, the one with larger absolute magnitude is considered smaller
    ///   (since -10 is less than -5).
    /// - For two positive values, the one with larger absolute magnitude is considered greater.
    /// - If their absolute magnitudes are equal, they are considered equal.
    ///
    /// # Implementation Details
    ///
    /// 1. Check if signs differ. If one is negative and the other positive, the negative
    ///    one is smaller.
    /// 2. If both are negative, compare absolute values in reverse order.
    /// 3. Otherwise, compare absolute values in normal order.
    ///
    /// This method is used behind the scenes by comparison operators like `<`, `>`, and `==`
    /// (via the `Ord` trait).
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    /// use std::cmp::Ordering;
    ///
    /// let a = BigInt::from_i32(-5);
    /// let b = BigInt::from_i32(-10);
    /// // a has smaller magnitude, so a is greater in real numeric value (-5 > -10).
    ///
    /// assert_eq!(a.cmp(&b), Ordering::Greater);
    ///
    /// let c = BigInt::from_i32(5);
    /// assert_eq!(c.cmp(&a), Ordering::Greater);  // 5 > -5
    /// ```
    fn cmp(&self, other: &Self) -> Ordering {
        // If signs are different, the negative one is less
        if self.negative != other.negative {
            return if self.negative {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }

        // If both are negative, compare absolute values in reverse
        let ordering = match self.compare_abs(other) {
            Some(true) => Ordering::Greater,
            Some(false) => Ordering::Less,
            None => Ordering::Equal,
        };

        // Reverse if negative
        if self.negative {
            ordering.reverse()
        } else {
            ordering
        }
    }
}

impl Add for &BigInt {
    type Output = BigInt;

    /// Adds two `BigInt` references and returns a new `BigInt` result.
    ///
    /// This implementation properly handles sign and magnitude for arbitrary-precision
    /// integers. If both operands have the same sign, their magnitudes (absolute values)
    /// are added. If they differ, the smaller magnitude is subtracted from the larger, and
    /// the resulting sign matches the sign of the operand with the larger magnitude.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(5);
    /// let b = BigInt::from_i32(-3);
    ///
    /// // Since `Add` is implemented for `&BigInt`, we borrow both values:
    /// let sum = &a + &b;
    /// assert_eq!(sum, BigInt::from_i32(2));  // 5 + (-3) = 2
    /// ```
    fn add(self, other: &BigInt) -> BigInt {
        if self.negative == other.negative {
            // If signs are the same, add magnitudes and keep the sign
            let mut result = self.add_absolute(other);
            result.negative = self.negative;
            result
        } else {
            // If signs differ, subtract the smaller magnitude from the larger
            let mut result = self.sub_absolute(other);
            if let Some(true) = self.compare_abs(other) {
                result.negative = self.negative;
            } else {
                result.negative = other.negative;
            }
            result.normalize();
            result
        }
    }
}

impl BigInt {
    /// Prints internal digits (in hex) along with a custom message.
    ///
    /// Useful for debugging or inspecting internal digit representation during development.
    /// This method is not meant for production logging.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bigint::BigInt;
    ///
    /// let num = BigInt::from_i32(42);
    /// num.debug_print("Inspecting digits");
    /// ```
    #[allow(dead_code)]
    pub fn debug_print(&self, msg: &str) {
        print!("{}: ", msg);
        for digit in self.digits.iter() {
            print!("{:08X} ", digit);
        }
        println!(" (hex: {})", self.to_hex());
    }
}

impl Add for BigInt {
    type Output = BigInt;

    /// Adds two `BigInt` values by reference and returns the result.
    ///
    /// This simply calls the implementation of `Add` for `&BigInt`, passing `&self` and
    /// `&other`. Consumes both `self` and `other`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(10);
    /// let b = BigInt::from_i32(5);
    /// let sum = a + b;  // Moves a and b
    /// assert_eq!(sum, BigInt::from_i32(15));
    /// ```
    fn add(self, other: BigInt) -> BigInt {
        &self + &other
    }
}

impl AddAssign for BigInt {
    /// Adds another `BigInt` to `self` in place.
    ///
    /// The `+=` operator uses the addition logic from `&BigInt + &BigInt`, then
    /// assigns the result back to `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let mut a = BigInt::from_i32(5);
    /// let b = BigInt::from_i32(10);
    ///
    /// a += b;  // In-place addition
    /// assert_eq!(a, BigInt::from_i32(15));
    /// ```
    fn add_assign(&mut self, other: BigInt) {
        *self = &*self + &other;
    }
}

impl Neg for BigInt {
    type Output = BigInt;

    /// Returns the negation of `self`.
    ///
    /// Equivalent to multiplying by -1. If `self` is zero, it remains zero (BigInt does
    /// not track negative zero).
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(42);
    /// let neg = -a;
    /// assert_eq!(neg, BigInt::from_i32(-42));
    /// ```
    fn neg(self) -> BigInt {
        self.negate()
    }
}

impl Sub for &BigInt {
    type Output = BigInt;

    /// Subtracts two `BigInt` references and returns a new `BigInt` result.
    ///
    /// This is implemented by reusing the addition logic: `a - b` is computed as
    /// `a + (-b)`. The sign and magnitude rules for addition apply accordingly.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(10);
    /// let b = BigInt::from_i32(4);
    ///
    /// let difference = &a - &b;
    /// assert_eq!(difference, BigInt::from_i32(6));
    /// ```
    fn sub(self, other: &BigInt) -> BigInt {
        // Reuse addition: a - b = a + (-b)
        self + &(-other.clone())
    }
}

impl Sub for BigInt {
    type Output = BigInt;

    /// Subtracts `other` from `self` by reference and returns the result.
    ///
    /// Consumes both `self` and `other`. Internally calls the `Sub` implementation
    /// for `&BigInt`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(8);
    /// let b = BigInt::from_i32(3);
    /// let diff = a - b;  // Moves a and b
    /// assert_eq!(diff, BigInt::from_i32(5));
    /// ```
    fn sub(self, other: BigInt) -> BigInt {
        &self - &other
    }
}

impl SubAssign for BigInt {
    /// Subtracts another `BigInt` from `self` in place.
    ///
    /// Implements the `-=` operator by reusing the `Sub` logic, then assigning
    /// the result back to `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let mut a = BigInt::from_i32(10);
    /// let b = BigInt::from_i32(6);
    ///
    /// a -= b;  // In-place subtraction
    /// assert_eq!(a, BigInt::from_i32(4));
    /// ```
    fn sub_assign(&mut self, other: BigInt) {
        *self = &*self - &other;
    }
}

impl Mul for &BigInt {
    type Output = BigInt;

    /// Multiplies two `BigInt` references.
    ///
    /// This operator automatically selects a multiplication strategy based on input size:
    /// - **Schoolbook multiplication** for small inputs (up to 32 digits).
    /// - **Karatsuba multiplication** for larger inputs.
    ///
    /// # Arguments
    ///
    /// * `other` - The `BigInt` to multiply with `self`.
    ///
    /// # Returns
    ///
    /// A new `BigInt` containing the product.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let x = BigInt::from_i32(6);
    /// let y = BigInt::from_i32(7);
    /// let product = &x * &y;
    /// assert_eq!(product, BigInt::from_i32(42));
    /// ```
    fn mul(self, other: &BigInt) -> BigInt {
        self.multiply(other)
    }
}

impl Mul for BigInt {
    type Output = BigInt;

    /// Multiplies two `BigInt` values by calling the `Mul` impl for `&BigInt`.
    ///
    /// Consumes both `self` and `other`. Internally, this performs `&self * &other`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let x = BigInt::from_i32(2);
    /// let y = BigInt::from_i32(3);
    ///
    /// let product = x * y;  // Moves x, y
    /// assert_eq!(product, BigInt::from_i32(6));
    /// ```
    fn mul(self, other: BigInt) -> BigInt {
        &self * &other
    }
}

impl Div for &BigInt {
    type Output = BigInt;

    /// Divides one `BigInt` reference by another and returns the quotient.
    ///
    /// Internally uses [`BigInt::div_rem`] to compute both quotient and remainder,
    /// then discards the remainder. Panics if `other` is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(17);
    /// let b = BigInt::from_i32(5);
    ///
    /// let quotient = &a / &b;
    /// assert_eq!(quotient, BigInt::from_i32(3));
    /// ```
    fn div(self, other: &BigInt) -> BigInt {
        self.div(other)
    }
}

impl Div for BigInt {
    type Output = BigInt;

    /// Divides `self` by `other` and returns the quotient.
    ///
    /// Consumes both `self` and `other`. Internally calls the `Div` impl
    /// for `&BigInt`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(25);
    /// let b = BigInt::from_i32(4);
    /// let quotient = a / b;  // Moves a, b
    /// assert_eq!(quotient, BigInt::from_i32(6));  // 25 / 4 = 6
    /// ```
    fn div(self, other: BigInt) -> BigInt {
        &self / &other
    }
}

impl DivAssign for BigInt {
    /// Divides `self` by another `BigInt` in place, discarding the remainder.
    ///
    /// Implements the `/=` operator via [`BigInt::div`].
    ///
    /// # Panics
    ///
    /// Panics if `other` is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let mut a = BigInt::from_i32(17);
    /// let b = BigInt::from_i32(5);
    ///
    /// a /= b;  // In-place division
    /// assert_eq!(a, BigInt::from_i32(3));
    /// ```
    fn div_assign(&mut self, other: BigInt) {
        *self = &*self / &other;
    }
}

impl Rem for &BigInt {
    type Output = BigInt;

    /// Computes the remainder of dividing one `BigInt` reference by another.
    ///
    /// This calls [`BigInt::rem`] internally. Panics if `other` is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(17);
    /// let b = BigInt::from_i32(5);
    ///
    /// let remainder = &a % &b;
    /// assert_eq!(remainder, BigInt::from_i32(2));
    /// ```
    fn rem(self, other: &BigInt) -> BigInt {
        self.rem(other)
    }
}

impl Rem for BigInt {
    type Output = BigInt;

    /// Computes the remainder of dividing `self` by `other`, consuming both.
    ///
    /// Internally calls the `Rem` impl for `&BigInt`. Panics if `other` is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let a = BigInt::from_i32(25);
    /// let b = BigInt::from_i32(4);
    ///
    /// let remainder = a % b;  // Moves a, b
    /// assert_eq!(remainder, BigInt::from_i32(1)); // 25 % 4 = 1
    /// ```
    fn rem(self, other: BigInt) -> BigInt {
        &self % &other
    }
}

impl RemAssign for BigInt {
    /// Computes `self % other` in place, discarding the quotient.
    ///
    /// Implements the `%=` operator via [`BigInt::rem`].
    ///
    /// # Panics
    ///
    /// Panics if `other` is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    ///
    /// let mut a = BigInt::from_i32(17);
    /// let b = BigInt::from_i32(5);
    ///
    /// a %= b;  // In-place remainder
    /// assert_eq!(a, BigInt::from_i32(2));
    /// ```
    fn rem_assign(&mut self, other: BigInt) {
        *self = &*self % &other;
    }
}

// Basic tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let zero = BigInt::new();
        assert_eq!(zero.digits, vec![0]);
        assert!(!zero.negative);

        let pos = BigInt::from_i32(42);
        assert_eq!(pos.digits, vec![42]);
        assert!(!pos.negative);

        let neg = BigInt::from_i32(-42);
        assert_eq!(neg.digits, vec![42]);
        assert!(neg.negative);
    }

    #[test]
    fn test_from_i64() {
        // Zero
        let min_i64 = BigInt::from_i64(i64::MIN);
        assert!(min_i64.negative);

        // Positive
        let big_pos = BigInt::from_i64(123456789);
        assert_eq!(format!("{}", big_pos), "123456789");

        // Negative
        let big_neg = BigInt::from_i64(-987654321);
        assert_eq!(format!("{}", big_neg), "-987654321");

        // Edge cases
        let max_i64 = BigInt::from_i64(i64::MAX);
        let min_i64 = BigInt::from_i64(i64::MIN);
        assert!(!max_i64.is_zero());
        assert!(min_i64.negative);
    }

    #[test]
    fn test_from_str_decimal() {
        // Simple positives
        let a = BigInt::from_str("12345").unwrap();
        assert_eq!(format!("{}", a), "12345");

        // Simple negatives
        let b = BigInt::from_str("-67890").unwrap();
        assert_eq!(format!("{}", b), "-67890");

        // Leading zeros
        let c = BigInt::from_str("0000123").unwrap();
        assert_eq!(format!("{}", c), "123");

        // Zero
        let zero = BigInt::from_str("0").unwrap();
        assert!(zero.is_zero());

        // Errors
        assert!(BigInt::from_str("").is_err());
        assert!(BigInt::from_str("  ").is_err());
        assert!(BigInt::from_str("-").is_err());
        assert!(BigInt::from_str("12ab3").is_err());
    }

    #[test]
    fn test_abs() {
        let pos = BigInt::from_i32(42);
        let neg = BigInt::from_i32(-42);

        assert_eq!(pos.abs(), pos);
        assert_eq!(neg.abs(), pos);
    }

    #[test]
    fn test_is_zero() {
        let zero = BigInt::new();
        let non_zero = BigInt::from_i32(42);

        assert!(zero.is_zero());
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_addition() {
        let cases = vec![
            (5, 3, 8),        // Simple positive addition
            (-5, -3, -8),     // Simple negative addition
            (5, -3, 2),       // Mixed signs, positive result
            (3, -5, -2),      // Mixed signs, negative result
            (0, 5, 5),        // Zero + positive
            (0, -5, -5),      // Zero + negative
            (5, 0, 5),        // Positive + zero
            (-5, 0, -5),      // Negative + zero
            (10, -7, 3),      // Larger numbers
            (-10, 7, -3),     // Larger numbers, opposite signs
            (1000, -999, 1),  // Large difference
            (-1000, 999, -1), // Large difference, opposite sign
        ];

        for (a, b, expected) in cases {
            let big_a = BigInt::from_i32(a);
            let big_b = BigInt::from_i32(b);
            let big_expected = BigInt::from_i32(expected);
            assert_eq!(
                &big_a + &big_b,
                big_expected,
                "Failed: {} + {} should be {}",
                a,
                b,
                expected
            );
        }
    }

    #[test]
    fn test_negation() {
        let cases = vec![(5, -5), (-5, 5), (0, 0)];

        for (input, expected) in cases {
            let big_input = BigInt::from_i32(input);
            let big_expected = BigInt::from_i32(expected);
            assert_eq!(-big_input, big_expected);
        }
    }

    #[test]
    fn test_add_assign() {
        let mut a = BigInt::from_i32(5);
        let b = BigInt::from_i32(3);
        a += b;
        assert_eq!(a, BigInt::from_i32(8));
    }

    #[test]
    fn test_display() {
        let cases = vec![
            (42, "42"),
            (-42, "-42"),
            (0, "0"),
            (123, "123"),
            (-123, "-123"),
        ];

        for (input, expected) in cases {
            let num = BigInt::from_i32(input);
            assert_eq!(format!("{}", num), expected);
        }
    }

    #[test]
    fn test_hex_display() {
        let cases = vec![
            (255, "FF"),
            (-255, "-FF"),
            (0, "0"),
            (16, "10"),
            (4096, "1000"),
        ];

        for (input, expected) in cases {
            let num = BigInt::from_i32(input);
            assert_eq!(num.to_hex(), expected);
        }
    }

    #[test]
    fn test_binary_display() {
        let cases = vec![
            (5, "101"),
            (-5, "-101"),
            (0, "0"),
            (8, "1000"),
            (15, "1111"),
        ];

        for (input, expected) in cases {
            let num = BigInt::from_i32(input);
            assert_eq!(num.to_binary(), expected);
        }
    }
    #[test]
    fn test_comparison() {
        let test_cases = vec![
            // (a, b, expected_ordering)
            (0, 0, Ordering::Equal),
            (1, 0, Ordering::Greater),
            (0, 1, Ordering::Less),
            (-1, 1, Ordering::Less),
            (1, -1, Ordering::Greater),
            (-2, -1, Ordering::Less),
            (-1, -2, Ordering::Greater),
            (100, 100, Ordering::Equal),
            (-100, -100, Ordering::Equal),
        ];

        for (a, b, expected) in test_cases {
            let big_a = BigInt::from_i32(a);
            let big_b = BigInt::from_i32(b);
            assert_eq!(
                big_a.cmp(&big_b),
                expected,
                "Failed comparing {} and {}",
                a,
                b
            );
        }
    }

    #[test]
    fn test_comparison_methods() {
        let five = BigInt::from_i32(5);
        let three = BigInt::from_i32(3);
        let neg_five = BigInt::from_i32(-5);
        let other_five = BigInt::from_i32(5);

        // Test less than
        assert!(three.is_less_than(&five));
        assert!(neg_five.is_less_than(&three));
        assert!(!five.is_less_than(&three));

        // Test greater than
        assert!(five.is_greater_than(&three));
        assert!(three.is_greater_than(&neg_five));
        assert!(!three.is_greater_than(&five));

        // Test less than or equal
        assert!(three.is_less_than_or_equal(&five));
        assert!(five.is_less_than_or_equal(&other_five));
        assert!(!five.is_less_than_or_equal(&three));

        // Test greater than or equal
        assert!(five.is_greater_than_or_equal(&three));
        assert!(five.is_greater_than_or_equal(&other_five));
        assert!(!three.is_greater_than_or_equal(&five));
    }

    #[test]
    fn test_multiplication() {
        let cases = vec![
            (0, 5, 0),         // Zero multiplication
            (1, 5, 5),         // Multiplication by 1
            (2, 3, 6),         // Simple multiplication
            (-2, 3, -6),       // Mixed signs
            (2, -3, -6),       // Mixed signs
            (-2, -3, 6),       // Negative * Negative
            (10, 10, 100),     // Larger numbers
            (-10, -10, 100),   // Larger numbers, both negative
            (100, 100, 10000), // Even larger numbers
        ];

        for (a, b, expected) in cases {
            let big_a = BigInt::from_i32(a);
            let big_b = BigInt::from_i32(b);
            let big_expected = BigInt::from_i32(expected);
            assert_eq!(
                &big_a * &big_b,
                big_expected,
                "Failed: {} * {} should be {}",
                a,
                b,
                expected
            );
        }
    }

    #[test]
    fn test_multiplication_large_numbers() {
        let cases = vec![
            // (a, b, expected_hex)
            (1_000_000, 1_000_000, "E8D4A51000"), // 1,000,000,000,000
            (1_000_000, 1, "F4240"),              // 1,000,000
            (0xFFFF, 0xFFFF, "FFFE0001"),         // 65535 * 65535
            (0x10000, 0x10000, "100000000"),      // 65536 * 65536
        ];

        for (a, b, expected) in cases {
            let big_a = BigInt::from_i32(a);
            let big_b = BigInt::from_i32(b);
            let result = &big_a * &big_b;
            assert_eq!(
                result.to_hex(),
                expected,
                "Failed: {} * {} should be {} in hex",
                a,
                b,
                expected
            );
        }

        // Test negative large numbers
        let neg_million = BigInt::from_i32(-1_000_000);
        let pos_million = BigInt::from_i32(1_000_000);
        assert_eq!((&neg_million * &neg_million).to_hex(), "E8D4A51000"); // Positive result
        assert_eq!((&neg_million * &pos_million).to_hex(), "-E8D4A51000"); // Negative result
    }

    #[test]
    fn test_subtraction() {
        let cases = vec![
            (5, 3, 2),      // Simple subtraction
            (3, 5, -2),     // Result is negative
            (-5, -3, -2),   // Negative numbers
            (-3, -5, 2),    // Negative numbers, positive result
            (0, 5, -5),     // Zero case
            (5, 0, 5),      // Zero case
            (0, -5, 5),     // Zero and negative
            (-5, 0, -5),    // Negative and zero
            (10, 7, 3),     // Larger numbers
            (1000, 999, 1), // Large close numbers
        ];

        for (a, b, expected) in cases {
            let big_a = BigInt::from_i32(a);
            let big_b = BigInt::from_i32(b);
            let big_expected = BigInt::from_i32(expected);
            assert_eq!(
                &big_a - &big_b,
                big_expected,
                "Failed: {} - {} should be {}",
                a,
                b,
                expected
            );
        }
    }

    #[test]
    fn test_sub_assign() {
        let mut a = BigInt::from_i32(5);
        let b = BigInt::from_i32(3);
        a -= b;
        assert_eq!(a, BigInt::from_i32(2));
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // ... (previous tests remain the same) ...

        #[test]
        fn test_karatsuba_multiplication() {
            let cases = vec![
                (
                    "FFFFFFFF", // 2^32 - 1
                    "FFFFFFFF",
                    "FFFFFFFE00000001", // (2^32 - 1)^2
                ),
                (
                    "FFFFFFFFFFFFFFFF", // 2^64 - 1
                    "FFFFFFFFFFFFFFFF",
                    "FFFFFFFFFFFFFFFE0000000000000001", // (2^64 - 1)^2
                ),
            ];

            for (a_hex, b_hex, expected) in cases {
                let big_a = BigInt::from_hex(a_hex).unwrap();
                let big_b = BigInt::from_hex(b_hex).unwrap();
                let result = &big_a * &big_b;
                assert_eq!(
                    result.to_hex(),
                    expected,
                    "Failed: {} * {} should be {}",
                    a_hex,
                    b_hex,
                    expected
                );
            }
        }

        #[test]
        fn test_shift_left() {
            let cases = vec![
                (0xFF, 1, "FF00"),
                (0xFF, 2, "FF0000"),
                (0x1234, 1, "123400"),
                (0, 1, "0"),
                (0xFF, 0, "FF"),
            ];

            for (input, shift, expected) in cases {
                let num = BigInt::from_i32(input as i32);
                assert_eq!(
                    num.shift_left(shift).to_hex(),
                    expected,
                    "Failed: {:X} << {} should be {}",
                    input,
                    shift,
                    expected
                );
            }
        }

        #[test]
        fn test_modulo() {
            let cases = vec![
                (17, 5, 2),  // Basic modulo
                (-17, 5, 3), // Negative number
                (5, 5, 0),   // Equal numbers
                (3, 5, 3),   // Number smaller than modulus
                (100, 7, 2), // Larger number
                (-13, 5, 2), // Another negative case
            ];

            for (a, m, expected) in cases {
                let big_a = BigInt::from_i32(a);
                let big_m = BigInt::from_i32(m);
                let big_expected = BigInt::from_i32(expected);
                assert_eq!(
                    big_a.modulo(&big_m),
                    big_expected,
                    "Failed: {} mod {} should be {}",
                    a,
                    m,
                    expected
                );
            }
        }

        #[test]
        fn test_mod_add() {
            let cases = vec![
                (12, 15, 7, 6),  // (12 + 15) mod 7 = 6
                (5, 3, 3, 2),    // (5 + 3) mod 3 = 2
                (-5, 3, 4, 2),   // (-5 + 3) mod 4 = 2
                (100, 50, 7, 3), // (100 + 50) mod 7 = 3
            ];

            for (a, b, m, expected) in cases {
                let big_a = BigInt::from_i32(a);
                let big_b = BigInt::from_i32(b);
                let big_m = BigInt::from_i32(m);
                let big_expected = BigInt::from_i32(expected);
                assert_eq!(
                    big_a.mod_add(&big_b, &big_m),
                    big_expected,
                    "Failed: ({} + {}) mod {} should be {}",
                    a,
                    b,
                    m,
                    expected
                );
            }
        }

        #[test]
        fn test_mod_sub() {
            let cases = vec![
                (12, 15, 7, 4),  // (12 - 15) mod 7 = 4
                (5, 3, 3, 2),    // (5 - 3) mod 3 = 2
                (-5, 3, 4, 0),   // (-5 - 3) mod 4 = 0
                (100, 50, 7, 1), // (100 - 50) mod 7 = 1
            ];

            for (a, b, m, expected) in cases {
                let big_a = BigInt::from_i32(a);
                let big_b = BigInt::from_i32(b);
                let big_m = BigInt::from_i32(m);
                let big_expected = BigInt::from_i32(expected);
                assert_eq!(
                    big_a.mod_sub(&big_b, &big_m),
                    big_expected,
                    "Failed: ({} - {}) mod {} should be {}",
                    a,
                    b,
                    m,
                    expected
                );
            }
        }
    }

    #[test]
    fn test_mod_mul() {
        let cases = vec![
            (3, 4, 5, 2),   // 12 mod 5 = 2
            (2, 3, 6, 0),   // 6 mod 6 = 0
            (10, 10, 6, 4), // 100 mod 6 = 4
            (-3, 4, 5, 3),  // -3*4 = -12, mod 5 -> 3
            (-2, -3, 7, 6), // (-2)*(-3) = 6, 6 mod 7 = 6
        ];
        for (a, b, m, expected) in cases {
            let big_a = BigInt::from_i32(a);
            let big_b = BigInt::from_i32(b);
            let big_m = BigInt::from_i32(m);
            let big_expected = BigInt::from_i32(expected);

            let result = big_a.mod_mul(&big_b, &big_m);
            assert_eq!(
                result, big_expected,
                "Failed: ({} * {}) mod {} should be {}",
                a, b, m, expected
            );
        }
    }

    #[test]
    fn test_debug_print() {
        let num = BigInt::from_i32(42);
        num.debug_print("Testing debug_print...");
    }

    #[test]
    fn test_division() {
        let cases = vec![
            (17, 5, 3, 2),    // Basic division with remainder
            (25, 5, 5, 0),    // Exact division
            (-17, 5, -3, -2), // Negative dividend
            (17, -5, -3, 2),  // Negative divisor
            (-17, -5, 3, -2), // Both negative
            (0, 5, 0, 0),     // Zero dividend
            (5, 7, 0, 5),     // Divisor larger than dividend
        ];

        for (a, b, q, r) in cases {
            let big_a = BigInt::from_i32(a);
            let big_b = BigInt::from_i32(b);
            let (quotient, remainder) = big_a.div_rem(&big_b);
            assert_eq!(
                quotient,
                BigInt::from_i32(q),
                "Failed division: {} / {} should give quotient {}",
                a,
                b,
                q
            );
            assert_eq!(
                remainder,
                BigInt::from_i32(r),
                "Failed division: {} / {} should give remainder {}",
                a,
                b,
                r
            );
        }
    }

    #[test]
    #[should_panic(expected = "Division by zero")]
    fn test_division_by_zero() {
        let a = BigInt::from_i32(42);
        let b = BigInt::new();
        let _ = a.div_rem(&b);
    }

    #[test]
    fn test_division_large_numbers() {
        let cases = vec![
            // "1000000" in hex -> decimal 16,777,216
            // "F4240"   in hex -> decimal 1,000,000
            //
            // 16,777,216 / 1,000,000 = 16 remainder 777,216
            // => quotient in hex  = "10"   (16 decimal)
            // => remainder in hex = "BDC00" (777,216 decimal)
            ("1000000", "F4240", "10", "BDC00"),
            // 2^32 - 1 => 0xFFFFFFFF (decimal 4294967295)
            // 2^16     => 0x10000     (decimal 65536)
            //
            // 4294967295 / 65536 = 65535 remainder 65535
            // => quotient in hex = "FFFF"
            // => remainder in hex = "FFFF"
            ("FFFFFFFF", "10000", "FFFF", "FFFF"),
        ];

        for (a_hex, b_hex, q_hex, r_hex) in cases {
            let a = BigInt::from_hex(a_hex).unwrap();
            let b = BigInt::from_hex(b_hex).unwrap();
            let expected_q = BigInt::from_hex(q_hex).unwrap();
            let expected_r = BigInt::from_hex(r_hex).unwrap();

            let (q, r) = a.div_rem(&b);
            assert_eq!(
                q, expected_q,
                "Failed division: {} / {} should give quotient {}",
                a_hex, b_hex, q_hex
            );
            assert_eq!(
                r, expected_r,
                "Failed division: {} / {} should give remainder {}",
                a_hex, b_hex, r_hex
            );
        }
    }

    #[cfg(test)]
    mod montgomery_tests {
        use super::*;
        use crate::montgomery::montgomery::MontgomeryContext;

        /// A small helper that creates a MontgomeryContext for a given integer (modulus).
        /// In real usage, you'd pick a large prime or typical crypto modulus.
        fn create_montgomery_ctx(m: i32) -> MontgomeryContext {
            let m_big = BigInt::from_i32(m);
            MontgomeryContext::new(m_big)
        }

        #[test]
        fn test_montgomery_basic() {
            // We'll test mod 7, then do a small multiply
            let ctx = create_montgomery_ctx(7);

            let a = BigInt::from_i32(3);
            let b = BigInt::from_i32(4);

            // Convert a & b into Montgomery form
            let a_mont = ctx.to_montgomery(&a);
            let b_mont = ctx.to_montgomery(&b);

            // Do Montgomery multiplication
            let prod_mont = ctx.mont_mul(&a_mont, &b_mont);

            // Convert back to normal form
            let prod_normal = ctx.from_montgomery(&prod_mont);

            // 3 * 4 = 12, and 12 mod 7 = 5
            let expected = BigInt::from_i32(5);
            assert_eq!(
                prod_normal, expected,
                "Montgomery multiply failed for 3*4 mod 7"
            );
        }

        #[test]
        fn test_montgomery_identity() {
            // If we multiply x by 1 in Montgomery form, we should get x.
            let ctx = create_montgomery_ctx(7);

            let x = BigInt::from_i32(5);
            let x_mont = ctx.to_montgomery(&x);

            // Montgomery representation of 1
            let one = BigInt::from_i32(1);
            let one_mont = ctx.to_montgomery(&one);

            // x' * 1' in Mont form
            let prod_mont = ctx.mont_mul(&x_mont, &one_mont);
            let prod_normal = ctx.from_montgomery(&prod_mont);

            assert_eq!(prod_normal, x, "x * 1 should yield x in Montgomery domain");
        }
    }

    #[cfg(test)]
    mod barrett_tests {
        use super::*;
        use crate::barrett::{barrett::barrett_mul, barrett::barrett_reduce, barrett::BarrettContext};

        /// Create a BarrettContext for a small integer modulus.
        fn create_barrett_ctx(m: i32) -> BarrettContext {
            let m_big = BigInt::from_i32(m);
            BarrettContext::new(m_big)
        }

        #[test]
        fn test_barrett_reduce_basic() {
            // Test x mod 7
            let ctx = create_barrett_ctx(7);
            let x = BigInt::from_i32(25); // 25 mod 7 = 4
            let reduced = barrett_reduce(&x, &ctx);
            let expected = BigInt::from_i32(4);
            assert_eq!(reduced, expected, "Barrett reduce failed for 25 mod 7");
        }

        #[test]
        fn test_barrett_mul_small() {
            // We'll do (3*4) mod 7 again, but with Barrett
            let ctx = create_barrett_ctx(7);

            let a = BigInt::from_i32(3);
            let b = BigInt::from_i32(4);

            let product_mod = barrett_mul(&a, &b, &ctx);
            let expected = BigInt::from_i32(5); // 12 mod 7 = 5
            assert_eq!(
                product_mod, expected,
                "Barrett multiply failed for 3*4 mod 7"
            );
        }

        #[test]
        fn test_barrett_mul_negative() {
            let ctx = create_barrett_ctx(7);
            let a = BigInt::from_i32(-3);
            let b = BigInt::from_i32(4);

            // Now expect: -3*4 = -12 => mod 7 => 2
            let product_mod = barrett_mul(&a, &b, &ctx);
            let expected = BigInt::from_i32(2);
            assert_eq!(
                product_mod, expected,
                "Barrett multiply failed for -3*4 mod 7"
            );
        }
    }
}
