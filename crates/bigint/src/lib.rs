// crates/bigint/src/lib.rs

//! A BigInt implementation for cryptographic operations
//! 
//! This module provides arbitrary-precision integer arithmetic
//! specifically designed for cryptographic computations.
//! It implements basic arithmetic operations and modular arithmetic
//! optimized for cryptographic use cases.

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
}