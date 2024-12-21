// crates/bigint/src/lib.rs

//! A BigInt implementation for cryptographic operations
//!
//! This module provides arbitrary-precision integer arithmetic
//! specifically designed for cryptographic computations.
//! It implements basic arithmetic operations and modular arithmetic
//! optimized for cryptographic use cases.
//!

use std::fmt;

impl fmt::Display for BigInt {
    /// Formats the BigInt as a decimal string.
    ///
    /// # Examples
    ///
    /// ```
    /// use bigint::BigInt;
    /// let num = BigInt::from_i32(-123);
    /// assert_eq!(format!("{}", num), "-123");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.negative {
            write!(f, "-")?;
        }

        // For now, just display the direct digit value
        // Later we'll implement proper base conversion
        write!(f, "{}", self.digits[0])
    }
}


use std::cmp::Ordering;

impl PartialOrd for BigInt {
    /// Implements partial comparison between BigInts.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use bigint::BigInt;
    /// let a = BigInt::from_i32(5);
    /// let b = BigInt::from_i32(3);
    /// assert!(a > b);
    /// ```
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigInt {
    /// Implements total ordering for BigInts.
    /// Numbers are ordered based on their value, with negative numbers being less than
    /// positive numbers.
    fn cmp(&self, other: &Self) -> Ordering {
        // If signs are different, negative is less
        if self.negative != other.negative {
            return if self.negative {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }

        // If both are negative, reverse the comparison
        let ordering = match self.compare_abs(other) {
            Some(true) => Ordering::Greater,
            Some(false) => Ordering::Less,
            None => Ordering::Equal,
        };

        if self.negative {
            ordering.reverse()
        } else {
            ordering
        }
    }
}

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
use std::ops::{Add, AddAssign, Neg};

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

        // Don't forget the final carry
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

    /// Returns the number with its sign negated
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
    fn sub_absolute(&self, other: &BigInt) -> BigInt {
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
    
        // Convert to hexadecimal, starting with most significant digit
        let mut started = false;
        for &digit in self.digits.iter().rev() {
            // Skip leading zeros in each digit except the last one
            if started {
                hex.push_str(&format!("{:08X}", digit));
            } else {
                let formatted = format!("{:X}", digit);
                if formatted != "0" {
                    hex.push_str(&formatted);
                    started = true;
                }
            }
        }
    
        // Handle case where the number is zero
        if !started {
            hex.push('0');
        }
    
        hex
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

}

impl Add for &BigInt {
    type Output = BigInt;

    fn add(self, other: &BigInt) -> BigInt {
        if self.negative == other.negative {
            // If signs are same, add absolute values and keep the sign
            let mut result = self.add_absolute(other);
            result.negative = self.negative;
            result
        } else {
            // If signs are different, subtract the smaller absolute value from the larger
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

impl Add for BigInt {
    type Output = BigInt;

    fn add(self, other: BigInt) -> BigInt {
        &self + &other
    }
}

impl AddAssign for BigInt {
    fn add_assign(&mut self, other: BigInt) {
        *self = &*self + &other;
    }
}

impl Neg for BigInt {
    type Output = BigInt;

    fn neg(self) -> BigInt {
        self.negate()
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
            assert_eq!(big_a.cmp(&big_b), expected, 
                "Failed comparing {} and {}", a, b);
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
}
