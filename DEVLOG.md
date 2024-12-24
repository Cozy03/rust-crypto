# Development Log

## 2024-12-22
### Initial Setup
- Created workspace structure
- Set up crate hierarchy
- Created README and documentation
- Initialized git repository

### BigInt Implementation Phase 1: Foundation
- Created basic `BigInt` struct with documentation
- Implemented core functionality:
  - `new()` for zero initialization
  - `from_i32()` for integer conversion
  - `normalize()` for internal representation
  - `is_zero()` for zero checking
  - `abs()` for absolute value

### BigInt Implementation Phase 2: Basic Arithmetic (Addition)
- Implemented addition operations:
  - `add_absolute()` for unsigned addition
  - Addition trait (`Add`, `AddAssign`) implementation
  - Support for both owned and referenced addition
- Implemented sign handling:
  - `negate()` for sign negation
  - Negation trait (`Neg`) implementation
- Added comparison functionality:
  - `compare_abs()` for absolute value comparison

### BigInt Implementation Phase 3: Comparison & Display
- Implemented `Display` trait with proper formatting
- Added specialized string representations:
  - Hexadecimal (`to_hex()`)
  - Binary (`to_binary()`)
- Implemented comparison traits:
  - `PartialOrd` for partial ordering
  - `Ord` for total ordering
  - Helper comparison methods (`is_less_than`, `is_greater_than`, etc.)

### BigInt Implementation Phase 4: Subtraction
- Implemented subtraction operations:
  - `sub_absolute()` for unsigned subtraction with borrow handling
  - Subtraction trait (`Sub`, `SubAssign`) implementation
  - Support for both owned and referenced subtraction

### BigInt Implementation Phase 5: Hexadecimal Parsing
- Added parsing functionality:
  - `from_hex()` to create `BigInt` from a hexadecimal string
  - Error handling for invalid characters
  - Support for negative numbers and optional `0x` prefix
- Added comprehensive test cases for `from_hex()`

### BigInt Implementation Phase 6: Multiplication
- Implemented multiplication operations:
  - Basic schoolbook multiplication for small numbers
  - Karatsuba multiplication for large numbers
- Benchmarked multiplication algorithms:
  - Identified performance improvements using Karatsuba
- Added test cases to verify multiplication correctness

## 2024-12-23
### BigInt Implementation Phase 7: Additional Constructors & Modular Multiplication Enhancements
- **Implemented Additional Constructors**:
  - `from_i64(value: i64) -> BigInt`:
    - Allows creation of `BigInt` from 64-bit signed integers.
    - Handled special case for `i64::MIN` to prevent overflow.
  - `from_str(value: &str) -> Result<BigInt, String>`:
    - Enables parsing `BigInt` from base-10 decimal strings.
    - Supports optional leading `-` for negative numbers.
    - Includes error handling for invalid input strings.
- **Enhanced Modular Multiplication (`mod_mul`)**:
  - Updated `mod_mul` to **conditionally use Barrett reduction** for larger moduli:
    - Defined a threshold based on the number of 32-bit digits (e.g., moduli with more than 2 digits use Barrett).
    - For moduli exceeding the threshold, `BarrettContext` is created and `barrett_mul` is utilized.
    - For smaller moduli, standard multiplication followed by modulo operation is used.
  - **Optimized Context Management**:
    - Recognized the importance of reusing `BarrettContext` for multiple operations with the same modulus to enhance performance.
    - Considered introducing a wrapper struct (e.g., `ModArithmetic`) to manage and reuse contexts efficiently.

### Testing & Validation
- **Expanded Test Suite**:
  - Added test cases for `from_i64` ensuring correct handling of edge cases like `i64::MIN` and `i64::MAX`.
  - Comprehensive tests for `from_str` covering valid inputs, negative numbers, leading zeros, and invalid strings.
  - Updated existing tests to cover scenarios where `mod_mul` switches between standard and Barrett reduction.
  - Ensured all arithmetic operations maintain correctness across positive and negative values.
- **Benchmarking Setup**:
  - Integrated **Criterion** for benchmarking modular multiplication:
    - Benchmarked three methods: Normal Mod Mul, Barrett Mod Mul, and Montgomery Mod Mul across various moduli sizes.
    - Observed performance characteristics and identified scenarios where Barrett and Montgomery offer advantages.

### Benchmark Results
- Conducted benchmarks comparing different modular multiplication strategies.
- Observed that:
  - **Normal Mod Mul** performs efficiently for smaller moduli.
  - **Barrett Mod Mul** introduces overhead for single operations but is beneficial for repeated multiplications with the same modulus.
  - **Montgomery Mod Mul** shows higher overhead in single operations but scales well with numerous multiplications in cryptographic applications.

### Documentation Updates
- Updated crate documentation to reflect new constructors and enhanced `mod_mul` functionality.
- Added usage examples showcasing how to utilize `from_i64`, `from_str`, and the enhanced `mod_mul`.
- Documented benchmarking results and insights to guide future optimizations.

### Code Refactoring
- Refactored `mod_mul` to include conditional logic for choosing between standard modulo and Barrett reduction.
- Ensured clean separation of concerns by maintaining separate modules for Barrett and Montgomery operations.
- Improved internal documentation and comments for better code maintainability.

## Next Steps (In Priority Order)

### Phase 8: Division & Modular Arithmetic
1. Basic division algorithm
2. Modulo operation
3. Modular multiplication
4. Montgomery multiplication
5. Barrett reduction

### Phase 9: Advanced Optimizations
1. Memory optimization for digit storage
2. SIMD operations where applicable
3. Constant-time operations for cryptographic use

### Phase 10: Additional Features
1. Conversion from/to other number formats:
   - String parsing
   - Conversion to/from bytes
   - Support for different bases
2. Serialization/Deserialization support
3. Random number generation
4. Prime number utilities

### Phase 11: Cryptographic Features
1. Modular exponentiation
2. Prime generation
3. Miller-Rabin primality test
4. GCD and Extended Euclidean Algorithm
5. Modular inverse calculation

### Phase 12: Documentation & Testing
1. Complete API documentation
2. Property-based testing
3. Fuzzing tests
4. Performance benchmarks
5. Security considerations documentation

---

## Summary of Recent Changes

- **Constructors**: Added `from_i64` and `from_str` to enhance `BigInt` creation capabilities.
- **Modular Multiplication**: Enhanced `mod_mul` to intelligently select between standard modulo and Barrett reduction based on modulus size.
- **Benchmarking**: Integrated Criterion for performance evaluation of different modular multiplication strategies.
- **Testing**: Expanded test coverage to ensure robustness across various operations and edge cases.
- **Documentation**: Updated and expanded documentation to reflect new functionalities and usage patterns.