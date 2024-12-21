# Rust Cryptography Learning Journey

A comprehensive implementation of cryptographic primitives and protocols in Rust, built from scratch for learning purposes.

⚠️ **Educational Purpose Only**: These implementations are for learning and should not be used in production environments.

## 🗺️ Project Structure

```
rust-crypto/
├── crates/
│   ├── bigint/           # Custom BigInt implementation
│   ├── hash/             # Hash function implementations
│   ├── symmetric/        # Symmetric encryption algorithms
│   ├── asymmetric/       # Public key cryptography
│   ├── protocols/        # Cryptographic protocols
│   ├── zkp/              # Zero-knowledge proofs
│   ├── mpc/              # Multi-party computation
│   └── pqc/              # Post-quantum cryptography
└── examples/             # Example applications using our implementations
    ├── password-manager/
    ├── secure-chat/
    └── blockchain/
```

## 🎯 Learning Roadmap

### Phase 1: Fundamentals
- [x] Repository Setup
- [ ] BigInt Library Implementation
  - [ ] Basic Operations
  - [ ] Modular Arithmetic
  - [ ] Karatsuba Multiplication
  - [ ] Montgomery Arithmetic

### Phase 2: Basic Cryptography
- [ ] Hash Functions
  - [ ] SHA-256
  - [ ] SHA-3
  - [ ] Merkle Trees
- [ ] Symmetric Encryption
  - [ ] AES-256
  - [ ] ChaCha20
  - [ ] Poly1305

[View full roadmap in ROADMAP.md](./ROADMAP.md)

## 🚀 Getting Started

### Prerequisites
- Rust (latest stable version)
- Cargo
- Git

### Setup Commands
```bash
# Clone the repository
git clone https://github.com/yourusername/rust-crypto.git
cd rust-crypto

# Create new crate for BigInt
cargo new --lib crates/bigint
cd crates/bigint

# Setup workspace in root Cargo.toml
cd ../..
```

### Running Tests
```bash
# Run all tests
cargo test --all

# Run specific crate tests
cargo test -p bigint
```

## 📚 Learning Resources

### Books
- Programming Bitcoin in Rust
- Real World Cryptography
- Cryptography Engineering

### Online Resources
- Rust Cookbook
- RustCrypto GitHub Organization
- Documentation for standard implementations

## 🧪 Testing Philosophy

Each implementation includes:
- Unit tests with standard test vectors
- Property-based testing where applicable
- Benchmarks against established libraries
- Security assumption documentation

## 📝 Documentation Standards

Each crate should include:
- Detailed API documentation
- Implementation notes
- Security considerations
- Usage examples

## 🤝 Contributing

While this is a personal learning project, suggestions and discussions are welcome:
1. Open an issue for discussion
2. Fork the repository
3. Create a feature branch
4. Submit a pull request

## 📋 Progress Tracking

Progress is tracked through:
- GitHub Projects board
- Milestone tracking
- Issue labels for different topics
- Regular commits with detailed messages

## 🔍 Code Review Checklist

Before marking any implementation as complete:
- [ ] Comprehensive test coverage
- [ ] Documentation complete
- [ ] Security considerations documented
- [ ] Benchmarks implemented
- [ ] Code reviewed for constant-time operations
- [ ] No unsafe code without justification

## 📅 Development Log

Keep track of learning progress in [DEVLOG.md](./DEVLOG.md)