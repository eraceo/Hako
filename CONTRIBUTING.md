# Contributing Guide - Hako

This document outlines the guidelines and processes for contributing to the Hako project. As a security-focused application, strict adherence to these guidelines is required to maintain the integrity, stability, and security of the codebase.

## Quick Start

### Prerequisites

Ensure the following tools are installed in your development environment:
- Go 1.25 or higher
- Git
- Make (recommended for automation)

### Development Environment Setup

```bash
# Clone the repository
git clone https://github.com/eraceo/Hako.git
cd hako

# Install dependencies
make deps

# Build the project and run test suites
make build
make test
```

## Project Architecture

Familiarize yourself with the repository structure before contributing:

```text
.
├── .github/
│   ├── assets/
│   │   └── Hako.png            # Project logo
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md       # Bug report template
│   │   └── feature_request.md  # Feature request template
│   └── workflows/
│       ├── ci.yml              # CI Pipeline (Tests, Linting)
│       └── release.yml         # Release pipeline (Goreleaser)
├── cmd/
│   └── hako/
│       └── main.go             # Entry point: Cobra initialization and execution
├── internal/                   # Private application code
│   ├── audit/
│   │   ├── logger.go           # Structured logging of security events
│   │   ├── logger_test.go      # Tests for the logger
│   │   ├── scanner.go          # Vault security audit (weak/duplicated passwords)
│   │   └── scanner_test.go     # Tests for the scanner
│   ├── cli/                    # CLI commands (Cobra)
│   │   ├── add.go              # 'add' command: Add an entry
│   │   ├── add_test.go         # Tests for the add command
│   │   ├── audit.go            # 'audit' command: Run a security audit
│   │   ├── audit_test.go       # Tests for the audit command
│   │   ├── completion.go       # 'completion' command: Generate shell autocompletion
│   │   ├── completion_test.go  # Tests for the completion command
│   │   ├── edit.go             # 'edit' command: Edit an entry
│   │   ├── edit_test.go        # Tests for the edit command
│   │   ├── export.go           # 'export' command: Export the vault (JSON/CSV)
│   │   ├── export_test.go      # Tests for the export command
│   │   ├── generate.go         # 'generate' command: Generate a strong password
│   │   ├── generate_test.go    # Tests for the generate command
│   │   ├── get.go              # 'get' command: Retrieve and decrypt an entry
│   │   ├── get_test.go         # Tests for the get command
│   │   ├── import.go           # 'import' command: Import data
│   │   ├── import_test.go      # Tests for the import command
│   │   ├── init.go             # 'init' command: Initialize a new vault
│   │   ├── init_test.go        # Tests for the init command
│   │   ├── list.go             # 'list' command: List entries
│   │   ├── list_test.go        # Tests for the list command
│   │   ├── passwd.go           # 'passwd' command: Change the master password
│   │   ├── passwd_test.go      # Tests for the passwd command
│   │   ├── printer.go          # Helpers for formatted output (Tables, JSON)
│   │   ├── printer_test.go     # Tests for printer helpers
│   │   ├── remove.go           # 'remove' command: Remove an entry
│   │   ├── remove_test.go      # Tests for the remove command
│   │   ├── root.go             # Root command and global flags
│   │   ├── root_test.go        # Tests for root configuration and flags
│   │   ├── search.go           # 'search' command: Search in the vault
│   │   ├── search_test.go      # Tests for the search command
│   │   ├── test_helpers.go     # Shared testing utilities (I/O Mocks, Vault setup)
│   │   ├── version.go          # 'version' command: Show the version
│   ├── clipboard/
│   │   ├── clipboard.go        # Secure clipboard management (copy + auto-clear)
│   │   └── clipboard_test.go   # Tests for the clipboard
│   ├── config/
│   │   ├── config.go           # Configuration loading (Viper)
│   │   └── config_test.go      # Configuration tests
│   ├── crypto/
│   │   ├── crypto.go           # Crypto primitives (AES-GCM, Argon2id, HKDF)
│   │   └── crypto_test.go      # Crypto tests and test vectors
│   ├── encoding/
│   │   └── tlv/
│   │       ├── tlv.go          # TLV (Tag-Length-Value) Encoding/Decoding
│   │       └── tlv_test.go     # Tests for the TLV encoding
│   ├── entropy/
│   │   ├── entropy.go          # Password entropy calculation (simplistic Zxcvbn-like)
│   │   └── entropy_test.go     # Entropy tests
│   ├── memory/
│   │   ├── secure.go           # Memguard wrapper for secure memory (SecureString)
│   │   └── secure_test.go      # Memory management tests
│   ├── secrets/
│   │   ├── entry.go            # 'Entry' data model (Password entry)
│   │   ├── entry_test.go       # Tests for the Entry model
│   │   ├── generator.go        # Password generation logic
│   │   └── generator_test.go   # Tests for the generator
│   ├── storage/
│   │   ├── vault.go            # Vault file management (Atomic Read/Write)
│   │   ├── vault_test.go       # Storage tests
│   │   ├── vault_unix.go       # File locking (Flock) for Unix
│   │   ├── vault_windows.go    # File locking for Windows
│   │   └── vault_windows_test.go # Windows-specific tests
│   ├── ui/
│   │   ├── prompt.go           # Interactive prompts (Masked password input)
│   │   ├── prompt_test.go      # UI tests
│   │   ├── sanitize.go         # String sanitization for terminal display
│   │   └── sanitize_test.go    # Sanitization tests
│   ├── validation/
│   │   ├── validator.go        # User input validation (business rules)
│   │   └── validator_test.go   # Validation tests
│   └── version/
│       ├── version.go          # Version constants and build metadata
│       └── version_test.go     # Version tests
├── scripts/
│   ├── e2e_test.ps1            # End-to-end tests (PowerShell)
│   ├── e2e_test.sh             # End-to-end tests (Bash)
│   ├── install.ps1             # Installation script (Windows)
│   └── install.sh              # Installation script (Unix)
├── test/
│   ├── benchmark_test.go       # Benchmark tests
│   └── integration_test.go     # Global integration tests
├── .gitignore                  # Files ignored by Git
├── .golangci.yml               # Linter configuration (golangci-lint)
├── .goreleaser.yaml            # Build and release configuration
├── config.example.yaml         # Example configuration file
├── CONTRIBUTING.md             # Contributing guide
├── go.mod                      # Go module definition and dependencies
├── go.sum                      # Dependency checksums
├── LICENSE                     # Project license
├── Makefile                    # Build commands (Make)
├── QUICKSTART.md               # Quickstart guide
├── README.md                   # Main documentation
└── ROADMAP.md                  # Project roadmap
```

## Testing and Quality

All code submissions must pass automated pipelines. Local verification is highly recommended prior to opening a Pull Request.

### Verification Commands

```bash
# Run unit tests
make test

# Run tests with coverage reporting
make test-coverage

# Run integration tests
go test ./test -v

# Run static analysis
make lint

# Run security checks
make security-check
```

### Quality Standards

- **Test Coverage**: A minimum of 80% coverage is required for all critical modules.
- **Linting**: Code must pass `golangci-lint` with zero errors or warnings.
- **Security**: Code must pass `gosec` with zero identified vulnerabilities.
- **Documentation**: All public functions, structs, and interfaces must be documented using standard GoDoc format.

## Security Considerations

Given the nature of the project, security is the primary directive. 

### Critical Modules

Modifications to the following modules require rigorous scrutiny and extended peer review:
- `internal/crypto/`: Cryptographic primitives and implementations.
- `internal/storage/`: Encrypted file IO and atomic operations.
- `internal/memory/`: Memory protection and allocation.
- `pkg/ui/`: Handling of raw user inputs and terminal output.

### Security Rules

1. **Log Sanitization**: Never output plaintext passwords, cryptographic keys, or sensitive user data to standard output or log files.
2. **Memory Management**: Sensitive data must be securely zeroed out immediately after its required scope ends (utilize the `memory` package).
3. **Input Validation**: All external inputs (CLI arguments, file reads, prompt inputs) must be strictly validated.
4. **Cryptographic Integrity**: Any changes to cryptographic paths must be accompanied by relevant test vectors and benchmark tests.

## Contribution Workflow

### 1. Repository Setup

```bash
# Clone your personal fork
git clone https://github.com/your-username/hako.git
cd hako

# Set the original repository as upstream
git remote add upstream https://github.com/eraceo/Hako.git
```

### 2. Development Phase

```bash
# Sync with upstream and create a designated branch
git checkout main
git pull upstream main
git checkout -b feature/issue-id-description

# Ensure continuous testing during development
make test
make lint

# Commit using the standard convention (see below)
git commit -m "feat(crypto): add hardware token support"
```

### 3. Submission

```bash
# Push the branch to your fork
git push origin feature/issue-id-description
```
Proceed to GitHub to open a Pull Request against the `main` branch.

## Contribution Categories

### Bug Fixes
- Write a failing test that reproduces the bug.
- Implement the fix.
- Ensure the test passes, effectively establishing a regression test.

### New Features
- Open an Issue first to discuss the implementation details and alignment with the project roadmap.
- Implement the feature alongside comprehensive unit and integration tests.
- Update relevant markdown documentation.

### Technical Debt & Maintenance
- Refactoring, performance optimizations, and dependency updates are welcome.
- Benchmarks must be provided for performance-related changes.

## Code Conventions

### Go Style Guidelines
- Code must be formatted using `gofmt` and `goimports`.
- Adhere strictly to the standard Go Code Review Comments.

### Commit Messages
We strictly follow the Conventional Commits specification.

Format: `type(scope): description`

**Types**:
- `feat`: New feature implementation.
- `fix`: Bug resolution.
- `docs`: Documentation updates.
- `style`: Code style changes (formatting, missing semi-colons, etc.).
- `refactor`: Code changes that neither fix a bug nor add a feature.
- `test`: Addition or correction of tests.
- `chore`: Routine tasks, dependency updates, or build process changes.

**Examples**:
```text
feat(crypto): implement Argon2id key derivation
fix(storage): resolve race condition during vault save
docs(readme): update CI/CD badges
```

### Code Documentation Example

```go
// DeriveKey generates a cryptographic key from a master password.
// It requires a non-empty password and a valid salt.
// Returns an error if the memory allocation for the secure string fails.
func DeriveKey(password string, salt []byte) (*memory.SecureString, error) {
    // Implementation
}
```

## Review Process

All Pull Requests are subjected to peer review. Ensure your submission meets the following criteria to expedite the process.

### Pull Request Checklist
- [ ] Automated tests pass (`make test`).
- [ ] Static analysis is clean (`make lint`).
- [ ] Security checks pass (`make security-check`).
- [ ] GoDoc and markdown documentation are updated.
- [ ] Git commit history is clean and rebased against the latest `main`.

### Acceptance Criteria
1. **Functionality**: The code strictly resolves the documented issue.
2. **Maintainability**: The logic is clear, modular, and adheres to project standards.
3. **Reliability**: Test coverage is adequate and meaningful.
4. **Security**: No attack vectors or memory leaks are introduced.
5. **Performance**: No unacknowledged degradation in execution time or memory footprint.

## Issue Reporting

### Standard Issues
Use the provided GitHub Issue templates to report bugs or request features. Include explicit reproduction steps, expected outputs, and environment details (OS, Architecture, Go version).

### Security Vulnerabilities
**Do not report security vulnerabilities via public GitHub Issues.**
If you discover a potential security flaw, please review the security policy in the repository (if provided) or contact the maintainers directly through private channels to facilitate a responsible disclosure process.

## General Inquiries

For general questions or architectural discussions, utilize GitHub Discussions. Save GitHub Issues strictly for actionable codebase changes. 

We appreciate your time and adherence to these standards to ensure Hako remains a secure and reliable tool.