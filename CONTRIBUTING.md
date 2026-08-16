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

### Branch Protection & Repository Rules

The `main` branch is strictly protected by GitHub Rulesets. All contributions must comply with the following automated requirements:

1. **Pull Requests Required**: Direct pushes to `main` are prohibited. All changes must be submitted via Pull Requests from a topic branch or fork.
2. **Automated CI Status Checks (Strict)**: A PR can only be merged when all 7 pipeline checks succeed against the latest `main`:
   - `Test (ubuntu-latest)`: Linux unit & integration tests with race detector.
   - `Test (windows-latest)`: Windows-specific filesystem and locking tests.
   - `Test (macos-latest)`: macOS build and integration tests.
   - `Lint`: Code style and static analysis via `golangci-lint`.
   - `Security Scan`: Automated vulnerability scanning with `gosec` and `govulncheck`.
   - `Memory Allocation Check`: Zero-allocation and memory safety benchmarks.
   - `Build Verification`: Static binary compilation validation.
3. **Signed Commits**: All commits must be cryptographically signed (GPG, SSH, or GitHub Web verified).
4. **Linear Git History**: Only clean, linear history is accepted (`Squash and merge` or `Rebase and merge`). Merge commits are rejected.
5. **Conversation Resolution**: All review comments and discussions must be resolved prior to merging.

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
- **Security**: Code must pass `gosec` and `govulncheck` with zero identified vulnerabilities.
- **Documentation**: All public functions, structs, and interfaces must be documented using standard GoDoc format.

## Security Considerations

Given the nature of the project, security is the primary directive. 

### Critical Modules

Modifications to the following modules require rigorous scrutiny and extended peer review:
- `internal/crypto/`: Cryptographic primitives and implementations.
- `internal/storage/`: Encrypted file IO and atomic operations.
- `internal/memory/`: Memory protection and allocation.
- `internal/audit/`: Structured audit logging and integrity hash chains.
- `internal/ui/`: Handling of raw user inputs and terminal output.

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