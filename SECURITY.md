# Security policy

Security is why Hako exists. We focus on cryptographic correctness, memory safety, and defense-in-depth. If you find a bug, we'll work with you to verify and patch it as quickly as we can.

## Supported versions

We only provide security patches for the latest major version.

| Version | Status |
| ------- | ------------------ |
| v1.x.x  | Supported |
| < v1.0  | No longer supported |

---

## Reporting a vulnerability

**Please don't report security bugs in public issues.** 

We use GitHub's **Private Vulnerability Reporting** feature. To submit a report:
1. Navigate to the **Security** tab of this repo.
2. Click **Report a vulnerability**.

### Helping us fix it faster
The more detail you provide, the faster we can triage. Please include:
*   A clear description of the bug and its potential impact.
*   Steps to reproduce the issue (including scripts or config files).
*   Your environment (OS, Go version, and `hako version`).
*   A harmless Proof of Concept (PoC) if possible.

### What to expect
*   **Acknowledgment**: We'll get back to you within 48 hours.
*   **Triage**: We aim to verify reports within 5 business days.
*   **Fixes**: Critical issues are usually patched within two weeks.

We follow **Coordinated Vulnerability Disclosure**. We ask that you keep details private until we've released a patch.

---

## Threat model

Hako is a local CLI tool. We assume your OS provides standard process isolation between users.

### High-priority areas
We're specifically interested in bugs that compromise the vault without needing root or admin access:
*   **Crypto implementation**: Weaknesses in AES-GCM, Argon2id, or random number generation.
*   **Memory leaks**: Secrets staying in the heap or RAM after Hako exits.
*   **File system attacks**: Race conditions (TOCTOU) or symlink vulnerabilities during vault saves.
*   **Import/Export**: Path traversal or unauthorized file access during data movement.

### Out of scope
We don't consider the following to be Hako vulnerabilities, as they imply the host is already compromised:
*   **Admin/Root compromise**: If an attacker can read process memory or install kernel modules, Hako cannot protect you.
*   **Physical access**: Attacker access to an unlocked, decrypted session.
*   **System-level malware**: Keyloggers or screen scrapers already running on the machine.
*   **Crashes**: Standard DoS (crashes) aren't security bugs unless they trigger a memory-leaking core dump.

## Safe harbor

We won't take legal action against researchers who act in good faith. If you follow this policy and disclose bugs responsibly, we consider your research authorized.
