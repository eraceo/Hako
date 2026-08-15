# Hako

![Hako Logo](.github/assets/Hako.png)

Hako is a fast, local-first password manager for the terminal. It’s built to be secure by default, using Argon2id for key derivation and AES-256-GCM for encryption. It also uses OS-level memory locking to ensure your secrets never leak into swap space.

### Key features
- **Strong crypto**: Uses Argon2id and AES-256-GCM (AEAD) out of the box.
- **Memory locking**: Employs `mlock()` and VirtualLock to keep sensitive buffers in RAM.
- **Atomic storage**: A custom, zero-allocation binary format that prevents file corruption.
- **Two-factor**: Support for keyfiles via HKDF domain separation.
- **Audit tool**: Find weak or reused passwords with the built-in scanner.

## Installation

### Requirements
- **Go 1.24+**
- **Clipboard helper** (for `--clip` support): `wl-copy`/`xclip` (Linux), `pbcopy` (macOS), or `clip.exe` (Windows).

### Build & Install
```bash
git clone https://github.com/eraceo/Hako.git
cd Hako
make build
sudo make install
```

---

## Usage

### 1. Initialize
```bash
hako init           # Standard vault
hako init --keyfile # Enhanced security (Recommended)
```

### 2. Basic commands
```bash
hako add github           # Interactive add
hako get github --clip    # Copy password to clipboard
hako search github        # Search by name, user, or URL
hako list                 # Show all entries
hako edit github --user x # Update an entry
hako rm github            # Delete an entry
```

### 3. Generate passwords
```bash
hako generate             # Random 16 chars
hako generate --memorable # Dictionary passphrase
```

---

## Configuration
Settings are stored in `~/.config/hako/config.yaml`. You can set default paths for your vault and keyfile, tweak Argon2 difficulty, or change the clipboard timeout.

To override settings on the fly:
```bash
hako list --vault /usb/vault.bin --keyfile none
```

---

## Security best practices
*   **The Master Password**: This is your primary defense. Make it long and unique.
*   **Physical 2FA**: If using a keyfile, keep it on a separate, encrypted USB drive.
*   **File Permissions**: Ensure your vault directory is only readable by your user (`chmod 700`).

---

## Contributing
We welcome improvements to security, performance, and cross-platform support. Please run `make check` before submitting a PR. For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License
MIT. See [LICENSE](LICENSE).
