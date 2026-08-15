# Hako quick start

Get Hako running in a few minutes. For the full manual, see the [README.md](README.md).

## Installation

```bash
git clone https://github.com/eraceo/Hako.git
cd Hako
make build
sudo make install
```

## The basics

### 1. Initialize your vault
You'll be prompted for a master password. 

```bash
hako init           # Standard setup
hako init --keyfile # Recommended: Uses a keyfile for two-factor auth
```

### 2. Add and get passwords
```bash
# Add an entry with a generated password
hako add github --user dev --generate

# Copy a password to your clipboard (auto-clears in 15s)
hako get github --clip

# View an entry's details
hako get github
```

### 3. Search and manage
```bash
hako list           # List everything
hako search github  # Find an entry
hako edit github    # Change username, URL, or tags
hako rm github      # Delete an entry
```

---

## Generating passwords
You can generate secure passwords on the fly without saving them to the vault.

```bash
hako generate             # Random 16 characters
hako generate --memorable # Easy-to-remember passphrase
hako generate --clip      # Generate and copy to clipboard
```

---

## Configuration
Settings live in `~/.config/hako/config.yaml`. 

You can adjust the Argon2 difficulty here. If Hako feels slow when unlocking, try lowering `iterations` or `memory_kib`. If you want more security and have the RAM to spare, turn them up.

```yaml
vault_path: "~/.local/share/hako/vault.bin"
clipboard:
  timeout: 15
```

---

## Security reminders
*   **Don't lose your keyfile**: If you used `--keyfile` during init, you need that file to unlock your vault. Keep a backup on a separate USB drive.
*   **Watch your history**: Commands like `hako get --show` print your password to the screen. Be careful if someone is looking over your shoulder or if you're recording your terminal.
*   **Exporting data**: The `export` command produces **plaintext**. Use it with caution.

---

## Common issues

### "no clipboard tool available"
Install a clipboard manager for your environment:
*   **Wayland**: `wl-clipboard`
*   **X11**: `xclip` or `xsel`
*   **macOS/Windows**: Works out of the box.

### "failed to lock memory"
Hako locks its memory to prevent secrets from being swapped to disk. If this fails, your system limit is too low. You can check it with `ulimit -l`. 

On Linux, edit `/etc/security/limits.conf` and add (replace `*` with your username for better security):
```text
* soft memlock 262144
* hard memlock 262144
```
*Note: A limit of 256 MiB (262144 KB) is more than enough for Hako and protects your system from memory exhaustion. Avoid using `unlimited` for stability reasons.*
