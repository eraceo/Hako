#!/bin/bash

# Hako Installation Script (Builds from source)

# Strict mode for better bash safety
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BINARY_NAME="hako"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="$HOME/.config/hako"
DATA_DIR="$HOME/.local/share/hako"
MIN_GO_VERSION="1.25"   

# Functions
print_info() { echo -e "${BLUE}ℹ${NC} $1"; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }

prevent_root_execution() {
    # Check if script is run directly as root/sudo
    if [ "${EUID:-$(id -u)}" -eq 0 ]; then
        print_error "Please do not run this script as root or with sudo."
        print_info "The script will request sudo automatically ONLY when copying the binary to $INSTALL_DIR."
        print_info "Running as root would wrongly install configurations to /root instead of your user home ($HOME)."
        exit 1
    fi
}

check_dependencies() {
    print_info "Checking dependencies..."
    
    # Check Make
    if ! command -v make >/dev/null 2>&1; then
        print_error "'make' is not installed. Please install make (build-essential / xcode-select) first."
        exit 1
    fi

    # Check Go
    if ! command -v go >/dev/null 2>&1; then
        print_error "Go is not installed. Please install Go $MIN_GO_VERSION or later."
        exit 1
    fi
    
    # Portable Go version check (works on GNU and BSD/macOS)
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    
    # Simple portable version comparison using awk
    IS_VALID_VERSION=$(awk -v ver="$GO_VERSION" -v min="$MIN_GO_VERSION" 'BEGIN {
        split(ver, v, ".");
        split(min, m, ".");
        if (v[1] > m[1] || (v[1] == m[1] && v[2] >= m[2])) print 1;
        else print 0;
    }')
    
    if [ "$IS_VALID_VERSION" -eq 0 ]; then
        print_error "Go version $GO_VERSION is too old. Please install Go $MIN_GO_VERSION or later."
        exit 1
    fi
    
    print_success "Go $GO_VERSION found"
    print_success "Make found"
    
    # Check clipboard tools
    CLIPBOARD_TOOLS=("wl-copy" "xclip" "xsel" "pbcopy")
    FOUND_CLIPBOARD=false
    
    for tool in "${CLIPBOARD_TOOLS[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            print_success "Clipboard tool found: $tool"
            FOUND_CLIPBOARD=true
            break
        fi
    done
    
    if [ "$FOUND_CLIPBOARD" = false ]; then
        print_warning "No clipboard tool found. Auto-clipboard features will not work."
        print_info "  Linux (Wayland): sudo apt install wl-clipboard"
        print_info "  Linux (X11): sudo apt install xclip"
        print_info "  macOS: built-in (pbcopy)"
    fi
}

build_application() {
    print_info "Building Hako..."
    
    # Call the Makefile to ensure we get the proper secure flags and version injection
    make build
    
    if [ ! -f "build/$BINARY_NAME" ]; then
        print_error "Build failed: build directory or binary missing."
        exit 1
    fi
    
    print_success "Build completed"
}

install_binary() {
    print_info "Installing Hako to $INSTALL_DIR..."
    
    # Ensure install dir exists (important for clean macOS installations)
    if [ ! -d "$INSTALL_DIR" ]; then
        print_info "Creating $INSTALL_DIR directory (sudo prompt)..."
        sudo mkdir -p "$INSTALL_DIR"
    fi
    
    # Using 'install -m 755' handles atomic file copy + permission setting safely
    if [ ! -w "$INSTALL_DIR" ]; then
        print_info "Administrator privileges required for installation in $INSTALL_DIR (sudo prompt)"
        sudo install -m 755 "build/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    else
        install -m 755 "build/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    fi
    
    print_success "Hako installed to $INSTALL_DIR/$BINARY_NAME"
}

setup_directories() {
    print_info "Setting up directories..."
    
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    
    mkdir -p "$DATA_DIR"
    chmod 700 "$DATA_DIR"
    
    if [ ! -f "$CONFIG_DIR/config.yaml" ] && [ -f "config.example.yaml" ]; then
        cp config.example.yaml "$CONFIG_DIR/config.yaml"
        chmod 600 "$CONFIG_DIR/config.yaml"
        print_success "Example configuration copied to $CONFIG_DIR/config.yaml"
    fi
}

setup_shell_completion() {
    print_info "Setting up shell completion..."
    SHELL_NAME=$(basename "${SHELL:-bash}")
    
    case "$SHELL_NAME" in
        bash)
            COMPLETION_DIR="/etc/bash_completion.d"
            # Some macOS Homebrew setups use this path:
            if [ -d "/usr/local/etc/bash_completion.d" ]; then
                COMPLETION_DIR="/usr/local/etc/bash_completion.d"
            elif [ -d "/opt/homebrew/etc/bash_completion.d" ]; then
                COMPLETION_DIR="/opt/homebrew/etc/bash_completion.d"
            fi

            if [ -d "$COMPLETION_DIR" ]; then
                if [ ! -w "$COMPLETION_DIR" ]; then
                    # Added '|| print_warning' to prevent set -e pipefail from crashing the script if sudo is cancelled
                    "build/$BINARY_NAME" completion bash | sudo tee "$COMPLETION_DIR/$BINARY_NAME" > /dev/null || print_warning "Skipped global bash completion (sudo failed/cancelled)."
                else
                    "build/$BINARY_NAME" completion bash > "$COMPLETION_DIR/$BINARY_NAME"
                fi
                print_success "Bash completion setup attempted in $COMPLETION_DIR"
            else
                print_info "Run manually: sudo $BINARY_NAME completion bash > /etc/bash_completion.d/$BINARY_NAME"
            fi
            ;;
        zsh)
            # macOS Support: Add Homebrew Apple Silicon & Intel paths to the search list
            ZSH_DIRS=(
                "/opt/homebrew/share/zsh/site-functions"
                "/usr/local/share/zsh/site-functions"
                "/usr/share/zsh/site-functions"
            )
            INSTALLED_ZSH=false
            
            for dir in "${ZSH_DIRS[@]}"; do
                if [ -d "$dir" ]; then
                    if [ ! -w "$dir" ]; then
                        # System Integrity Protection (macOS) might block sudo writes to /usr/share.
                        if "build/$BINARY_NAME" completion zsh | sudo tee "$dir/_$BINARY_NAME" > /dev/null 2>/dev/null; then
                            print_success "Zsh completion installed to $dir"
                            INSTALLED_ZSH=true
                            break
                        fi
                    else
                        "build/$BINARY_NAME" completion zsh > "$dir/_$BINARY_NAME"
                        print_success "Zsh completion installed to $dir"
                        INSTALLED_ZSH=true
                        break
                    fi
                fi
            done
            
            if [ "$INSTALLED_ZSH" = false ]; then
                # Safe fallback to user directory if macOS SIP blocks everything else
                USER_ZSH_DIR="$HOME/.zsh/completions"
                mkdir -p "$USER_ZSH_DIR"
                "build/$BINARY_NAME" completion zsh > "$USER_ZSH_DIR/_$BINARY_NAME"
                print_success "Zsh completion installed to $USER_ZSH_DIR"
                print_warning "Add 'fpath=($USER_ZSH_DIR \$fpath)' to your ~/.zshrc before 'compinit' to enable it."
            fi
            ;;
        fish)
            FISH_DIR="$HOME/.config/fish/completions"
            mkdir -p "$FISH_DIR"
            "build/$BINARY_NAME" completion fish > "$FISH_DIR/$BINARY_NAME.fish"
            print_success "Fish completion installed"
            ;;
        *)
            print_info "Run: $BINARY_NAME completion [bash|zsh|fish|powershell] for manual setup"
            ;;
    esac
}

run_tests() {
    print_info "Running security tests..."
    if ! make test-unit; then
        print_error "Tests failed. Aborting installation."
        exit 1
    fi
    print_success "All tests passed"
}

main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════╗"
    echo "║            Hako Installer            ║"
    echo "║     Secure CLI Password Manager      ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    
    if [ ! -f "go.mod" ] || [ ! -d "cmd/hako" ]; then
        print_error "Please run this script from the root of the cloned Hako repository"
        exit 1
    fi
    
    prevent_root_execution
    check_dependencies
    run_tests
    build_application
    install_binary
    setup_directories
    setup_shell_completion
    
    echo
    print_success "Hako installation completed successfully!"
    echo
    print_info "Next steps:"
    echo "  1. Initialize your vault: hako init --keyfile"
    echo "  2. Add a password:        hako add example --generate"
    echo "  3. Get a password:        hako get example --clip"
    echo
}

main "$@"