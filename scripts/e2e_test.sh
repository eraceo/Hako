#!/bin/bash
set -e

# Define paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
BINARY_PATH="$BUILD_DIR/hako"

# DrvFS (/mnt/c/...) forces 0777 permissions and triggers Hako's security block.
TEST_DIR="/tmp/hako_e2e_temp_$$" 
VAULT_FILE="$TEST_DIR/vault.bin"
CONFIG_FILE="$TEST_DIR/config.yaml"
MASTER_PASSWORD="test-master-password-123"

# Ensure clean state
echo "Cleaning up previous test runs..."
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
chmod 700 "$TEST_DIR"
touch "$CONFIG_FILE"

# Clean up safely on exit or error
trap 'rm -rf "$TEST_DIR"' EXIT

# Build the application
echo "Building Hako for E2E tests..."
cd "$PROJECT_ROOT"
mkdir -p "$BUILD_DIR"
go build -o "$BINARY_PATH" ./cmd/hako
cd - > /dev/null

if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Binary not found at $BINARY_PATH"
    exit 1
fi

# Helper function to run hako and check output
run_hako() {
    local input_string=""
    local expected_pattern=""
    local should_fail=false
    
    # Parse args manually
    local args=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            --input)
                input_string="$2"
                shift 2
                ;;
            --expect)
                expected_pattern="$2"
                shift 2
                ;;
            --should-fail)
                should_fail=true
                shift
                ;;
            *)
                args+=("$1")
                shift
                ;;
        esac
    done

    export HAKO_VAULT_FILE="$VAULT_FILE"
    
    # AND append standard isolating flags
    export HAKO_KEYFILE_PATH=""
    args+=("--vault=$VAULT_FILE" "--config=$CONFIG_FILE" "--keyfile=none")
    
    echo "Running: hako ${args[*]}"
    
    local input_file="$TEST_DIR/input.txt"
    local output_file="$TEST_DIR/stdout.txt"
    local error_file="$TEST_DIR/stderr.txt"
    
    if [ -n "$input_string" ]; then
        printf "%b" "$input_string" > "$input_file"
    else
        touch "$input_file"
    fi

    set +e
    "$BINARY_PATH" "${args[@]}" < "$input_file" > "$output_file" 2> "$error_file"
    local exit_code=$?
    set -e

    local stdout=$(cat "$output_file")
    local stderr=$(cat "$error_file")

    if [ "$should_fail" = true ]; then
        if [ $exit_code -eq 0 ]; then
            echo "Error: Command expected to fail but succeeded."
            echo "Stdout: $stdout"
            echo "Stderr: $stderr"
            exit 1
        fi
    else
        if [ $exit_code -ne 0 ]; then
            echo "Error: Command failed with exit code $exit_code"
            echo "Stdout: $stdout"
            echo "Stderr: $stderr"
            exit 1
        fi
    fi

    if [ -n "$expected_pattern" ]; then
        if ! echo "$stdout $stderr" | grep -qE "$expected_pattern"; then
            echo "Error: Output did not match pattern '$expected_pattern'"
            echo "Stdout: $stdout"
            echo "Stderr: $stderr"
            exit 1
        fi
    fi
}

# 1. Init
echo -e "\n--- Test: Init ---"
# init requires password and confirmation
init_input="$MASTER_PASSWORD\n$MASTER_PASSWORD\n"
run_hako "init" --input "$init_input" --expect "Vault initialized successfully"

if [ ! -f "$VAULT_FILE" ]; then
    echo "Error: Vault file was not created at $VAULT_FILE"
    exit 1
fi

# 2. Add Entry
echo -e "\n--- Test: Add Entry ---"
add_input="$MASTER_PASSWORD\n"
run_hako "add" "github" "--user" "testuser" "--url" "https://github.com" "--notes" "My_GitHub" "--tags" "dev,work" "--generate" --input "$add_input" --expect "Generated password:"

# 3. Get Entry
echo -e "\n--- Test: Get Entry ---"
get_input="$MASTER_PASSWORD\n"
run_hako "get" "github" --input "$get_input" --expect "Username.*testuser"

# 4. Edit Entry
echo -e "\n--- Test: Edit Entry ---"
# Edit github entry to change username
edit_input="$MASTER_PASSWORD\nnewuser\n\n\n\n\n"
run_hako "edit" "github" --input "$edit_input" --expect "updated successfully"

# 4b. Verify Edit
echo -e "\n--- Test: Verify Edit ---"
run_hako "get" "github" --input "$get_input" --expect "Username.*newuser"

# 5. List Entries
echo -e "\n--- Test: List Entries ---"
run_hako "list" --input "$get_input" --expect "github"

# 6. Search Entries
echo -e "\n--- Test: Search Entries ---"
run_hako "search" "git" --input "$get_input" --expect "github"

# 7. Remove Entry
echo -e "\n--- Test: Remove Entry ---"
# remove asks for master password THEN confirmation
remove_input="$MASTER_PASSWORD\ny\n"
run_hako "remove" "github" --input "$remove_input" --expect "removed successfully"

# 8. Verify Removal
echo -e "\n--- Test: Verify Removal ---"
run_hako "get" "github" --input "$get_input" --should-fail --expect "not found"

echo -e "\n======================================"
echo "All E2E tests passed successfully!"
echo "======================================"