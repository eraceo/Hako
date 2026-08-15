$ErrorActionPreference = "Stop"

# Define paths
$ScriptDir = $PSScriptRoot
$ProjectRoot = Split-Path -Parent $ScriptDir
$BuildDir = Join-Path $ProjectRoot "build"
$BinaryPath = Join-Path $BuildDir "hako.exe"
$TestDir = Join-Path $ProjectRoot "test_e2e_temp"
$VaultFile = Join-Path $TestDir "vault.bin"
$ConfigFile = Join-Path $TestDir "config.yaml"
$MasterPassword = "Test-Master-Password-123!@#"

# Ensure clean state
Write-Host "Cleaning up previous test runs..."
if (Test-Path $TestDir) {
    Remove-Item -Path $TestDir -Recurse -Force
}
New-Item -ItemType Directory -Path $TestDir | Out-Null
New-Item -ItemType File -Path $ConfigFile | Out-Null

# Build the application
Write-Host "Building Hako for E2E tests..."
Push-Location $ProjectRoot
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}
go build -o $BinaryPath ./cmd/hako
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed with exit code $LASTEXITCODE"
}
Pop-Location

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found at $BinaryPath"
}

# Helper function to run hako and check output
function Run-Hako {
    param (
        [string[]]$HakoArgs,
        [string]$InputString,
        [string]$ExpectedOutputPattern,
        [bool]$ShouldFail = $false
    )

    $env:HAKO_VAULT_FILE = $VaultFile
    
    $env:HAKO_KEYFILE_PATH = ""
    
    # Put flags after the command.
    $CmdArgs = $HakoArgs + @("--vault=$VaultFile", "--config=$ConfigFile", "--keyfile=none")
    
    Write-Host "Running: hako $($CmdArgs -join ' ')"
    
    $InputFile = Join-Path $TestDir "input.txt"
    $OutputFile = Join-Path $TestDir "stdout.txt"
    $ErrorFile = Join-Path $TestDir "stderr.txt"
    
    if ($InputString) {
        # Write input to file with ASCII encoding to prevent BOM or UTF-16 issues in Go standard input
        $InputString | Out-File -FilePath $InputFile -Encoding ascii -NoNewline
    } else {
        # Create empty file
        New-Item -Path $InputFile -ItemType File -Force | Out-Null
    }

    $Process = Start-Process -FilePath $BinaryPath -ArgumentList $CmdArgs -RedirectStandardInput $InputFile -RedirectStandardOutput $OutputFile -RedirectStandardError $ErrorFile -PassThru -NoNewWindow -Wait

    $ExitCode = $Process.ExitCode
    $StdOut = Get-Content -Path $OutputFile -Raw
    $StdErr = Get-Content -Path $ErrorFile -Raw

    if ($ShouldFail) {
        if ($ExitCode -eq 0) {
            Write-Error "Command expected to fail but succeeded.`nStdout: $StdOut`nStderr: $StdErr"
        }
    } else {
        if ($ExitCode -ne 0) {
            Write-Error "Command failed with exit code $ExitCode`nStdout: $StdOut`nStderr: $StdErr"
        }
    }

    if ($ExpectedOutputPattern) {
        if (($StdOut -notmatch $ExpectedOutputPattern) -and ($StdErr -notmatch $ExpectedOutputPattern)) {
            Write-Error "Output did not match pattern '$ExpectedOutputPattern'.`nStdout: $StdOut`nStderr: $StdErr"
        }
    }
    
    return $StdOut
}

try {
    # 1. Init
    Write-Host "`n--- Test: Init ---"
    # init requires password and confirmation
    $InitInput = "$MasterPassword`n$MasterPassword`n"
    Run-Hako -HakoArgs "init" -InputString $InitInput -ExpectedOutputPattern "Vault initialized successfully"

    if (-not (Test-Path $VaultFile)) {
        Write-Error "Vault file was not created at $VaultFile"
    }

    # 2. Add Entry
    Write-Host "`n--- Test: Add Entry ---"
    # hako add github ...
    $AddInput = "$MasterPassword`n"
    Run-Hako -HakoArgs "add", "github", "--user", "testuser", "--url", "https://github.com", "--notes", "My_GitHub", "--tags", "dev,work", "--generate" -InputString $AddInput -ExpectedOutputPattern "Generated password:"

    # 3. Get Entry
    Write-Host "`n--- Test: Get Entry ---"
    $GetInput = "$MasterPassword`n"
    Run-Hako -HakoArgs "get", "github" -InputString $GetInput -ExpectedOutputPattern "Username.*testuser"

    # 4. Edit Entry
    Write-Host "`n--- Test: Edit Entry ---"
    # Edit github entry to change username
    # Interactive input: MasterPassword -> New Username (changed) -> New Password (enter to skip) -> New URL (enter to skip) -> New Notes (enter to skip) -> New Tags (enter to skip)
    $EditInput = "$MasterPassword`nnewuser`n`n`n`n`n"
    Run-Hako -HakoArgs "edit", "github" -InputString $EditInput -ExpectedOutputPattern "updated successfully"

    # 4b. Verify Edit
    Write-Host "`n--- Test: Verify Edit ---"
    Run-Hako -HakoArgs "get", "github" -InputString $GetInput -ExpectedOutputPattern "Username.*newuser"

    # 5. List Entries
    Write-Host "`n--- Test: List Entries ---"
    Run-Hako -HakoArgs "list" -InputString $GetInput -ExpectedOutputPattern "github"

    # 5. Search Entries
    Write-Host "`n--- Test: Search Entries ---"
    Run-Hako -HakoArgs "search", "git" -InputString $GetInput -ExpectedOutputPattern "github"

    # 6. Remove Entry
    Write-Host "`n--- Test: Remove Entry ---"
    # remove asks for master password THEN confirmation
    $RemoveInput = "$MasterPassword`ny`n"
    Run-Hako -HakoArgs "rm", "github" -InputString $RemoveInput -ExpectedOutputPattern "removed successfully"

    # 7. Verify Removal
    Write-Host "`n--- Test: Verify Removal ---"
    Run-Hako -HakoArgs "get", "github" -InputString $GetInput -ShouldFail $true -ExpectedOutputPattern "not found"

    Write-Host "`nAll E2E tests passed successfully!"
} catch {
    Write-Error "Test failed: $_"
} finally {
    # Cleanup
    if (Test-Path $TestDir) {
        Remove-Item -Path $TestDir -Recurse -Force
    }
}