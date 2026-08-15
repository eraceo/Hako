# scripts/install.ps1
$ErrorActionPreference = "Stop"

Write-Host "Installing Hako for Windows..." -ForegroundColor Cyan

# Determine project root
$ScriptDir = $PSScriptRoot
$ProjectRoot = Split-Path -Parent $ScriptDir
Push-Location $ProjectRoot

# Check for Go
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Error "Go is not installed. Please install Go 1.25+ first."
}

# Ensure dependencies are tidy
Write-Host "Downloading dependencies..."
go mod tidy

# Cleanup previous local build if exists to prevent locked file errors
if (Test-Path "hako.exe") {
    Remove-Item -Path "hako.exe" -Force
}

# Build using the same secure flags as the Makefile
Write-Host "Building Hako..."
$Version = $(git describe --tags --always --dirty 2>$null)
if ([string]::IsNullOrWhiteSpace($Version)) { $Version = "dev" }

$Commit = $(git rev-parse HEAD 2>$null)
if ([string]::IsNullOrWhiteSpace($Commit)) { $Commit = "unknown" }

# Robust UTC ISO 8601 Date formatting
$Date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$LdFlags = "-s -w -X github.com/eraceo/Hako/internal/version.Version=$Version -X github.com/eraceo/Hako/internal/version.Commit=$Commit -X github.com/eraceo/Hako/internal/version.Date=$Date"

# -trimpath prevents leaking the developer's exact computer paths in panic stack traces
go build -trimpath -ldflags "$LdFlags" -o hako.exe ./cmd/hako

if (-not (Test-Path "hako.exe")) {
    Write-Error "Build failed."
}

# Install directory setup
$InstallDir = Join-Path $env:LOCALAPPDATA "hako\bin"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$DestPath = Join-Path $InstallDir "hako.exe"

# Handle Windows File Locks on the destination binary
if (Test-Path $DestPath) {
    try {
        Remove-Item -Path $DestPath -Force -ErrorAction Stop
    } catch {
        Write-Error "Cannot overwrite $DestPath. Is Hako currently running? Close it and try again."
    }
}

# Move binary
Move-Item -Path "hako.exe" -Destination $DestPath -Force

Write-Host "Hako securely installed to $DestPath" -ForegroundColor Green

# Add to User PATH if not exists cleanly
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
$Paths = $UserPath -split ";"
if ($InstallDir -notin $Paths) {
    Write-Host "Adding $InstallDir to your User PATH..."
    # Ensure no double semicolons
    $NewPath = ($Paths + $InstallDir) -match "." -join ";"
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
    
    # Update current session PATH so it works immediately
    $env:PATH = ($env:PATH -split ";" + $InstallDir) -match "." -join ";"
    
    Write-Host "PATH updated successfully. You may need to restart your terminal for some applications." -ForegroundColor Yellow
} else {
    Write-Host "Directory is already in your PATH."
}

Pop-Location
Write-Host "Installation Complete! Type 'hako --help' to get started." -ForegroundColor Green