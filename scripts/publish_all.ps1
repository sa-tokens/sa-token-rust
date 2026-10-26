#Requires -Version 5.1
<#
.SYNOPSIS
  Publish all sa-token-rust crates to crates.io (Windows 10 / PowerShell 5.1+).

.DESCRIPTION
  Same order and quality gate as scripts/publish_all.sh.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\publish_all.ps1

.NOTES
  Optional environment variables:
    SLEEP_SECONDS   seconds to wait after each successful publish (default 5)
    VERIFY          1 = run fmt/clippy/test before publish (default 1); 0 = skip
    SKIP_PUBLISHED  1 = skip crates already on crates.io (default 1); 0 = fail
#>
$ErrorActionPreference = "Stop"

$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$SleepSeconds = 5
if ($env:SLEEP_SECONDS) { $SleepSeconds = [int]$env:SLEEP_SECONDS }
$Verify = if ($env:VERIFY) { $env:VERIFY } else { "1" }
$SkipPublished = if ($env:SKIP_PUBLISHED) { $env:SKIP_PUBLISHED } else { "1" }

# tonic-full-example 的 build.rs 依赖 protoc。Windows 上若装在默认位置，这里补上。
if (-not $env:PROTOC) {
    $localProtoc = Join-Path $env:LOCALAPPDATA "protoc\bin\protoc.exe"
    if (Test-Path $localProtoc) {
        $env:PROTOC = $localProtoc
        $env:Path = "$(Split-Path $localProtoc -Parent);$env:Path"
    }
}

function Invoke-CargoChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Step,
        [Parameter(Mandatory = $true)]
        [string[]]$CargoArgs
    )

    # PowerShell 5.1 turns native stderr into a terminating error when
    # ErrorActionPreference is Stop. cargo writes progress to stderr.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & cargo @CargoArgs
        if ($LASTEXITCODE -ne 0) {
            throw "$Step failed (exit $LASTEXITCODE)"
        }
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Publish-Crate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Manifest
    )

    # crates.io 稀疏索引经常比上传慢。依赖包会报 failed to select a version，需要重试。
    $maxAttempts = 10
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        Write-Host "Publishing $Manifest (attempt $attempt/$maxAttempts)..."
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $output = & cargo publish --manifest-path $Manifest 2>&1 |
                ForEach-Object { $_.ToString() } |
                Out-String
            $code = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $prev
        }

        if ($output) { Write-Host $output.TrimEnd() }

        if ($code -eq 0) {
            Write-Host "Waiting ${SleepSeconds}s for crates.io index to update..."
            Start-Sleep -Seconds $SleepSeconds
            return
        }

        $already = $output -like "*already exists on crates.io index*" -or $output -like "*already uploaded*"
        if ($SkipPublished -eq "1" -and $already) {
            Write-Host "Skip published crate: $Manifest"
            return
        }

        $indexLag = $output -like "*failed to select a version*" -or $output -like "*candidate versions found which didn't match*"
        if ($indexLag -and $attempt -lt $maxAttempts) {
            $wait = [Math]::Min(20 * $attempt, 90)
            Write-Host "crates.io index not ready, retry in ${wait}s..."
            Start-Sleep -Seconds $wait
            continue
        }

        throw "Publish failed: $Manifest"
    }
}

if ($Verify -eq "1") {
    Write-Host "Running pre-publish quality gate..."
    $manifest = Join-Path $WorkspaceRoot "Cargo.toml"

    Write-Host "  [1/4] cargo fmt --check"
    Invoke-CargoChecked -Step "cargo fmt --check" -CargoArgs @(
        "fmt", "--all", "--manifest-path", $manifest, "--", "--check"
    )

    Write-Host "  [2/4] cargo clippy -D warnings"
    Invoke-CargoChecked -Step "cargo clippy" -CargoArgs @(
        "clippy", "--workspace", "--all-targets", "--manifest-path", $manifest, "--",
        "-D", "warnings",
        "-A", "clippy::unwrap_used",
        "-A", "clippy::expect_used",
        "-A", "clippy::panic",
        "-A", "clippy::indexing_slicing",
        "-A", "clippy::unwrap_in_result",
        "-A", "missing_docs",
        "-A", "unreachable_pub",
        "-A", "missing_debug_implementations",
        "-A", "unused_qualifications"
    )

    Write-Host "  [3/4] cargo test --workspace"
    Invoke-CargoChecked -Step "cargo test" -CargoArgs @(
        "test", "--workspace", "--manifest-path", $manifest
    )

    if (Get-Command cargo-deny -ErrorAction SilentlyContinue) {
        Write-Host "  [extra] cargo deny check"
        Invoke-CargoChecked -Step "cargo deny check" -CargoArgs @(
            "deny", "--manifest-path", $manifest, "check"
        )
    } else {
        Write-Host "  [extra] cargo-deny not installed, skipping (install: cargo install cargo-deny --locked)"
    }

    Write-Host "Quality gate passed."
}

# Publish order: foundations, versioned plugins, then facades and the root package.
$crates = @(
    "sa-token-adapter\Cargo.toml",
    "sa-token-storage-memory\Cargo.toml",
    "sa-token-storage-redis\Cargo.toml",
    "sa-token-core\Cargo.toml",
    "sa-token-macro\Cargo.toml",
    "sa-token-storage-database\Cargo.toml",
    "sa-token-plugin-common\Cargo.toml",
    "sa-token-plugin-axum\Cargo.toml",
    "sa-token-plugin-poem\Cargo.toml",
    "sa-token-plugin-tide\Cargo.toml",
    "sa-token-plugin-warp\Cargo.toml",
    "sa-token-plugin-actix-web-v4\Cargo.toml",
    "sa-token-plugin-actix-web-v5\Cargo.toml",
    "sa-token-plugin-actix-web\Cargo.toml",
    "sa-token-plugin-rocket-v05\Cargo.toml",
    "sa-token-plugin-rocket\Cargo.toml",
    "sa-token-plugin-salvo-v079\Cargo.toml",
    "sa-token-plugin-salvo\Cargo.toml",
    "sa-token-plugin-gotham-v074\Cargo.toml",
    "sa-token-plugin-gotham\Cargo.toml",
    "sa-token-plugin-ntex-v212\Cargo.toml",
    "sa-token-plugin-ntex\Cargo.toml",
    "sa-token-plugin-tonic\Cargo.toml",
    "Cargo.toml"
)

foreach ($rel in $crates) {
    Publish-Crate -Manifest (Join-Path $WorkspaceRoot $rel)
}

Write-Host "All crates published."
