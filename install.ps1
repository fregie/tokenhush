#Requires -Version 5.1
<#
.SYNOPSIS
    install.ps1 - install the Tokenhush CLI from a GitHub release (Windows).

.DESCRIPTION
    The Windows counterpart to install.sh (docs/deployment.md §2). The script
    downloads the Windows zip for the detected architecture, verifies it against
    the release `checksums.txt` (sha256) and only then installs the binary into a
    per-user directory and adds that directory to your user PATH. No
    administrator rights are required, and a checksum mismatch aborts the install
    with a non-zero exit before anything is written.

    The archive name is frozen:
      tokenhush_<version>_windows_<arch>.zip
    It must stay in lockstep with the `archives.name_template` in
    .goreleaser.yaml.

    macOS users should prefer `brew install --cask fregie/tap/tokenhush` and
    Linux users should run install.sh.

.EXAMPLE
    irm https://raw.githubusercontent.com/fregie/tokenhush/main/install.ps1 | iex

    # The piped form cannot take arguments; wrap it in a script block instead:
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/fregie/tokenhush/main/install.ps1))) -DryRun

.EXAMPLE
    .\install.ps1 -Version 0.3.0 -Dir "$env:USERPROFILE\bin"

.NOTES
    Exit codes: 0 success, 1 runtime failure, 2 usage error.
#>
[CmdletBinding()]
param(
    # Version to install, without the leading "v" (default: latest release).
    [string]$Version = $env:TOKENHUSH_VERSION,
    # Destination directory (default: %LOCALAPPDATA%\Programs\tokenhush).
    [string]$Dir = $env:TOKENHUSH_INSTALL_DIR,
    # Download base URL for mirrors or testing (requires an explicit -Version).
    [string]$BaseUrl = $env:TOKENHUSH_BASE_URL,
    # Download, verify and unpack, but do not install.
    [switch]$DryRun,
    # Print this help.
    [switch]$Help
)

$ErrorActionPreference = 'Stop'

$Repo = 'fregie/tokenhush'
$Binary = 'tokenhush'
$ReleasesBase = "https://github.com/$Repo/releases"
$Usage = @'
install.ps1 - install the Tokenhush CLI from a GitHub release (Windows).

Usage:
  irm https://raw.githubusercontent.com/fregie/tokenhush/main/install.ps1 | iex
  & ([scriptblock]::Create((irm <url>))) -DryRun
  .\install.ps1 [-Version <v>] [-Dir <path>] [-BaseUrl <url>] [-DryRun]

Parameters:
  -Version   version to install, without the leading "v" (default: latest release)
  -Dir       destination directory (default: %LOCALAPPDATA%\Programs\tokenhush)
  -BaseUrl   download base URL for mirrors/testing (requires an explicit -Version)
  -DryRun    download, verify and unpack, but do not install
  -Help      print this help

Environment overrides (handy with the piped one-liner):
  TOKENHUSH_VERSION, TOKENHUSH_INSTALL_DIR, TOKENHUSH_BASE_URL

Exit codes: 0 success, 1 runtime failure, 2 usage error.
'@

# Windows PowerShell 5.1 still negotiates older TLS by default; GitHub requires 1.2+.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# %LOCALAPPDATA% is always set on Windows; fall back to the profile path and
# fail with guidance rather than a null-binding error if it is somehow missing.
function Get-LocalAppDataDir {
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { return $env:LOCALAPPDATA }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) { return (Join-Path $env:USERPROFILE 'AppData\Local') }
    Fail 'LOCALAPPDATA is not set; pass -Dir explicitly'
}

function Get-TempDir {
    if (-not [string]::IsNullOrWhiteSpace($env:TEMP)) { return $env:TEMP }
    if (-not [string]::IsNullOrWhiteSpace($env:TMP)) { return $env:TMP }
    return [System.IO.Path]::GetTempPath()
}

function Fail([string]$Message) {
    Write-Host "install.ps1: error: $Message" -ForegroundColor Red
    exit 1
}

function FailUsage([string]$Message) {
    Write-Host "install.ps1: error: $Message" -ForegroundColor Red
    Write-Host ''
    Write-Host $script:Usage
    exit 2
}

# x86 (32-bit) PowerShell on a 64-bit host reports the native architecture in
# PROCESSOR_ARCHITEW6432, so prefer that when present (also covers ARM64 hosts
# running an emulated x64 shell).
function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
    switch ($arch) {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        default { Fail "unsupported architecture: $arch (supported: amd64, arm64)" }
    }
}

# Reads the tag from the /releases/latest API response.
function Get-LatestVersion {
    $headers = @{ 'User-Agent' = 'tokenhush-install-script' }
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers -TimeoutSec 60
    } catch {
        Fail "failed to resolve the latest release ($($_.Exception.Message)); pass -Version explicitly"
    }
    $tag = $release.tag_name
    if ($tag -notmatch '^v[0-9]') { Fail "could not parse a version from tag '$tag'" }
    return $tag.Substring(1)
}

# download <url> <dest>
function Save-Download([string]$Url, [string]$Destination) {
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -TimeoutSec 60
    } catch {
        Fail "failed to download $Url ($($_.Exception.Message))"
    }
    # Best-effort: clear the mark-of-the-web so SmartScreen does not flag the binary.
    try { Unblock-File -Path $Destination } catch { }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

# verify_checksum <archive> <checksums.txt> - fail closed on a mismatch. The
# archive is never installed when its hash does not match the release manifest.
function Assert-Checksum([string]$Archive, [string]$Checksums) {
    $name = Split-Path -Leaf $Archive
    $expected = $null
    foreach ($line in Get-Content -LiteralPath $Checksums) {
        $fields = @($line -split '\s+' | Where-Object { $_ -ne '' })
        if ($fields.Length -ge 2 -and $fields[-1].TrimStart('*') -eq $name) {
            $expected = $fields[0]
            break
        }
    }
    if (-not $expected) { Fail "checksums.txt contains no entry for $name" }
    $actual = Get-Sha256 $Archive
    if ($actual -ne $expected.ToLowerInvariant()) {
        Fail "checksum mismatch for ${name}: expected $expected, got $actual"
    }
    Write-Host "verified sha256 $actual  $name"
}

# Adds <Entry> to the persistent per-user PATH when missing, and to the current
# session so the freshly installed binary resolves without a new shell.
function Add-ToUserPath([string]$Entry) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $userPath) { $userPath = '' }
    $entries = @($userPath -split ';' | Where-Object { $_ -ne '' })
    if ($entries -notcontains $Entry) {
        $trimmed = $userPath.TrimEnd(';')
        if ($trimmed -eq '') { $newPath = $Entry } else { $newPath = $trimmed + ';' + $Entry }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Host "added $Entry to your user PATH"
    } else {
        Write-Host "$Entry is already on your user PATH"
    }
    if ((@($env:Path -split ';')) -notcontains $Entry) {
        $env:Path = $env:Path.TrimEnd(';') + ';' + $Entry
    }
}

function Show-NextSteps {
    Write-Host ''
    Write-Host 'Next steps:'
    Write-Host "  Start the gateway:   $Binary run"
    Write-Host "  Verify the install:  $Binary version"
    Write-Host ''
    Write-Host "If `"$Binary`" is not found, open a new terminal so PATH picks up $Dir."
}

if ($Help) {
    Write-Host $Usage
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Version)) { $Version = 'latest' }

$arch = Get-Architecture
if ([string]::IsNullOrWhiteSpace($Dir)) { $Dir = Join-Path (Get-LocalAppDataDir) 'Programs\tokenhush' }

if ($BaseUrl) {
    if ($Version -eq 'latest') {
        FailUsage '-BaseUrl requires an explicit -Version (latest cannot be resolved there)'
    }
} elseif ($Version -eq 'latest') {
    $Version = Get-LatestVersion
}
$Version = $Version.TrimStart('v')

if ($BaseUrl) {
    $base = $BaseUrl.TrimEnd('/')
} else {
    $base = "$ReleasesBase/download/v$Version"
}

$archiveName = "tokenhush_${Version}_windows_${arch}.zip"
$archiveUrl = "$base/$archiveName"
$checksumsUrl = "$base/checksums.txt"

Write-Host "tokenhush $Version (windows/$arch)"
Write-Host "downloading $archiveUrl"

$tempDir = Join-Path (Get-TempDir) ('tokenhush-install-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    $archivePath = Join-Path $tempDir $archiveName
    $checksumsPath = Join-Path $tempDir 'checksums.txt'

    Save-Download $archiveUrl $archivePath
    Save-Download $checksumsUrl $checksumsPath
    Assert-Checksum $archivePath $checksumsPath

    $extractDir = Join-Path $tempDir 'src'
    New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDir -Force

    $match = Get-ChildItem -LiteralPath $extractDir -Recurse -Filter "$Binary.exe" | Select-Object -First 1
    if (-not $match) { Fail "the archive did not contain $Binary.exe" }
    $binaryPath = $match.FullName

    try {
        & $binaryPath version *> $null
        if ($LASTEXITCODE -ne 0) { Fail "the downloaded binary failed to run (exit $LASTEXITCODE)" }
    } catch {
        Fail "the downloaded binary failed to run ($($_.Exception.Message))"
    }

    if ($DryRun) {
        Write-Host "[dry-run] verified $archiveName; would install it to $(Join-Path $Dir "$Binary.exe")"
        Show-NextSteps
        exit 0
    }

    if (-not (Test-Path -LiteralPath $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    }
    $target = Join-Path $Dir "$Binary.exe"
    Copy-Item -LiteralPath $binaryPath -Destination $target -Force
    try { Unblock-File -Path $target } catch { }

    Write-Host "installed $Version to $target"
    Add-ToUserPath $Dir
    Show-NextSteps
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
