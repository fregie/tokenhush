# install.ps1 - one-line installer for the Tokenhush CLI on Windows.
#
# Usage:
#   irm https://raw.githubusercontent.com/fregie/tokenhush/main/install.ps1 | iex
#
#   # The piped form cannot take arguments; wrap the script block to pass flags:
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/fregie/tokenhush/main/install.ps1))) -DryRun
#
#   .\install.ps1 [-Version <x.y.z>] [-Dir <path>] [-BaseUrl <url>] [-DryRun] [-Help]
#
# The script downloads the Windows zip for the detected architecture, verifies
# it against the release checksums.txt (sha256) and only then installs
# tokenhush.exe into a per-user directory and adds that directory to the user
# PATH. It never needs administrator rights and never touches the system trust
# store.
#
# The archive name is frozen: tokenhush_<version>_windows_<arch>.zip. It must
# stay in lockstep with .goreleaser.yaml.
#
# Until the v0.5.0 release wave ships, the newest published release is the
# older v0.4 line. Installing the current v0.5 line therefore falls back to
# `go install github.com/fregie/tokenhush/cmd/tokenhush@main` when a Go 1.25+
# toolchain is on PATH; an explicitly requested version is always installed as
# given.
#
# The script is safe under `irm | iex`: it uses parameters and $env: only, and
# -Help prints usage without side effects.
#
# Exit codes: 0 success, 1 runtime failure, 2 usage error.

[CmdletBinding()]
param(
    # Version to install, without the leading "v" (default: newest release).
    [string]$Version = $env:TOKENHUSH_VERSION,
    # Destination directory (default: %LOCALAPPDATA%\Programs\tokenhush).
    [string]$Dir = $env:TOKENHUSH_INSTALL_DIR,
    # Download base URL for mirrors/testing (requires an explicit -Version).
    [string]$BaseUrl = $env:TOKENHUSH_BASE_URL,
    # Download, verify and unpack, but do not install.
    [switch]$DryRun,
    # Print this help.
    [switch]$Help
)

$Usage = @'
install.ps1 - install the Tokenhush CLI on Windows from a GitHub release.

Usage:
  irm https://raw.githubusercontent.com/fregie/tokenhush/main/install.ps1 | iex

  # The piped form cannot take arguments; wrap the script block to pass flags:
  & ([scriptblock]::Create((irm https://raw.githubusercontent.com/fregie/tokenhush/main/install.ps1))) -DryRun

  .\install.ps1 [-Version <x.y.z>] [-Dir <path>] [-BaseUrl <url>] [-DryRun] [-Help]

Parameters:
  -Version <x.y.z>  install this exact release, even when it is older than the
                    current 0.5.0 line (default: the newest published release)
  -Dir <path>       destination directory (default: %LOCALAPPDATA%\Programs\tokenhush)
  -BaseUrl <url>    download base URL for mirrors/testing; replaces the GitHub
                    releases base and requires an explicit -Version
  -DryRun           download, verify and unpack, but do not install
  -Help             print this help and exit

Environment:
  TOKENHUSH_VERSION      same as -Version (without the leading "v")
  TOKENHUSH_INSTALL_DIR  same as -Dir
  TOKENHUSH_BASE_URL     same as -BaseUrl

The archive is verified against the release checksums.txt (sha256) before
anything is installed. No administrator rights are required.

macOS: brew install --cask fregie/tap/tokenhush
Linux: curl -fsSL https://raw.githubusercontent.com/fregie/tokenhush/main/install.sh | bash
'@

if ($Help) {
    Write-Host $Usage
    exit 0
}

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host 'install.ps1: error: PowerShell 5.1 or newer is required' -ForegroundColor Red
    exit 1
}

$ErrorActionPreference = 'Stop'

$Repo = 'fregie/tokenhush'
$Binary = 'tokenhush'
$ReleasesBase = "https://github.com/$Repo/releases"
$GoPackage = 'github.com/fregie/tokenhush/cmd/tokenhush'
$MinVersion = '0.5.0'
$GoMinVersion = '1.25'

# Windows PowerShell 5.1 still negotiates older TLS by default; GitHub requires 1.2+.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

function Fail([string]$Message) {
    Write-Host "install.ps1: error: $Message" -ForegroundColor Red
    exit 1
}

function FailUsage([string]$Message) {
    Write-Host "install.ps1: error: $Message" -ForegroundColor Red
    Write-Host ''
    Write-Host $Usage
    exit 2
}

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

# Reads the version from the /releases/latest redirect (no API rate limit).
function Get-LatestVersion {
    $url = "$ReleasesBase/latest"
    $location = $null
    $request = [System.Net.HttpWebRequest]::Create($url)
    $request.AllowAutoRedirect = $false
    $request.Method = 'HEAD'
    $request.UserAgent = 'tokenhush-install-script'
    $request.Timeout = 60000
    try {
        $response = $request.GetResponse()
        $location = $response.Headers['Location']
        $response.Close()
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $location = $_.Exception.Response.Headers['Location']
            $_.Exception.Response.Close()
        } else {
            Fail "failed to resolve the latest release ($($_.Exception.Message)); pass -Version explicitly"
        }
    } catch {
        Fail "failed to resolve the latest release ($($_.Exception.Message)); pass -Version explicitly"
    }
    if ([string]::IsNullOrWhiteSpace($location)) {
        Fail "failed to resolve the latest release (no redirect from $url); pass -Version explicitly"
    }
    $tag = ($location.Trim() -split '/')[-1]
    if ($tag -notmatch '^v[0-9]') { Fail "could not parse a version from '$location'" }
    return $tag.Substring(1)
}

# Save-Download <url> <dest> - Invoke-WebRequest, then clear the mark-of-the-web
# so SmartScreen is less likely to block the downloaded binary.
function Save-Download([string]$Url, [string]$Destination) {
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -TimeoutSec 60
    } catch {
        Fail "failed to download $Url ($($_.Exception.Message))"
    }
    try { Unblock-File -Path $Destination } catch { }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

# Assert-Checksum <archive> <checksums.txt> - fail closed on a mismatch or a
# missing entry, before anything is installed.
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

# ConvertTo-NumericVersion <text> - major.minor.patch as [version], ignoring a
# leading "v" and any pre-release suffix. Returns $null when unparseable.
function ConvertTo-NumericVersion([string]$Text) {
    $match = [regex]::Match($Text, '(\d+)(?:\.(\d+))?(?:\.(\d+))?')
    if (-not $match.Success) { return $null }
    $minor = 0
    $patch = 0
    if ($match.Groups[2].Success) { $minor = [int]$match.Groups[2].Value }
    if ($match.Groups[3].Success) { $patch = [int]$match.Groups[3].Value }
    return [version]"$([int]$match.Groups[1].Value).$minor.$patch"
}

# Test-VersionOlder <version> <minimum> - $true when <version> predates <minimum>.
function Test-VersionOlder([string]$Version, [string]$Minimum) {
    $left = ConvertTo-NumericVersion $Version
    $right = ConvertTo-NumericVersion $Minimum
    if ($null -eq $left -or $null -eq $right) { return $false }
    return $left -lt $right
}

# Get-GoVersion - the version reported by `go` on PATH, or $null.
function Get-GoVersion {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) { return $null }
    $output = & go version 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $output) { return $null }
    $match = [regex]::Match([string]$output, 'go(\d+(?:\.\d+){0,2})')
    if (-not $match.Success) { return $null }
    return $match.Groups[1].Value
}

# Get-GoBinDir - where `go install` drops binaries: GOBIN, or GOPATH\bin.
function Get-GoBinDir {
    $gobin = (& go env GOBIN) 2>$null
    if (-not [string]::IsNullOrWhiteSpace($gobin)) { return $gobin.Trim() }
    $gopath = (& go env GOPATH) 2>$null
    return (Join-Path $gopath.Trim() 'bin')
}

# Install-FromSource <latest> - the newest published release predates
# MinVersion, so build the current main line instead of silently installing the
# old release by default.
function Install-FromSource([string]$Latest) {
    $targetDir = Get-GoBinDir

    Write-Host "the newest published release is v$Latest, older than the $MinVersion line"
    if ($DryRun) {
        Write-Host "[dry-run] would run: go install $GoPackage@main"
        Write-Host "[dry-run] binary would be installed as $(Join-Path $targetDir "$Binary.exe")"
        Show-NextSteps $targetDir
        return
    }

    Write-Host "building from source instead: go install $GoPackage@main"
    & go install "$GoPackage@main"
    if ($LASTEXITCODE -ne 0) {
        Fail "go install failed; see the output above, or pass -Version once a v$MinVersion+ release exists"
    }
    $target = Join-Path $targetDir "$Binary.exe"
    if (-not (Test-Path -LiteralPath $target)) { Fail "go install finished but $target is missing" }
    Write-Host "installed $Binary from source to $target"
    Show-NextSteps $targetDir
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

function Show-NextSteps([string]$InstallDir) {
    Write-Host ''
    Write-Host 'Next steps:'
    Write-Host "  1. Start the gateway:   $Binary run              # http://127.0.0.1:8787"
    Write-Host "  2. Point a tool at it:  $Binary env claude"
    Write-Host '     (other tools: claude, codex, aider, cline, roo, opencode, qwen,'
    Write-Host '      crush, zed, continue, openwebui, goose, openhands, kilo)'
    Write-Host "     Details: https://github.com/$Repo/blob/main/docs/tool-setup.md"
    Write-Host "  3. Verify the install:  $Binary version"
    Write-Host ''
    Write-Host "If `"$Binary`" is not found, open a new terminal so PATH picks up $InstallDir."
}

if ([string]::IsNullOrWhiteSpace($Version)) { $Version = 'latest' }
$explicit = $Version -ne 'latest'

$arch = Get-Architecture
if ([string]::IsNullOrWhiteSpace($Dir)) { $Dir = Join-Path (Get-LocalAppDataDir) 'Programs\tokenhush' }

if ($BaseUrl) {
    if (-not $explicit) {
        FailUsage '-BaseUrl requires an explicit -Version (latest cannot be resolved there)'
    }
    $Version = $Version.TrimStart('v')
    $base = $BaseUrl.TrimEnd('/')
} elseif ($explicit) {
    $Version = $Version.TrimStart('v')
    if (Test-VersionOlder $Version $MinVersion) {
        Write-Host "note: installing the explicitly requested v$Version (older than the $MinVersion line)"
    }
    $base = "$ReleasesBase/download/v$Version"
} else {
    $latest = Get-LatestVersion
    if (Test-VersionOlder $latest $MinVersion) {
        $goVersion = Get-GoVersion
        if ($goVersion -and -not (Test-VersionOlder $goVersion $GoMinVersion)) {
            Install-FromSource $latest
            exit 0
        }
        Fail @"
the newest published release is v$latest, older than the v$MinVersion line
this script refuses to install a pre-$MinVersion release by default.

The v$MinVersion line has not been published yet. Either:
  1. install Go 1.25+ (https://go.dev/dl/) and re-run this script to build
     $Binary from the main branch, or
  2. re-run with -Version <x.y.z> once a v$MinVersion+ release exists.
"@
    }
    $Version = $latest
    $base = "$ReleasesBase/latest/download"
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
    try { Unblock-File -Path $binaryPath } catch { }

    try {
        & $binaryPath version *> $null
        if ($LASTEXITCODE -ne 0) { Fail "the downloaded binary failed to run (exit $LASTEXITCODE)" }
    } catch {
        Fail "the downloaded binary failed to run ($($_.Exception.Message))"
    }

    if ($DryRun) {
        Write-Host "[dry-run] verified $archiveName; would install it to $(Join-Path $Dir "$Binary.exe")"
        Show-NextSteps $Dir
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
    Show-NextSteps $Dir
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
