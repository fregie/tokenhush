#!/usr/bin/env bash
# install.sh - one-line installer for the Tokenhush CLI on Linux.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/fregie/tokenhush/main/install.sh | bash
#   bash install.sh [--version <x.y.z>] [--dir <path>] [--dry-run]
#
# The script resolves the release, downloads the matching archive, verifies its
# sha256 against the release checksums.txt and only then installs the binary.
# It never needs root and never touches the system trust store.
#
# macOS is served by Homebrew instead:
#   brew install --cask fregie/tap/tokenhush
# Windows uses install.ps1:
#   irm https://raw.githubusercontent.com/fregie/tokenhush/main/install.ps1 | iex
#
# A published release older than the minimum line is never installed by
# default; the script falls back to
# `go install github.com/fregie/tokenhush/cmd/tokenhush@main` when a Go 1.25+
# toolchain is on PATH. An explicitly requested version is always installed as
# given.
#
# Exit codes: 0 success, 1 runtime failure, 2 usage error.
set -euo pipefail

REPO="fregie/tokenhush"
RELEASES_BASE="https://github.com/${REPO}/releases"
BINARY="tokenhush"
GO_PACKAGE="github.com/fregie/tokenhush/cmd/tokenhush"
MIN_VERSION="0.5.0"
GO_MIN_VERSION="1.25"

VERSION="${TOKENHUSH_VERSION:-latest}"
INSTALL_DIR="${TOKENHUSH_INSTALL_DIR:-}"
BASE_URL="${TOKENHUSH_BASE_URL:-}"
DRY_RUN=0
TMP_DIR=""

usage() {
  cat <<'EOF'
install.sh - install the Tokenhush CLI on Linux from a GitHub release.

Usage:
  curl -fsSL https://raw.githubusercontent.com/fregie/tokenhush/main/install.sh | bash
  bash install.sh [--version <x.y.z>] [--dir <path>] [--dry-run]

Flags:
  --version <x.y.z>  install this exact release, even when it is older than the
                     current 0.5.0 line (default: the newest published release)
  --dir <path>       destination directory (default: ~/.local/bin)
  --dry-run          download, verify and unpack, but do not install
  -h, --help         print this help and exit

Environment:
  TOKENHUSH_VERSION      version to install, without the leading "v"
  TOKENHUSH_INSTALL_DIR  destination directory
  TOKENHUSH_BASE_URL     download base URL for mirrors/testing; replaces the
                         GitHub releases base and requires an explicit version

The archive is verified against the release checksums.txt (sha256) before
anything is installed. No root privileges are required.

macOS:   brew install --cask fregie/tap/tokenhush
Windows: irm https://raw.githubusercontent.com/fregie/tokenhush/main/install.ps1 | iex
EOF
}

die() {
  printf 'install.sh: error: %s\n' "$*" >&2
  exit 1
}

# TMP_DIR is global so the EXIT trap can still read it after main() returns.
cleanup() {
  if [ -n "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

usage_error() {
  printf 'install.sh: error: %s\n\n' "$*" >&2
  usage >&2
  exit 2
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --version)
        [ $# -ge 2 ] || usage_error "--version requires a value"
        [ -n "$2" ] || usage_error "--version requires a non-empty value"
        VERSION="$2"; shift ;;
      --dir)
        [ $# -ge 2 ] || usage_error "--dir requires a value"
        [ -n "$2" ] || usage_error "--dir requires a non-empty value"
        INSTALL_DIR="$2"; shift ;;
      --dry-run) DRY_RUN=1 ;;
      -h|--help)
        usage; exit 0 ;;
      *)
        usage_error "unknown argument: $1" ;;
    esac
    shift
  done
}

detect_os() {
  case "$(uname -s)" in
    Linux) printf 'linux\n' ;;
    Darwin)
      die "macOS is not supported by install.sh; use: brew install --cask fregie/tap/tokenhush" ;;
    MINGW*|MSYS*|CYGWIN*)
      die "Windows is not supported by install.sh; use: irm https://raw.githubusercontent.com/fregie/tokenhush/main/install.ps1 | iex" ;;
    *)
      die "unsupported operating system: $(uname -s) (supported: Linux)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *) die "unsupported architecture: $(uname -m) (supported: amd64, arm64)" ;;
  esac
}

# detect_shell - name of the user's login shell ($SHELL), the PATH-hint target.
detect_shell() {
  local name
  name="$(basename "${SHELL:-sh}")"
  case "$name" in
    bash|zsh|fish|ksh|mksh|dash|ash|sh) printf '%s\n' "$name" ;;
    *) printf 'sh\n' ;;
  esac
}

# path_rc <shell> - profile file that <shell> reads at startup.
path_rc() {
  case "$1" in
    zsh)  printf '~/.zshrc\n' ;;
    bash) printf '~/.bashrc\n' ;;
    fish) printf '~/.config/fish/config.fish\n' ;;
    *)    printf '~/.profile\n' ;;
  esac
}

# path_snippet <shell> <dir> - one-liner that adds <dir> to PATH in <shell>.
path_snippet() {
  case "$1" in
    fish) printf 'fish_add_path "%s"\n' "$2" ;;
    *)    printf 'export PATH="%s:$PATH"\n' "$2" ;;
  esac
}

# version_lt <a> <b> - succeeds (0) when version <a> is strictly older than
# <b>. Dotted numeric fields are compared in order and a pre-release suffix
# (for example -rc1) is ignored. Implemented with awk on purpose: `sort -V`
# is not available on all minimal Linux targets, and no external semver tool
# should be required.
version_lt() {
  awk -v a="$1" -v b="$2" '
    function split_version(v, out,   i, n, parts) {
      sub(/-.*/, "", v)
      n = split(v, parts, ".")
      for (i = 1; i <= 3; i++) {
        out[i] = (i <= n && parts[i] ~ /^[0-9]+$/) ? parts[i] + 0 : 0
      }
    }
    BEGIN {
      split_version(a, x)
      split_version(b, y)
      for (i = 1; i <= 3; i++) {
        if (x[i] < y[i]) exit 0
        if (x[i] > y[i]) exit 1
      }
      exit 1
    }'
}

# resolve_latest_version - the version from the /releases/latest redirect.
resolve_latest_version() {
  command -v curl >/dev/null 2>&1 \
    || die "curl is required to resolve the latest release; pass --version explicitly"
  local effective
  effective="$(curl -fsSLI --connect-timeout 15 --retry 3 -o /dev/null -w '%{url_effective}' \
    "${RELEASES_BASE}/latest")" \
    || die "failed to resolve the latest release; pass --version explicitly"
  local tag="${effective##*/}"
  case "$tag" in
    v[0-9]*) printf '%s\n' "${tag#v}" ;;
    *) die "could not parse a version from '${effective}'" ;;
  esac
}

# download <url> <dest> - curl first, wget as a fallback.
download() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 15 --retry 3 -o "$dest" "$url" \
      || die "failed to download ${url}"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$dest" "$url" \
      || die "failed to download ${url}"
  else
    die "curl or wget is required to download release artifacts"
  fi
}

# sha256_file <path> - portable sha256 over a file, hash only.
sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -r "$path" | awk '{print $1}'
  else
    die "no sha256 tool found (tried sha256sum, shasum, openssl)"
  fi
}

# verify_checksum <archive> <checksums.txt> - fail closed on a mismatch or a
# missing entry, before anything is installed.
verify_checksum() {
  local archive="$1" checksums="$2" expected actual name
  name="$(basename "$archive")"
  expected="$(awk -v name="$name" '
    { file = $2; sub(/^\*/, "", file); if (file == name) { print $1; exit } }' "$checksums")"
  [ -n "$expected" ] || die "checksums.txt contains no entry for ${name}"
  actual="$(sha256_file "$archive")"
  [ "$actual" = "$expected" ] \
    || die "checksum mismatch for ${name}: expected ${expected}, got ${actual}"
  printf 'verified sha256 %s  %s\n' "$actual" "$name"
}

# go_bin_dir - where `go install` drops binaries: GOBIN, or GOPATH/bin.
go_bin_dir() {
  local dir
  dir="$(go env GOBIN)"
  if [ -z "$dir" ]; then
    dir="$(go env GOPATH)/bin"
  fi
  printf '%s\n' "$dir"
}

# go_toolchain_ok - true when `go` on PATH reports GO_MIN_VERSION or newer.
go_toolchain_ok() {
  command -v go >/dev/null 2>&1 || return 1
  local output version
  output="$(go version 2>/dev/null)" || return 1
  version="$(printf '%s\n' "$output" | awk '
    { for (i = 1; i <= NF; i++) if ($i ~ /^go[0-9]/) { sub(/^go/, "", $i); print $i; exit } }')"
  [ -n "$version" ] || return 1
  ! version_lt "$version" "$GO_MIN_VERSION"
}

# install_from_source <latest> - the newest published release predates
# MIN_VERSION, so build the current main line instead of silently installing
# the old release by default.
install_from_source() {
  local latest="$1" target
  target="$(go_bin_dir)"

  printf 'the newest published release is v%s, older than the %s line\n' "$latest" "$MIN_VERSION"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run] would run: go install %s@main\n' "$GO_PACKAGE"
    printf '[dry-run] binary would be installed as %s/%s\n' "$target" "$BINARY"
    print_next_steps "$target"
    return 0
  fi

  printf 'building from source instead: go install %s@main\n' "$GO_PACKAGE"
  go install "${GO_PACKAGE}@main" \
    || die "go install failed; see the output above, or pass --version once a v${MIN_VERSION}+ release exists"
  [ -x "${target}/${BINARY}" ] || die "go install finished but ${target}/${BINARY} is missing"
  printf 'installed %s from source to %s\n' "$BINARY" "${target}/${BINARY}"
  print_next_steps "$target"
}

# print_next_steps <install_dir> - run the gateway, point a tool at it, and a
# PATH hint when <install_dir> is not on PATH. Prints only; never edits rc files.
print_next_steps() {
  local dir="$1" shell rc snippet
  printf '\nNext steps:\n'
  printf '  1. Start the gateway:   %s run              # http://127.0.0.1:8787\n' "$BINARY"
  printf '  2. Point a tool at it:  %s env claude\n' "$BINARY"
  printf '     (other tools: claude, codex, aider, cline, roo, opencode, qwen,\n'
  printf '      crush, zed, continue, openwebui, goose, openhands, kilo)\n'
  printf '     Details: https://github.com/%s/blob/main/docs/tool-setup.md\n' "$REPO"
  printf '  3. Verify the install:  %s version\n' "$BINARY"

  case ":${PATH}:" in
    *":${dir}:"*)
      printf '\n%s is already on your PATH.\n' "$dir" ;;
    *)
      shell="$(detect_shell)"
      rc="$(path_rc "$shell")"
      snippet="$(path_snippet "$shell" "$dir")"
      printf '\n%s is not on your PATH. Add it, then open a new shell:\n' "$dir"
      printf '  %s\n' "$snippet"
      printf 'For example, append that line to %s.\n' "$rc" ;;
  esac
}

main() {
  parse_args "$@"

  if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="${HOME:?HOME is not set; pass --dir explicitly}/.local/bin"
  fi

  local os arch explicit version latest
  os="$(detect_os)"
  arch="$(detect_arch)"
  VERSION="${VERSION#v}"

  explicit=0
  if [ "$VERSION" != "latest" ]; then
    explicit=1
  fi

  if [ -n "$BASE_URL" ]; then
    [ "$explicit" -eq 1 ] \
      || usage_error "TOKENHUSH_BASE_URL requires an explicit version (latest cannot be resolved there)"
    BASE_URL="${BASE_URL%/}"
  elif [ "$explicit" -eq 1 ]; then
    if version_lt "$VERSION" "$MIN_VERSION"; then
      printf 'note: installing the explicitly requested v%s (older than the %s line)\n' \
        "$VERSION" "$MIN_VERSION"
    fi
    BASE_URL="${RELEASES_BASE}/download/v${VERSION}"
  else
    latest="$(resolve_latest_version)"
    if version_lt "$latest" "$MIN_VERSION"; then
      if go_toolchain_ok; then
        install_from_source "$latest"
        return 0
      fi
      die "the newest published release is v${latest}, older than the v${MIN_VERSION} line
this script refuses to install a pre-${MIN_VERSION} release by default.

The v${MIN_VERSION} line has not been published yet. Either:
  1. install Go 1.25+ (https://go.dev/dl/) and re-run this script to build
     ${BINARY} from the main branch, or
  2. re-run with --version <x.y.z> once a v${MIN_VERSION}+ release exists."
    fi
    VERSION="$latest"
    BASE_URL="${RELEASES_BASE}/latest/download"
  fi

  local archive="tokenhush_${VERSION}_${os}_${arch}.tar.gz"
  local archive_url="${BASE_URL}/${archive}"
  local checksums_url="${BASE_URL}/checksums.txt"

  printf 'tokenhush %s (%s/%s)\n' "$VERSION" "$os" "$arch"
  printf 'downloading %s\n' "$archive_url"

  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tokenhush-install.XXXXXX")"

  download "$archive_url" "${TMP_DIR}/${archive}"
  download "$checksums_url" "${TMP_DIR}/checksums.txt"
  verify_checksum "${TMP_DIR}/${archive}" "${TMP_DIR}/checksums.txt"

  mkdir -p "${TMP_DIR}/src"
  tar -xzf "${TMP_DIR}/${archive}" -C "${TMP_DIR}/src" "$BINARY"
  "${TMP_DIR}/src/${BINARY}" version >/dev/null \
    || die "the downloaded binary failed to run"

  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run] verified %s; would install it to %s/%s\n' "$archive" "$INSTALL_DIR" "$BINARY"
    print_next_steps "$INSTALL_DIR"
    return 0
  fi

  if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR" || die "cannot create ${INSTALL_DIR}"
  fi
  [ -w "$INSTALL_DIR" ] || die "${INSTALL_DIR} is not writable"

  install -m 0755 "${TMP_DIR}/src/${BINARY}" "${INSTALL_DIR}/${BINARY}"
  printf 'installed %s to %s/%s\n' "$VERSION" "$INSTALL_DIR" "$BINARY"
  print_next_steps "$INSTALL_DIR"
}

main "$@"
