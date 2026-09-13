#!/usr/bin/env bash
# install.sh - install the Tokenhush CLI from a GitHub release.
#
# Linux is served by this script plus the raw release binaries (docs/deployment.md §2);
# macOS users should prefer `brew install --cask fregie/tap/tokenhush` and
# Windows users `scoop install tokenhush`. The script downloads the release
# archive for the detected OS/arch, verifies it against the release
# `checksums.txt` (sha256) and only then installs the binary.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/fregie/tokenhush/main/install.sh | bash
#   bash install.sh --dry-run
#   bash install.sh --version 0.1.0 --dir "$HOME/.local/bin"
#
# Environment overrides:
#   TOKENHUSH_VERSION      version to install, without the leading "v"
#                          (default: latest release)
#   TOKENHUSH_INSTALL_DIR  destination directory (default: ~/.local/bin)
#   TOKENHUSH_BASE_URL     download base URL, used for mirrors/testing
#                          (default: GitHub releases; requires TOKENHUSH_VERSION
#                          or --version, since "latest" cannot be resolved there)
#
# Exit codes: 0 success, 1 runtime failure, 2 usage error.
set -euo pipefail

REPO="fregie/tokenhush"
RELEASES_BASE="https://github.com/${REPO}/releases"
BINARY="tokenhush"
DEFAULT_INSTALL_DIR="${HOME}/.local/bin"

VERSION="${TOKENHUSH_VERSION:-latest}"
INSTALL_DIR="${TOKENHUSH_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
BASE_URL="${TOKENHUSH_BASE_URL:-}"
DRY_RUN=0
TMP_DIR=""

usage() {
  sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
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
      --dry-run) DRY_RUN=1 ;;
      --version)
        [ $# -ge 2 ] || usage_error "--version requires a value"
        VERSION="$2"; shift ;;
      --dir)
        [ $# -ge 2 ] || usage_error "--dir requires a value"
        INSTALL_DIR="$2"; shift ;;
      --base-url)
        [ $# -ge 2 ] || usage_error "--base-url requires a value"
        BASE_URL="$2"; shift ;;
      -h|--help)
        usage; exit 0 ;;
      *)
        usage_error "unknown argument: $1" ;;
    esac
    shift
  done
}

detect_os() {
  local uname_s
  uname_s="$(uname -s)"
  case "$uname_s" in
    Linux)  echo "linux" ;;
    Darwin) echo "darwin" ;;
    MINGW*|MSYS*|CYGWIN*)
      die "Windows is not supported by this script; use 'scoop install tokenhush' instead" ;;
    *) die "unsupported operating system: ${uname_s}; use 'brew install --cask fregie/tap/tokenhush' on macOS or 'scoop install tokenhush' on Windows, or build from source" ;;
  esac
}

detect_arch() {
  local uname_m
  uname_m="$(uname -m)"
  case "$uname_m" in
    x86_64|amd64)   echo "amd64" ;;
    aarch64|arm64)  echo "arm64" ;;
    *) die "unsupported architecture: ${uname_m} (supported: amd64, arm64)" ;;
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
  local shell="$1" dir="$2"
  case "$shell" in
    fish) printf 'fish_add_path "%s"\n' "$dir" ;;
    *)    printf 'export PATH="%s:$PATH"\n' "$dir" ;;
  esac
}

# print_next_steps <install_dir> - run the gateway, then make it reachable;
# shared by the dry-run and install paths. Prints only; never edits rc files.
print_next_steps() {
  local dir="$1" shell rc snippet
  shell="$(detect_shell)"
  rc="$(path_rc "$shell")"
  snippet="$(path_snippet "$shell" "$dir")"

  printf '\nNext steps:\n'
  printf '  Start the gateway:   %s run\n' "$BINARY"
  printf '  Verify the install:  %s version\n' "$BINARY"
  printf '\nIf "%s" is not found, add it to your PATH (%s):\n' "$BINARY" "$shell"
  printf '  echo %s >> %s\n' "'${snippet}'" "$rc"
  printf '  # or, for this shell only:\n'
  printf '  %s\n' "$snippet"
  case ":${PATH}:" in
    *":${dir}:"*) printf 'note: %s is already on your PATH\n' "$dir" ;;
    *) printf 'note: %s is not on your PATH\n' "$dir" ;;
  esac
}

# download <url> <dest> - curl first, wget as a fallback.
download() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 15 --retry 3 -o "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$dest" "$url"
  else
    die "curl or wget is required to download release artifacts"
  fi
}

# resolve_latest_version - reads the version from the /releases/latest redirect.
resolve_latest_version() {
  command -v curl >/dev/null 2>&1 \
    || die "curl is required to resolve the latest release version; pass --version explicitly"
  local effective
  effective="$(curl -fsSLI --connect-timeout 15 -o /dev/null -w '%{url_effective}' \
    "${RELEASES_BASE}/latest")" \
    || die "failed to resolve the latest release; pass --version explicitly"
  local tag="${effective##*/}"
  case "$tag" in
    v[0-9]*) echo "${tag#v}" ;;
    *) die "could not parse a version from '${effective}'" ;;
  esac
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

# verify_checksum <archive> <checksums.txt>
verify_checksum() {
  local archive="$1" checksums="$2" expected actual name
  name="$(basename "$archive")"
  expected="$(awk -v name="$name" '$2 == name { print $1 }' "$checksums")"
  [ -n "$expected" ] || die "checksums.txt contains no entry for ${name}"
  actual="$(sha256_file "$archive")"
  [ "$actual" = "$expected" ] \
    || die "checksum mismatch for ${name}: expected ${expected}, got ${actual}"
  printf 'verified sha256 %s  %s\n' "$actual" "$name"
}

main() {
  parse_args "$@"

  local os arch
  os="$(detect_os)"
  arch="$(detect_arch)"
  VERSION="${VERSION#v}"

  if [ -z "$BASE_URL" ]; then
    if [ "$VERSION" = "latest" ]; then
      VERSION="$(resolve_latest_version)"
      BASE_URL="${RELEASES_BASE}/latest/download"
    else
      BASE_URL="${RELEASES_BASE}/download/v${VERSION}"
    fi
  else
    [ "$VERSION" != "latest" ] \
      || die "--base-url requires an explicit --version (latest cannot be resolved there)"
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
    exit 0
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
