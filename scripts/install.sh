#!/bin/sh
set -e

REPO="letzcode/k8s-eu-audit"
BINARY="k8s-eu-audit"
INSTALL_DIR="/usr/local/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RESET='\033[0m'

echo ""
echo "${CYAN}  k8s-eu-audit installer${RESET}"
echo "  Kubernetes compliance for NIS2 & DORA"
echo ""

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux)  OS="linux" ;;
  darwin) OS="darwin" ;;
  mingw*|msys*|cygwin*) OS="windows" ;;
  *)
    echo "${RED}  Error: Unsupported OS: $OS${RESET}"
    exit 1
    ;;
esac

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)
    echo "${RED}  Error: Unsupported architecture: $ARCH${RESET}"
    exit 1
    ;;
esac

echo "  Detected: ${OS}/${ARCH}"

# Get latest release version from GitHub API
echo "  Fetching latest release..."
VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' \
  | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

if [ -z "$VERSION" ]; then
  echo "${RED}  Error: Could not fetch latest version from GitHub.${RESET}"
  echo "  Check: https://github.com/${REPO}/releases"
  exit 1
fi

echo "  Latest version: ${VERSION}"

# Build download URL
# Expects release assets named: k8s-eu-audit_linux_amd64.tar.gz
ASSET="${BINARY}_${OS}_${ARCH}.tar.gz"
if [ "$OS" = "windows" ]; then
  ASSET="${BINARY}_${OS}_${ARCH}.zip"
fi

URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"

# Download to temp dir
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "  Downloading ${ASSET}..."
curl -fsSL "$URL" -o "${TMP}/${ASSET}"

# Extract
echo "  Extracting..."
if [ "$OS" = "windows" ]; then
  unzip -q "${TMP}/${ASSET}" -d "$TMP"
else
  tar -xzf "${TMP}/${ASSET}" -C "$TMP"
fi

# Install binary
BINARY_PATH="${TMP}/${BINARY}"
if [ "$OS" = "windows" ]; then
  BINARY_PATH="${TMP}/${BINARY}.exe"
fi

if [ ! -f "$BINARY_PATH" ]; then
  echo "${RED}  Error: Binary not found in archive.${RESET}"
  exit 1
fi

chmod +x "$BINARY_PATH"

# Try to install to /usr/local/bin, fall back to ~/.local/bin
if [ -w "$INSTALL_DIR" ]; then
  mv "$BINARY_PATH" "${INSTALL_DIR}/${BINARY}"
else
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
  mv "$BINARY_PATH" "${INSTALL_DIR}/${BINARY}"
  echo "  Note: Installed to ${INSTALL_DIR} (no write access to /usr/local/bin)"
  echo "  Make sure ${INSTALL_DIR} is in your PATH."
fi

echo ""
echo "${GREEN}  ✓ k8s-eu-audit ${VERSION} installed to ${INSTALL_DIR}/${BINARY}${RESET}"
echo ""
echo "  Get started:"
echo "    k8s-eu-audit scan --framework nis2"
echo "    k8s-eu-audit scan --framework nis2 -o report.html"
echo ""
echo "  Docs: https://github.com/${REPO}"
echo ""