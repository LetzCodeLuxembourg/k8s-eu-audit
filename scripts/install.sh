#!/usr/bin/env bash
set -euo pipefail

REPO="letzcode/k8s-eu-audit"
BINARY="k8s-eu-audit"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case $ARCH in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

VERSION="${1:-$(curl -sf "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')}"

URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}_${OS}_${ARCH}.tar.gz"

echo "Installing ${BINARY} ${VERSION} (${OS}/${ARCH}) → ${INSTALL_DIR}"
curl -sL "$URL" | tar -xz -C /tmp "${BINARY}"
install -m755 "/tmp/${BINARY}" "${INSTALL_DIR}/${BINARY}"
echo "Done. Run: ${BINARY} version"
