#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${TARGET:-x86_64-unknown-linux-musl}"
BINARY_NAME="ja4finger"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT_DIR/Cargo.toml" | head -n1)"

if [[ -z "$VERSION" ]]; then
  echo "failed to determine version from Cargo.toml" >&2
  exit 1
fi

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required to install the musl target" >&2
  exit 1
fi

if ! rustup target list --installed | grep -Fx "$TARGET" >/dev/null 2>&1; then
  echo "installing Rust target: $TARGET"
  rustup target add "$TARGET"
fi

echo "building release binary for $TARGET"
cargo build --release --target "$TARGET"

BIN_PATH="$ROOT_DIR/target/$TARGET/release/$BINARY_NAME"
if [[ ! -x "$BIN_PATH" ]]; then
  echo "expected binary not found: $BIN_PATH" >&2
  exit 1
fi

DIST_DIR="$ROOT_DIR/dist"
PACKAGE_BASENAME="${BINARY_NAME}-v${VERSION}-${TARGET}"
PACKAGE_DIR="$DIST_DIR/$PACKAGE_BASENAME"
ARCHIVE_PATH="$DIST_DIR/${PACKAGE_BASENAME}.tar.gz"
SHA256_PATH="$DIST_DIR/${PACKAGE_BASENAME}.sha256"

rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"

cp "$BIN_PATH" "$PACKAGE_DIR/$BINARY_NAME"
cp "$ROOT_DIR/README.md" "$PACKAGE_DIR/README.md"

cat >"$PACKAGE_DIR/BUILD-INFO.txt" <<EOF
binary=$BINARY_NAME
version=$VERSION
target=$TARGET
source=$(basename "$ROOT_DIR")
EOF

tar -C "$DIST_DIR" -czf "$ARCHIVE_PATH" "$PACKAGE_BASENAME"
(
  cd "$DIST_DIR"
  sha256sum "$(basename "$ARCHIVE_PATH")" >"$SHA256_PATH"
)

echo
echo "package ready:"
echo "  directory: $PACKAGE_DIR"
echo "  archive:   $ARCHIVE_PATH"
echo "  sha256:    $SHA256_PATH"
echo
echo "binary info:"
file "$PACKAGE_DIR/$BINARY_NAME"

if ldd "$PACKAGE_DIR/$BINARY_NAME" >/tmp/ja4finger-ldd.$$ 2>&1; then
  cat /tmp/ja4finger-ldd.$$
else
  cat /tmp/ja4finger-ldd.$$
fi
rm -f /tmp/ja4finger-ldd.$$
