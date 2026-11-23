#!/bin/bash
set -eu
cd "$(dirname "$0")/.."
app="target/mac/debloatR.app"
bin="$app/Contents/MacOS"
mkdir -p "$bin"
export MACOSX_DEPLOYMENT_TARGET=13.0
for pair in 'arm64 aarch64' 'x86_64 x86_64'; do
  read -r arch rustarch <<< "$pair"
  target="$rustarch-apple-darwin"
  rustup target add "$target"
  cargo build --release --locked --target "$target"
  swiftc -parse-as-library -O -target "$arch-apple-macos13.0" macos/App.swift -o "target/mac/ui-$arch"
done
lipo -create target/mac/ui-{arm64,x86_64} -output "$bin/debloatR"
lipo -create target/{aarch64,x86_64}-apple-darwin/release/debloatR -output "$bin/scanner"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>debloatR</string>
<key>CFBundleIdentifier</key><string>com.ibrahim9876q.debloatr</string>
<key>CFBundleName</key><string>debloatR</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.2.1</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
</dict></plist>
PLIST
codesign --force --sign - "$bin/scanner"
codesign --force --sign - "$app"
"$bin/scanner" --once | python3 -c 'import sys,json; s=json.load(sys.stdin); assert s["total"]>0 and any(r["bytes"] for r in s["rows"])'
ditto -c -k --keepParent "$app" target/mac/debloatR-macOS.zip
