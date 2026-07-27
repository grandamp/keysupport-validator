#!/bin/bash
#
# Builds and runs the macOS PIV probe against a card in an attached USB/CCID
# reader (including a YubiKey with the PIV applet enabled).
#
# The probe links the *same* TLV.swift, PIVCrypto.swift, and Gzip.swift the iOS
# app uses. Only the transport differs — CryptoTokenKit here, CoreNFC there — so
# a green run proves the APDU sequences, TLV parsing, gzip handling, PKCS#1
# construction and the Proof of Possession round trip all work against real
# hardware. macOS has no NFC API, so the contactless path still needs an iPhone.
#
# Usage:
#   ./ios/Tools/piv-probe/build-and-run.sh              # card operations only
#   ./ios/Tools/piv-probe/build-and-run.sh --validate   # also submit to VSS
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$HERE/../../KeySupportValidator"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Building…"
swiftc -o "$WORK/piv-probe" \
    "$APP/PIV/TLV.swift" \
    "$APP/PIV/Gzip.swift" \
    "$APP/PIV/PIVCrypto.swift" \
    "$APP/Network/VSSService.swift" \
    "$HERE/main.swift"

# TKSmartCardSlotManager.default returns nil for an unsigned command-line tool.
# An ad-hoc signature carrying the smartcard entitlement is enough to get a slot
# manager; without this the probe reports "No smart card slot manager".
cat > "$WORK/sc.entitlements" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.smartcard</key>
	<true/>
</dict>
</plist>
PLIST

codesign -s - --entitlements "$WORK/sc.entitlements" -f "$WORK/piv-probe" 2>/dev/null

echo
"$WORK/piv-probe" "$@"
