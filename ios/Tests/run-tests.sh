#!/bin/bash
#
# Exercises the platform-independent PIV logic — BER-TLV parsing, PKCS#1 v1.5
# padding, APDU chunking arithmetic, and gzip decompression — by compiling it
# for macOS and running it natively. No device, no simulator, no card required.
#
# The CoreNFC and SwiftUI layers cannot be covered this way; those need real
# hardware. See ../README.md for what is still unverified.
#
# Usage:  ./ios/Tests/run-tests.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIV="$HERE/../KeySupportValidator/PIV"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Swift requires top-level statements to live in a file named main.swift.
cp "$HERE/PIVLogicTests.swift" "$WORK/main.swift"

# Two gzip fixtures: one with the FNAME header flag set, one without, so the
# RFC 1952 header-skipping logic is covered in both shapes.
python3 -c "
body = bytes([0x30,0x82,0x07,0xD0]) + bytes([(i*7)%251 for i in range(1000)])*2
open('$WORK/fixture_noname','wb').write(body)
open('$WORK/fixture_named','wb').write(body)
"
gzip -n -c "$WORK/fixture_noname" > "$WORK/fixture_noname.gz"   # FLG = 0x00
(cd "$WORK" && gzip -k fixture_named)                            # FLG = 0x08 (FNAME)

echo "Compiling test harness…"
swiftc -o "$WORK/testrunner" \
    "$PIV/TLV.swift" \
    "$PIV/DistinguishedName.swift" \
    "$PIV/CertificateDetails.swift" \
    "$HERE/../KeySupportValidator/App/CredentialDetails.swift" \
    "$PIV/Gzip.swift" \
    "$PIV/PIVCrypto.swift" \
    "$WORK/main.swift"

echo "Running…"
echo
# A real certificate with known validity, for the DER date parser.
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/k.pem" -nodes \
    -subj "/CN=Test Certificate" -days 365 \
    -outform DER -out "$WORK/cert.der" 2>/dev/null

TEST_CERT_DER="$WORK/cert.der" \
  "$WORK/testrunner" "$WORK/fixture_noname.gz" "$WORK/fixture_named.gz"
