# KeySupport Validator — iOS

A Swift/SwiftUI port of the Android app. Reads the PIV Card Authentication
certificate over NFC, proves the card holds the matching private key, and
validates the credential against the KeySupport Validation Service.

This is a working translation of `app/src/main/java/net/keysupport/cardread/`,
not a sketch. Every APDU, algorithm identifier, and TLV shape is carried over
from the Kotlin implementation.

---

## Status — what is and is not verified

**Verified against real card hardware** (YubiKey 5C Nano, firmware 5.7.4, PIV
applet over USB/CCID, via `Tools/piv-probe`):

| Key in slot 9E | algRef | PoP template | APDU path | Signature | Result |
|---|---|---|---|---|---|
| RSA-2048 | `0x07` | 266 bytes | chained, 250 + 16 | 256 bytes | **PoP verified** |
| ECC P-256 | `0x11` | 38 bytes | single APDU | 72 bytes, X9.62 | **PoP verified** |

That covers applet SELECT, the GET DATA certificate read, TLV unwrapping,
X.509 parsing, PKCS#1 v1.5 construction, `CLA 0x10` command chaining, and
signature verification — against real silicon, on both the chaining and
single-APDU branches.

The VSS client was exercised too: request encoding, endpoint reachability,
JSON decoding, and the failure path all work. A self-signed test certificate
is correctly rejected with *"unable to find valid certification path to
requested target"*.

**Verified as a built app:**

- Builds clean for the iOS Simulator in both Debug and Release
  (`** BUILD SUCCEEDED **`, Xcode 26.6) — a full compile, link and bundle, not
  just a type-check.
- Runs on the simulator. The `.unsupported` state renders correctly with the
  Scan button disabled, which is right: `NFCTagReaderSession.readingAvailable`
  is false there. The success and failure screens were inspected via the DEBUG
  preview hook below and match the Android palette.
- Type-checks clean against the iOS 26.5 SDK targeting iOS 17, zero errors and
  zero warnings, under both Swift 5 and `-swift-version 6` strict concurrency.
  The latter matters: the CoreNFC delegate plus `CheckedContinuation` bridge in
  `PIVReader` is exactly the pattern strict concurrency usually rejects.
- 58 assertions over the platform-independent logic — `./Tests/run-tests.sh`.

**Verified end to end over NFC on a real card**, read on an iPhone 13:

- 1652-byte certificate object retrieved across six GET RESPONSE rounds
- validity dates read straight out of the DER, since iOS exposes no API for them
- gzip decompressed on device — this card stores its certificate compressed
- X.509 parsed, RSA-2048 key detected
- Proof of Possession chained 250 + 16 and **verified**
- VSS returned **SUCCESS** against a real Federal PKI trust anchor

The card is dual-interface and serves slot 9E over contactless without a PIN,
which is the assumption the entire NFC-only design rests on.

**Still not verified:**

- **RSA-3072 (`0x05`)**, carried over from a `// let's check` comment in the
  Kotlin source. It matches SP 800-78-5 but no card on hand uses it.
  RSA-2048 (`0x07`) and ECC P-256 (`0x11`) are hardware-confirmed.
- **ECC P-384 (`0x14`)** — correct by construction, never exercised by a card.
- **Revoked and expired credentials.** Only the valid path has run against real
  Federal PKI. The failure branches are covered by unit tests and by a
  self-signed certificate that VSS correctly rejects.
**VSS returns no certificate path for at least some valid credentials.**
Observed consistently across two independent scans of the same production card:
`validationResult.result` is SUCCESS while `x509CertificatePath` is absent or
empty. The Certificate Path card and the "Issued By" detail row both derive from
it, so both are simply omitted. That is handled gracefully, but it means the
trust chain is not always available to show — worth confirming with the service
owner whether the field is optional for this validation policy, or whether the
response shape differs from what `VSSResponse` decodes.

### The short-read defect, and why it matters for the NFC port

Hardware testing found a real bug that no amount of static checking would have
caught. A `GET DATA` asking for `Le = 256` returned **exactly 256 bytes with
SW 90 00** for a certificate object that declares 793. The status word says
success; the buffer is silently truncated. The same thing then happened to the
RSA-2048 GENERAL AUTHENTICATE response, which needs ~264 bytes.

The cause is that a smart card stack may transparently walk `61 XX` GET RESPONSE
chains and *still* stop at whatever `Le` the caller asked for. Measured on
CryptoTokenKit:

| `Le` requested | Bytes returned |
|---|---|
| 256 | 256 — truncated, SW 90 00 |
| 1024 | 793 — complete |
| 65536 (extended) | 793 — complete |

Both call sites are fixed. Certificate reads detect the short buffer via
`TLV.declaredTotalLength` and re-read with the length the object itself
declares. GENERAL AUTHENTICATE no longer computes a length at all: it sends
`Le = 0x00` and lets the chain deliver the remainder. `Tests/run-tests.sh`
carries regression cover.

**CoreNFC turned out to behave differently, and worse.** It does not walk the
`61 XX` chain *at all* — the card answers `SW 6100` and CoreNFC simply hands
back 256 bytes. Same silent truncation, different route. `PIVReader.send` now
drives GET RESPONSE explicitly, which covers both stacks.

---

## Building

`KeySupportValidator.xcodeproj` is committed — just open it. It is generated from
`project.yml` by [XcodeGen](https://github.com/yonaskolb/XcodeGen); regenerate
after adding files rather than editing the pbxproj by hand:

```
brew install xcodegen
cd ios && xcodegen generate
```

Simulator build, no signing required:

```
xcodebuild -project ios/KeySupportValidator.xcodeproj -scheme KeySupportValidator \
  -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 17' build
```

### Running on a device

Set your team in Xcode under Signing & Capabilities (`project.yml` deliberately
leaves `DEVELOPMENT_TEAM` unset), then add **+ Capability → Near Field
Communication Tag Reading**. That writes the entitlement already shown in
`Resources/KeySupportValidator.entitlements`.

**This requires a paid Apple Developer Program membership.** A free personal team
cannot provision the NFC entitlement — its profiles are 7-day and carry no NFC
entitlement at all — so there is no zero-cost path onto a device, even your own.
Signing will fail with a capability error until the membership is active.

The app needs a physical **iPhone 7 or later**; the simulator has no NFC.

### Info.plist

`Resources/Info.plist` is a complete app plist. The two keys that matter:

- `NFCReaderUsageDescription` — the permission prompt string.
- `com.apple.developer.nfc.readersession.iso7816.select-identifiers` —
  an array containing `A000000308000010000100`.

The AID list is not advisory. iOS filters tags against it before your code ever
runs; if the AID is missing, the card is never surfaced and the session times out
with nothing useful to debug. **If a scan does nothing at all, check this first.**

### Inspecting UI states without a card

Every interesting screen normally requires tapping a real card to a real iPhone.
DEBUG builds accept a forced starting state so the UI can be reviewed on a
simulator:

```
xcrun simctl install booted <path>/KeySupportValidator.app
SIMCTL_CHILD_KSV_PREVIEW_STATE=success \
  xcrun simctl launch booted net.keysupport.cardread
```

Values: `idle`, `unsupported`, `reading`, `verifying`, `validating`, `success`,
`revoked`, `expired`, `popfailed`. The hook is `#if DEBUG` only and is absent
from Release binaries.

---

## What changed from the Android version, and why

| | Android | iOS |
|---|---|---|
| Tag discovery | `enableReaderMode` polls invisibly in the background | User taps a button; Apple's system sheet is mandatory and cannot be bypassed |
| Session lifetime | Unbounded | **~20s connected tag, 60s session — hard limits** |
| `61 XX` chaining | Manual `GET RESPONSE` loop | **Also manual** — CoreNFC does *not* chain |
| `6C XX` wrong-`Le` | Manual reissue | Still manual — CoreNFC does *not* do this |
| Extended APDUs | `isoDep.isExtendedLengthApduSupported` | **No equivalent API exists** |
| Cert parsing | `CertificateFactory` | `SecCertificateCreateWithData` + `SecCertificateCopyKey` |
| Gzip | `GZIPInputStream` | **No gzip in Foundation** — hand-rolled |
| NFC toggle | User-disableable, app shows a settings prompt | Not user-facing; only "device doesn't support it" |

Three of those forced real design changes:

**1. Network validation moved outside the NFC session.** `MainActivity.kt:95-161`
reads the cert, runs PoP, *and* calls VSS while still holding the tag. With a 20
second cap and a 15 second network timeout, that would intermittently kill scans
on slow connections. Here `PIVReader` does card work only and returns; the VSS
call happens in `ScanViewModel` after `session.invalidate()`. This is the most
important structural difference in the port.

**2. GENERAL AUTHENTICATE always chains.** The Kotlin code branches three ways on
payload size and card capability. iOS gives no way to ask whether a card supports
extended-length APDUs, so that branch is unportable. Command chaining with
`CLA 0x10` is required of every PIV card by SP 800-73, so `sendGeneralAuthenticate`
always chains at 250-byte boundaries instead of gambling. An RSA-2048 template is
266 bytes and splits 250 + 16; a P-256 template is 38 bytes and goes out whole.

**3. Gzip is implemented by hand.** Apple's `COMPRESSION_ZLIB` is *raw DEFLATE*
with no container, so `Gzip.swift` strips the RFC 1952 header and trailer and
feeds the bare stream to the Compression framework. It also reads the CertInfo
byte (tag `0x71`, bit 0) rather than relying only on magic-byte sniffing as the
Kotlin does — closer to what SP 800-73 actually specifies.

---

## File map

```
KeySupportValidator/
  App/
    KeySupportValidatorApp.swift   @main entry point
    ContentView.swift              SwiftUI UI, mirrors the Compose screen
    ScanViewModel.swift            State machine; owns the card→network ordering
  PIV/
    PIVReader.swift                CoreNFC session, APDUs, chaining  ← the hard part
    PIVCrypto.swift                Cert parsing, PoP challenge, signature verification
    TLV.swift                      BER-TLV reader/writer
    Gzip.swift                     RFC 1952 header stripping + raw DEFLATE
  Network/
    VSSService.swift               URLSession + Codable client
  Resources/
    Info.plist                     NFC usage string + PIV AID  ← required
    KeySupportValidator.entitlements
Tests/
  PIVLogicTests.swift              58 assertions over the pure logic
  run-tests.sh                     Compiles for macOS and runs them
Tools/
  piv-probe/
    main.swift                     Same logic, CryptoTokenKit transport
    build-and-run.sh               Builds, ad-hoc signs, runs against a reader
```

## Testing on a Mac

`Tools/piv-probe` runs the PIV logic against a real card over USB/CCID. It links
`TLV.swift`, `PIVCrypto.swift`, `Gzip.swift` and `VSSService.swift` verbatim from
the app and reimplements only the transport, so a green run exercises the same
code the iPhone will:

```
./ios/Tools/piv-probe/build-and-run.sh              # card operations only
./ios/Tools/piv-probe/build-and-run.sh --validate   # also submit to VSS
```

Any CCID reader works. A YubiKey with the PIV applet is the cheapest option if
you don't have a reader — provision slot 9E and it behaves like a PIV card:

```
ykman piv keys generate -a rsa2048 --pin-policy never --touch-policy never 9e pub.pem
ykman piv certificates generate -s "CN=PoP Test" 9e pub.pem
```

`ykman piv reset` returns the PIV applet to factory defaults. It does not touch
FIDO2, so a YubiKey used for SSH is unaffected. Use `-a eccp256` for the
single-APDU branch; RSA-2048 is the one that forces command chaining.

Two things that will waste your time otherwise:

- `TKSmartCardSlotManager.default` returns nil for an unsigned command-line
  tool. `build-and-run.sh` ad-hoc signs with `com.apple.security.smartcard`.
- CryptoTokenKit's `send` returns `(sw, response)` — not `(response, sw)`.

## What the first iPhone run answered

Every question this section used to pose has been settled against a production
PIV card on an iPhone 13. Recorded here because several answers
contradict the documentation:

- **Does CoreNFC walk `61 XX` GET RESPONSE chains? No.** This is the important
  one. A `GET DATA` for a 1652-byte object returned 256 bytes with `SW 6100` and
  stopped. Nothing surfaces the truncation — the caller receives a short buffer
  and an apparently fine status word, and it fails later as a TLV parse error.
  The Android `while` loop is required, not optional. `iPhone-App.md` claimed the
  opposite and has been corrected.
- **Do not compute `Le` for GENERAL AUTHENTICATE.** Asking for an exact length
  earns `SW 6282` when it overshoots — a *warning*, with a perfectly valid
  signature attached, that a strict `90 00` check throws away. Pass
  `expectedResponseLength: 256` (CoreNFC's `Le = 0x00`) and let the GET RESPONSE
  loop collect the rest. Works unchanged across RSA and ECC.
- **Is the card dual-interface, serving slot 9E over contactless without a PIN?
  Yes.** The premise of the whole app holds.
- **Does re-`SELECT`ing the applet cause trouble? No.** Both the YubiKey and the
  production card accept it.
- **Is the certificate gzip-compressed on real cards? Yes** — CertInfo bit 0 set.
  The YubiKey stores its certificate uncompressed, so only a real card exercises
  `Gzip.swift`.
- CoreNFC's reported ~1694-byte response ceiling was never approached, because
  GET RESPONSE delivers in 256-byte instalments that are accumulated here rather
  than in one buffer.
