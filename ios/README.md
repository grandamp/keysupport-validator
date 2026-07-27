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

**Verified statically:**

- Type-checks clean against the iOS 26.5 SDK targeting iOS 17, zero errors and
  zero warnings, under both Swift 5 and `-swift-version 6` strict concurrency.
  The latter matters: the CoreNFC delegate plus `CheckedContinuation` bridge in
  `PIVReader` is exactly the pattern strict concurrency usually rejects.
- 58 assertions over the platform-independent logic — `./Tests/run-tests.sh`.

**Not verified — still needs an iPhone:**

- **The CoreNFC transport itself.** Everything above it is proven, but
  `NFCTagReaderSession` has no macOS equivalent and cannot be exercised off
  device. See the short-read note below — that class of defect is exactly what
  is still lurking here.
- **The SwiftUI layer.** No Xcode project is committed, so a full app build has
  not been run.
- **The VSS SUCCESS path**, which needs a certificate chaining to a real Federal
  PKI trust anchor. Note this path is already proven by the shipping Android app
  against the same endpoint and policy OID.
- **The gzip path against a real card.** The YubiKey stores certificates
  uncompressed (CertInfo `0x00`), so only the unit-test fixtures cover it.
- The RSA-3072 algorithm identifier (`0x05`) is carried over from a `// let's check`
  comment in the Kotlin source. It matches SP 800-78-5, but confirm against your
  card stock. RSA-2048 and the ECC identifiers are now hardware-confirmed.

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
declares; GENERAL AUTHENTICATE sizes its `Le` from the key. `Tests/run-tests.sh`
carries regression cover for both.

**CoreNFC may well behave the same way**, which is why this is called out
rather than buried. If a scan fails with "TLV data ended unexpectedly" on a
real iPhone, this is the first thing to look at.

---

## Setting up the Xcode project

There is deliberately no `.xcodeproj` in the repo. A hand-written `project.pbxproj`
is long, opaque, and easy to get subtly wrong; Xcode's own template takes about a
minute and gives you something guaranteed valid. Steps:

1. **File → New → Project → iOS → App.**
   Product Name `KeySupportValidator`, Interface **SwiftUI**, Language **Swift**.
   Set the minimum deployment target to **iOS 17.0**.

2. **Delete** the generated `ContentView.swift` and `KeySupportValidatorApp.swift`,
   then drag in the `KeySupportValidator/App`, `KeySupportValidator/PIV`, and
   `KeySupportValidator/Network` folders from this directory. Choose
   *Create groups* and make sure the app target is checked.

3. **Signing & Capabilities → + Capability → Near Field Communication Tag Reading.**
   This writes `com.apple.developer.nfc.readersession.formats = ["TAG"]` into your
   entitlements file. `Resources/KeySupportValidator.entitlements` shows the
   expected result. **This requires a paid Apple Developer Program membership** —
   a free Apple ID cannot provision the NFC entitlement, so there is no
   zero-cost path here even for running on your own phone.

4. **Merge `Resources/Info.plist` into your target's Info.plist.** Two keys:

   - `NFCReaderUsageDescription` — the permission prompt string.
   - `com.apple.developer.nfc.readersession.iso7816.select-identifiers` —
     an array containing `A000000308000010000100`.

   The AID list is not advisory. iOS filters tags against it before your code
   ever runs; if the AID is missing, the card is simply never surfaced and the
   session times out with nothing useful to debug. **If a scan does nothing at
   all, check this first.**

5. Build to a **physical iPhone 7 or later**. There is no simulator path.

---

## What changed from the Android version, and why

| | Android | iOS |
|---|---|---|
| Tag discovery | `enableReaderMode` polls invisibly in the background | User taps a button; Apple's system sheet is mandatory and cannot be bypassed |
| Session lifetime | Unbounded | **~20s connected tag, 60s session — hard limits** |
| `61 XX` chaining | Manual `GET RESPONSE` loop | Handled by CoreNFC |
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

## Open questions for the first iPhone run

- **Does CoreNFC truncate at the requested `expectedResponseLength`?** See the
  short-read defect above. The mitigations are in place, but CoreNFC's actual
  behaviour is unconfirmed.
- Does asking for more than 256 bytes make CoreNFC emit an *extended* `Le` that
  a contactless card rejects? If so, the fallback is explicit `00 C0 00 00 00`
  GET RESPONSE looping, the way the Android reader does it.
- Does re-`SELECT`ing the applet cause trouble on any card? iOS already selects
  it from the Info.plist AID list before handing over the tag
  (`tag.initialSelectedAID`); `selectPIVApplet` re-sends it for explicitness and
  parity with Android. The YubiKey accepts it. If a card objects, drop the call.
- Is your PIV card dual-interface, and does it expose slot 9E over contactless
  without a PIN? That assumption underpins the whole app and cannot be checked
  with a contact reader.
- CoreNFC has a reported ~1694-byte ceiling on response data. The 793-byte
  object measured here fits comfortably; a larger certificate could approach it.
