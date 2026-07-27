# KeySupport Validator — iOS

A Swift/SwiftUI port of the Android app. Reads the PIV Card Authentication
certificate over NFC, proves the card holds the matching private key, and
validates the credential against the KeySupport Validation Service.

This is a working translation of `app/src/main/java/net/keysupport/cardread/`,
not a sketch. Every APDU, algorithm identifier, and TLV shape is carried over
from the Kotlin implementation.

---

## Status — what is and is not verified

**Verified here:**

- Type-checks clean against the iOS 26.5 SDK targeting iOS 17, with zero errors
  and zero warnings.
- Also clean under `-swift-version 6` strict concurrency. This matters: the
  CoreNFC delegate plus `CheckedContinuation` bridge in `PIVReader` is exactly
  the pattern strict concurrency usually rejects.
- 50 assertions pass over the platform-independent logic — BER-TLV encode/decode
  across every length-form boundary, sibling-tag skipping, the exact PKCS#1 v1.5
  byte layout for 2048- and 3072-bit keys, the APDU chunking arithmetic, and
  gzip round trips with and without the FNAME header flag. Run `./Tests/run-tests.sh`.

**Not verified — needs your hardware:**

- **This has never touched a real card.** The NFC path cannot be exercised
  without a physical iPhone and a dual-interface PIV card. The simulator has no
  NFC at all.
- No Xcode project is committed (see below), so a full app build has not been run.
- The RSA-3072 algorithm identifier (`0x05`) is carried over from a `// let's check`
  comment in the Kotlin source. It matches SP 800-78-5, but confirm against your
  card stock before trusting it. RSA-2048 (`0x07`) and the ECC identifiers are solid.

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
  PIVLogicTests.swift              50 assertions over the pure logic
  run-tests.sh                     Compiles for macOS and runs them
```

## Open questions for the first hardware run

- Does re-`SELECT`ing the applet cause trouble on any card? iOS already selects
  it from the Info.plist AID list before handing over the tag
  (`tag.initialSelectedAID`); `selectPIVApplet` re-sends it for explicitness and
  parity with Android. If a card objects, that call can simply be dropped.
- Do any cards in your test set reject the `Le` byte on GET DATA? The fallback
  path exists but has never fired.
- CoreNFC has a reported ~1694-byte ceiling on response data. RSA-2048
  certificates and signatures fit comfortably, but a large cert chain could
  approach it.
