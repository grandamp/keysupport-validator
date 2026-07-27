# Building for iPhone (iOS)

Building the exact same app for an iPhone is entirely feasible! Apple opened up their NFC capabilities (via the **CoreNFC** framework) to allow raw APDU communication with smart cards starting in iOS 13.

Here is a breakdown of what it would take and how the Android components translate to the Apple ecosystem:

### 1. The Tech Stack
*   **Language:** Swift (instead of Kotlin).
*   **UI Framework:** SwiftUI (the exact Apple equivalent of Jetpack Compose).
*   **Networking:** `URLSession` with `Codable` structs (instead of Retrofit + kotlinx.serialization).
*   **Cryptography:** Apple's `CryptoKit` and `Security` frameworks to handle the SHA-256/384 hashing and RSA/ECDSA signature verification for the Proof of Possession.

### 2. The NFC Layer (`CoreNFC`)
Instead of Android's `IsoDep`, iOS uses `NFCISO7816Tag`. The translation is straightforward, with a few Apple-specific quirks:
*   **Auto-Chaining:** ~~iOS handles the `61 XX` (GET RESPONSE) chaining automatically when using `sendCommand(apdu:)`. You wouldn't need to write the `while` loop we wrote in Kotlin.~~

    **Corrected — this is not true.** Measured against a production PIV card
    over NFC on an iPhone 13: a `GET DATA` for the 1652-byte Card Authentication
    object returned **256 bytes with `SW 6100`** and stopped there. CoreNFC does
    *not* walk the chain, and nothing surfaces the truncation — the caller simply
    receives a short buffer with an apparently fine status word, which fails much
    later as a confusing TLV parse error.

    **You do need the `while` loop we wrote in Kotlin.** The iOS reader issues
    `00 C0 00 00 <Le>` until a final status word, exactly as `PivReader.transceive`
    does; the object above takes six rounds to arrive complete.

    Related: do not compute `Le` for `GENERAL AUTHENTICATE`. Asking for an exact
    length earns `SW 6282` ("end of file reached before reading Ne bytes") when it
    overshoots. Pass `expectedResponseLength: 256` — CoreNFC's encoding of
    `Le = 0x00`, "return whatever you have" — and let the GET RESPONSE loop collect
    the rest. That works unchanged across RSA and ECC key sizes.
*   **The System UI:** On Android, NFC scanning happens invisibly in the background, allowing custom "Ready to Scan" UI. On iOS, invoking an `NFCTagReaderSession` triggers a mandatory, un-bypassable Apple system bottom-sheet that pops up and says "Ready to Scan". 
*   **Info.plist Entitlements:** Apple is very strict about security. We would have to explicitly declare the PIV Applet AID (`A000000308000010000100`) inside the iOS app's `Info.plist` file under `com.apple.developer.nfc.readersession.iso7816.select-identifiers`. If it's not declared there, the iPhone's NFC chip will completely ignore the smart card.

### 3. Certificate Parsing
Android has the excellent `java.security.cert.CertificateFactory` built-in, which flawlessly turns raw bytes into an `X509Certificate` object. 
Native Swift (`SecCertificate`) is much more opaque. To strip the ASN.1 wrappers and extract the Public Key for the Proof of Possession, we would likely need to pull in a lightweight open-source Swift ASN.1 parsing library (like Apple's own `swift-asn1`).

### 4. Development Requirements
*   **A Mac:** You need macOS running Xcode to compile the app.
*   **Physical iPhone:** The iOS Simulator *cannot* simulate NFC. You must have a physical iPhone to test the code.
*   **Apple Developer Program:** Testing an NFC app on a physical iPhone requires an active Apple Developer Program membership ($99/year) to generate the necessary NFC provisioning profiles.

### Summary
Because the app relies so heavily on hardware-level APIs (NFC and Crypto), using a cross-platform framework like React Native or Flutter isn't recommended. A clean, native **Swift + SwiftUI** app is the way to go.
