# KeySupport Validator (formerly CardRead)

A modern Android application built with Kotlin and Jetpack Compose to read PIV/CAC/TWIC Card Authentication Certificates via NFC, perform cryptographic Proof of Possession (PoP), and validate the certificates against the KeySupport Validation Service (VSS).

## Architecture
* **Language:** Kotlin
* **UI Framework:** Jetpack Compose (Material 3)
* **Concurrency:** Kotlin Coroutines (Dispatchers.IO for NFC and Networking)
* **Networking:** Retrofit2 + OkHttp3
* **Serialization:** Kotlinx.serialization (JSON)

## Core NFC & APDU Logic
The app uses Android's `NfcAdapter.ReaderCallback` to handle NFC discovery reliably via `IsoDep`. 

### Applet Selection
* **PIV Applet AID:** `00 A4 04 00 0B A0 00 00 03 08 00 00 10 00 01 00`

### Certificate Extraction
* **Card Authentication Certificate:** Requests Tag `5FC101` (Note: `5FC105` is PIV Authentication and requires a PIN).
* **Command:** `00 CB 3F FF 05 5C 03 5F C1 01 00` (Fallbacks to no `Le` byte if the card returns `69 82`).
* **Decompression:** Automatically detects Gzip magic headers (`1F 8B`) and decompresses the payload to raw ASN.1 DER if required.
* **APDU Chaining:** Handles `61 XX` (GET RESPONSE) and `6C XX` (re-issue with correct length) for robust transceiving across different smart card vendors.

### Proof of Possession (PoP)
Performs a challenge/response to cryptographically prove the card holds the private key matching the extracted public key:
* Generates a 64-byte random nonce.
* Determines the key algorithm and size from the X.509 Certificate.
* Computes the digest (SHA-256 or SHA-384) and formats the data block according to NIST SP 800-73 `DynamicAuthTempl`.
* **GENERAL AUTHENTICATE APDU:** `00 87 <algRef> 9E <Lc> <Data>`
  * `algRef 0x07` = RSA 2048
  * `algRef 0x11` = ECC P-256
  * `algRef 0x14` = ECC P-384
* **Signature Verification:** Extracts the resulting signature from the `7C` response container and verifies it locally using `java.security.Signature`.

## Validation Service (VSS)
Once PoP succeeds, the raw X.509 certificate is Base64 encoded and submitted to the VSS REST API.
* **Endpoint:** `https://home.keysupport.net/vss/v2/validate`
* **Policy OID:** `2.16.840.1.101.10.2.18.2.2.1` (Card Authentication Policy)
* **UX/UI:** Parses the nested `validationResult` object to extract user-friendly revocation/expiration reasons and displays the Trust Anchor Certificate Path (`x509CertificatePath`) in an expandable Material 3 Card upon success.
