import Foundation
import CoreNFC
import Security

struct PIVScanResult {
    let certificateDER: Data
    let certificate: SecCertificate
    let proofOfPossessionVerified: Bool
}

enum PIVScanPhase {
    case readingCertificate
    case verifyingCard
}

enum PIVReaderError: Error, LocalizedError {
    case nfcUnavailable
    case notAnISO7816Tag
    case appletSelectFailed(sw1: UInt8, sw2: UInt8)
    case certificateReadFailed(sw1: UInt8, sw2: UInt8)
    case generalAuthenticateFailed(sw1: UInt8, sw2: UInt8)
    case sessionInvalidated(String)
    case userCancelled

    var errorDescription: String? {
        switch self {
        case .nfcUnavailable:
            return "This device cannot read NFC smart cards."
        case .notAnISO7816Tag:
            return "That tag is not a smart card."
        case .appletSelectFailed(let sw1, let sw2):
            return "Could not select the PIV applet (\(Self.statusWord(sw1, sw2)))."
        case .certificateReadFailed(let sw1, let sw2):
            return "Could not read the Card Authentication certificate (\(Self.statusWord(sw1, sw2)))."
        case .generalAuthenticateFailed(let sw1, let sw2):
            return "The card refused the authentication challenge (\(Self.statusWord(sw1, sw2)))."
        case .sessionInvalidated(let reason):
            return reason
        case .userCancelled:
            return "Scan cancelled."
        }
    }

    private static func statusWord(_ sw1: UInt8, _ sw2: UInt8) -> String {
        String(format: "SW %02X%02X", sw1, sw2)
    }
}

/// Reads the PIV Card Authentication certificate over NFC and proves the card
/// holds the matching private key.
///
/// The session lifetime is deliberately short. iOS caps a *connected* tag at
/// roughly 20 seconds (60s for the overall reader session) and that limit cannot
/// be extended, so this type does card work only and hands the certificate back
/// to the caller. Network validation happens after the session is invalidated —
/// see `ScanViewModel`. The Android app performs the VSS call while still holding
/// the tag, which would be a live timeout hazard here.
final class PIVReader: NSObject {

    /// PIV Card Application AID (SP 800-73-4). Must also be declared in Info.plist
    /// under `com.apple.developer.nfc.readersession.iso7816.select-identifiers`,
    /// or iOS will never surface the card to this app at all.
    static let pivApplicationID = Data([0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00])

    private var session: NFCTagReaderSession?
    private var continuation: CheckedContinuation<PIVScanResult, Error>?
    private var progressHandler: ((PIVScanPhase) -> Void)?
    private let lock = NSLock()

    static var isAvailable: Bool { NFCTagReaderSession.readingAvailable }

    func scan(onPhase: @escaping (PIVScanPhase) -> Void) async throws -> PIVScanResult {
        guard NFCTagReaderSession.readingAvailable else { throw PIVReaderError.nfcUnavailable }
        progressHandler = onPhase

        return try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            self.continuation = continuation
            lock.unlock()

            guard let session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: nil) else {
                finish(.failure(PIVReaderError.nfcUnavailable))
                return
            }
            session.alertMessage = "Hold your PIV, CAC, or TWIC card against the top of your iPhone."
            self.session = session
            session.begin()
        }
    }

    /// Resumes the pending continuation exactly once. Later callers are no-ops,
    /// which matters because `invalidate()` always triggers `didInvalidateWithError`.
    private func finish(_ result: Result<PIVScanResult, Error>) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(with: result)
    }
}

// MARK: - Card flow

private extension PIVReader {

    func readCard(_ tag: NFCISO7816Tag) async throws -> PIVScanResult {
        progressHandler?(.readingCertificate)
        try await selectPIVApplet(on: tag)
        let der = try await readCardAuthenticationCertificate(from: tag)
        let certificate = try PIVCrypto.certificate(fromDER: der)

        progressHandler?(.verifyingCard)
        let verified = try await performProofOfPossession(on: tag, certificate: certificate)

        return PIVScanResult(
            certificateDER: der,
            certificate: certificate,
            proofOfPossessionVerified: verified
        )
    }

    func selectPIVApplet(on tag: NFCISO7816Tag) async throws {
        // iOS already issued a SELECT using the AID list from Info.plist before
        // handing us the tag (`tag.initialSelectedAID` reports which one matched).
        // Re-selecting is idempotent and keeps this flow explicit.
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00,
            instructionCode: 0xA4,
            p1Parameter: 0x04,
            p2Parameter: 0x00,
            data: PIVReader.pivApplicationID,
            expectedResponseLength: 256
        )
        let (_, sw1, sw2) = try await send(apdu, to: tag)
        guard sw1 == 0x90, sw2 == 0x00 else {
            throw PIVReaderError.appletSelectFailed(sw1: sw1, sw2: sw2)
        }
    }

    func readCardAuthenticationCertificate(from tag: NFCISO7816Tag) async throws -> Data {
        // GET DATA for object 5FC101, the Card Authentication certificate.
        // 5FC105 (PIV Authentication) would demand a PIN; 5FC101 is readable over
        // the contactless interface without cardholder entry, which is the whole
        // reason an NFC-only app is possible.
        let objectID = Data([0x5C, 0x03, 0x5F, 0xC1, 0x01])

        func getData(expecting length: Int) -> NFCISO7816APDU {
            NFCISO7816APDU(
                instructionClass: 0x00,
                instructionCode: 0xCB,
                p1Parameter: 0x3F,
                p2Parameter: 0xFF,
                data: objectID,
                expectedResponseLength: length
            )
        }

        var (payload, sw1, sw2) = try await send(getData(expecting: 256), to: tag)

        // Some cards reject the Le byte outright. Retry with no expected length,
        // mirroring the Android reader's 6982 fallback.
        if sw1 != 0x90 || sw2 != 0x00 {
            (payload, sw1, sw2) = try await send(getData(expecting: -1), to: tag)
        }
        guard sw1 == 0x90, sw2 == 0x00 else {
            throw PIVReaderError.certificateReadFailed(sw1: sw1, sw2: sw2)
        }

        // A certificate object is far larger than the 256 bytes an Le of 0x00 asks
        // for. Stacks that transparently follow `61 XX` chains still stop at the
        // requested length and report success, so a short buffer arrives with
        // SW 90 00 and no error. Verified on a YubiKey over CCID: a 793-byte object
        // came back as exactly 256 bytes. Re-read with the length the object itself
        // declares. Asking for more than 256 requests an extended Le, which is why
        // this is done only when the first read proves it is necessary.
        if let declared = TLV.declaredTotalLength([UInt8](payload)), payload.count < declared {
            let (full, fullSW1, fullSW2) = try await send(getData(expecting: declared), to: tag)
            guard fullSW1 == 0x90, fullSW2 == 0x00 else {
                throw PIVReaderError.certificateReadFailed(sw1: fullSW1, sw2: fullSW2)
            }
            payload = full
        }

        let wrapper = try TLV.value(ofTag: 0x53, in: [UInt8](payload))
        let certificateBytes = Data(try TLV.value(ofTag: 0x70, in: wrapper))

        // CertInfo (tag 0x71) bit 0 flags gzip compression. Not every card
        // populates it, so fall back to sniffing the RFC 1952 magic bytes.
        let certInfo = TLV.optionalValue(ofTag: 0x71, in: wrapper)?.first ?? 0x00
        if (certInfo & 0x01) == 0x01 || certificateBytes.looksGzipped {
            return try certificateBytes.gunzipped()
        }
        return certificateBytes
    }

    func performProofOfPossession(on tag: NFCISO7816Tag, certificate: SecCertificate) async throws -> Bool {
        let challenge = try PIVCrypto.makeChallenge(for: certificate)

        // Dynamic authentication template: 7C L { 81 L <challenge> 82 00 }.
        // The empty 0x82 is the slot the card fills with its signature.
        var template = try TLV.encode(tag: 0x81, value: [UInt8](challenge.challengeBlock))
        template.append(contentsOf: [0x82, 0x00])
        let payload = try TLV.encode(tag: 0x7C, value: template)

        let response = try await sendGeneralAuthenticate(
            payload,
            algorithm: challenge.algorithm,
            expectedResponseLength: challenge.expectedResponseLength,
            to: tag
        )
        let inner = try TLV.value(ofTag: 0x7C, in: [UInt8](response))
        let signature = try TLV.value(ofTag: 0x82, in: inner)

        return try PIVCrypto.verify(signature: Data(signature), challenge: challenge)
    }

    /// Issues GENERAL AUTHENTICATE against the Card Authentication key (P2 = 0x9E).
    ///
    /// CoreNFC exposes no equivalent of Android's `isoDep.isExtendedLengthApduSupported`,
    /// so we cannot probe the card and choose extended-length encoding at runtime.
    /// Command chaining with CLA 0x10 is required of every PIV card by SP 800-73,
    /// so we always chain rather than gamble on extended-length support. Only RSA
    /// actually overflows a short APDU — an RSA-2048 template runs ~266 bytes,
    /// while a P-256 template is ~38 and goes out in a single command.
    func sendGeneralAuthenticate(
        _ payload: [UInt8],
        algorithm: PIVAlgorithm,
        expectedResponseLength: Int,
        to tag: NFCISO7816Tag
    ) async throws -> Data {
        let chunkSize = 250
        var offset = 0

        while true {
            let remaining = payload.count - offset
            let isFinal = remaining <= chunkSize
            let length = isFinal ? remaining : chunkSize
            let chunk = Array(payload[offset..<(offset + length)])

            let apdu = NFCISO7816APDU(
                instructionClass: isFinal ? 0x00 : 0x10,
                instructionCode: 0x87,
                p1Parameter: algorithm.rawValue,
                p2Parameter: 0x9E,
                data: Data(chunk),
                // Sized from the key rather than left at 256 — see PoPChallenge.
                expectedResponseLength: isFinal ? expectedResponseLength : -1
            )

            let (data, sw1, sw2) = try await send(apdu, to: tag)
            guard sw1 == 0x90, sw2 == 0x00 else {
                throw PIVReaderError.generalAuthenticateFailed(sw1: sw1, sw2: sw2)
            }
            if isFinal { return data }
            offset += length
        }
    }

    /// CoreNFC walks 61 XX / GET RESPONSE chains internally, so unlike the Android
    /// reader there is no loop for those. 6C XX is *not* handled for us — the card
    /// is reporting the exact Le it wants, so reissue once with that length.
    func send(_ apdu: NFCISO7816APDU, to tag: NFCISO7816Tag) async throws -> (Data, UInt8, UInt8) {
        let (data, sw1, sw2) = try await tag.sendCommand(apdu: apdu)
        guard sw1 == 0x6C else { return (data, sw1, sw2) }

        let retry = NFCISO7816APDU(
            instructionClass: apdu.instructionClass,
            instructionCode: apdu.instructionCode,
            p1Parameter: apdu.p1Parameter,
            p2Parameter: apdu.p2Parameter,
            data: apdu.data ?? Data(),
            expectedResponseLength: Int(sw2)
        )
        return try await tag.sendCommand(apdu: retry)
    }
}

// MARK: - NFCTagReaderSessionDelegate

extension PIVReader: NFCTagReaderSessionDelegate {

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) { }

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        // Fires on user cancel, on timeout, and after our own invalidate() calls.
        // If we already resumed with a real result, finish() does nothing.
        if let readerError = error as? NFCReaderError,
           readerError.code == .readerSessionInvalidationErrorUserCanceled {
            finish(.failure(PIVReaderError.userCancelled))
        } else {
            finish(.failure(PIVReaderError.sessionInvalidated(error.localizedDescription)))
        }
        self.session = nil
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let tag = tags.first, case let .iso7816(pivTag) = tag else {
            session.invalidate(errorMessage: "That is not a smart card.")
            return
        }

        Task { [weak self] in
            guard let self else { return }
            do {
                try await session.connect(to: tag)
                let result = try await self.readCard(pivTag)

                // Resume before invalidating so we win the race against
                // didInvalidateWithError, then drop the tag immediately — the
                // VSS call must not run inside the 20-second tag window.
                session.alertMessage = "Card read successfully."
                self.finish(.success(result))
                session.invalidate()
            } catch {
                self.finish(.failure(error))
                session.invalidate(errorMessage: error.localizedDescription)
            }
        }
    }
}
