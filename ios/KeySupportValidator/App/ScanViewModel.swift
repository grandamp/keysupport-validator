import Foundation
import SwiftUI

enum ScanState: Equatable {
    case idle
    /// iPhone 6s and earlier, or iPad — no ISO 7816 reader hardware.
    case unsupported
    case readingCertificate
    case verifyingCard
    case validatingNetwork
    case success(subject: String, path: [String])
    case failure(title: String, message: String)

    var isTerminal: Bool {
        switch self {
        case .success, .failure: return true
        default: return false
        }
    }
}

@MainActor
final class ScanViewModel: ObservableObject {

    @Published private(set) var state: ScanState

    private let reader = PIVReader()
    private let vss = VSSClient()

    init() {
        #if DEBUG
        // Every interesting screen — success, revoked, expired, PoP failure —
        // is only reachable by tapping a real card to a real iPhone. That makes
        // the UI impossible to review on a simulator, so DEBUG builds allow a
        // starting state to be forced:
        //
        //   SIMCTL_CHILD_KSV_PREVIEW_STATE=success \
        //     xcrun simctl launch <device> net.keysupport.cardread
        //
        // Never compiled into Release.
        if let forced = Self.previewState(named: ProcessInfo.processInfo.environment["KSV_PREVIEW_STATE"]) {
            state = forced
            return
        }
        #endif
        state = PIVReader.isAvailable ? .idle : .unsupported
    }

    #if DEBUG
    static func previewState(named name: String?) -> ScanState? {
        switch name?.lowercased() {
        case "idle":        return .idle
        case "unsupported": return .unsupported
        case "reading":     return .readingCertificate
        case "verifying":   return .verifyingCard
        case "validating":  return .validatingNetwork
        case "success":
            // Shaped like a real Federal PIV subject so the layout is exercised
            // honestly. The serial is fabricated — never commit a real one.
            return .success(
                subject: "SERIALNUMBER=0000000000000000000000000000000000000000000000000, "
                       + "OU=Example Bureau, OU=Example Department, "
                       + "O=Example Organization, C=US",
                path: [
                    "CN=Federal Common Policy CA G2, OU=FPKI, O=Example Organization, C=US",
                    "CN=Agency Issuing CA G3, OU=FPKI, O=Example Organization, C=US",
                    "CN=EXAMPLE.CARDHOLDER.1234567890, OU=Example Organization, C=US"
                ]
            )
        case "revoked":
            return .failure(title: "Revoked", message: "Credential Validation Failed: certificate has been revoked")
        case "expired":
            return .failure(title: "Expired", message: "Credential Validation Failed: NotAfter validation failed")
        case "popfailed":
            return .failure(
                title: "PoP Failed",
                message: "Proof of Possession signature validation failed. This card does not hold the private key matching its own certificate."
            )
        default: return nil
        }
    }
    #endif

    var isBusy: Bool {
        switch state {
        case .readingCertificate, .verifyingCard, .validatingNetwork: return true
        default: return false
        }
    }

    func scan() async {
        guard PIVReader.isAvailable else {
            state = .unsupported
            return
        }

        state = .readingCertificate

        // Phase 1: everything that needs the card. Kept as short as possible.
        let result: PIVScanResult
        do {
            result = try await reader.scan { [weak self] phase in
                Task { @MainActor in
                    guard let self else { return }
                    switch phase {
                    case .readingCertificate: self.state = .readingCertificate
                    case .verifyingCard:      self.state = .verifyingCard
                    }
                }
            }
        } catch PIVReaderError.userCancelled {
            state = .idle
            return
        } catch {
            state = .failure(title: "Read Error", message: error.localizedDescription)
            return
        }

        guard result.proofOfPossessionVerified else {
            state = .failure(
                title: "PoP Failed",
                message: "Proof of Possession signature validation failed. This card does not hold the private key matching its own certificate."
            )
            return
        }

        // Phase 2: the NFC session is closed by now, so this network call is not
        // racing the tag timeout. This split is the main structural difference
        // from the Android implementation, which validates while still connected.
        state = .validatingNetwork
        do {
            let response = try await vss.validate(certificateDER: result.certificateDER)
            state = Self.interpret(response, fallbackSubject: PIVCrypto.subjectSummary(of: result.certificate))
        } catch {
            state = .failure(title: "Network Error", message: error.localizedDescription)
        }
    }

    func reset() {
        state = PIVReader.isAvailable ? .idle : .unsupported
    }

    private static func interpret(_ response: VSSResponse, fallbackSubject: String) -> ScanState {
        if response.validationResult?.result == "SUCCESS" {
            return .success(
                subject: response.x509SubjectName ?? fallbackSubject,
                path: response.x509CertificatePath ?? []
            )
        }

        let reason = response.validationResult?.invalidityReasonText
            ?? response.error
            ?? response.message
            ?? "Revoked/Expired"

        let lowered = reason.lowercased()
        let title: String
        if lowered.contains("revoked") {
            title = "Revoked"
        } else if lowered.contains("notafter") || lowered.contains("expired") {
            title = "Expired"
        } else {
            title = "Validation Error"
        }

        return .failure(title: title, message: "Credential Validation Failed: \(reason)")
    }
}
