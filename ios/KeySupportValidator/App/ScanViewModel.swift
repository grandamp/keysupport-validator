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

    @Published private(set) var state: ScanState = PIVReader.isAvailable ? .idle : .unsupported

    private let reader = PIVReader()
    private let vss = VSSClient()

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
