import Foundation

struct VSSRequest: Encodable {
    let validationPolicyId: String
    let x509Certificate: String
}

struct ValidationResult: Decodable {
    let result: String?
    let isAffirmativelyInvalid: Bool?
    let invalidityReasonText: String?
}

struct VSSResponse: Decodable {
    let validationPolicyId: String?
    let x509SubjectName: String?
    let x509CertificatePath: [String]?
    let error: String?
    let status: String?
    let message: String?
    let validationResult: ValidationResult?
}

enum VSSError: Error, LocalizedError {
    case offline
    case cannotConnect
    case timedOut
    case badStatus(Int)
    case malformedResponse

    var errorDescription: String? {
        switch self {
        case .offline:            return "No Internet Connection"
        case .cannotConnect:      return "Could not connect to validation server"
        case .timedOut:           return "Connection to server timed out"
        case .badStatus(let code): return "Validation server returned HTTP \(code)"
        case .malformedResponse:  return "Validation server returned an unreadable response"
        }
    }
}

/// Client for the KeySupport Validation Service.
///
/// Call this only *after* the NFC session has been invalidated. iOS gives a
/// connected tag ~20 seconds, and these timeouts alone could consume most of it.
struct VSSClient {

    /// PIV Card Authentication policy OID.
    static let cardAuthenticationPolicyOID = "2.16.840.1.101.10.2.18.2.2.1"

    private let endpoint = URL(string: "https://home.keysupport.net/vss/v2/validate")!
    private let session: URLSession

    init() {
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 30
        configuration.waitsForConnectivity = false
        session = URLSession(configuration: configuration)
    }

    func validate(certificateDER: Data) async throws -> VSSResponse {
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try JSONEncoder().encode(
            VSSRequest(
                validationPolicyId: Self.cardAuthenticationPolicyOID,
                x509Certificate: certificateDER.base64EncodedString()
            )
        )

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch let urlError as URLError {
            // Map to the same user-facing categories the Android app distinguishes.
            switch urlError.code {
            case .notConnectedToInternet, .dataNotAllowed:
                throw VSSError.offline
            case .cannotConnectToHost, .cannotFindHost, .networkConnectionLost, .dnsLookupFailed:
                throw VSSError.cannotConnect
            case .timedOut:
                throw VSSError.timedOut
            default:
                throw urlError
            }
        }

        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw VSSError.badStatus(http.statusCode)
        }

        do {
            return try JSONDecoder().decode(VSSResponse.self, from: data)
        } catch {
            throw VSSError.malformedResponse
        }
    }
}
