import Foundation
import Security
import CryptoKit

/// Algorithm identifiers from NIST SP 800-78, used as P1 of GENERAL AUTHENTICATE.
enum PIVAlgorithm: UInt8 {
    case rsa2048 = 0x07
    case rsa3072 = 0x05   // Added in SP 800-78-5; confirm against your card stock.
    case eccP256 = 0x11
    case eccP384 = 0x14
}

/// Everything needed to issue a Proof of Possession challenge and check the answer.
struct PoPChallenge {
    let algorithm: PIVAlgorithm
    /// Bytes placed in the 0x81 field of the dynamic authentication template.
    /// For RSA this is a full PKCS#1 v1.5 encoded message; for ECC it is a bare digest.
    let challengeBlock: Data
    /// The random value the returned signature must ultimately verify against.
    let nonce: Data
    let verificationAlgorithm: SecKeyAlgorithm
    let publicKey: SecKey
    /// `Le` for the final GENERAL AUTHENTICATE. The signed response is larger
    /// than the 256 bytes an `Le` of 0x00 asks for — an RSA-2048 answer runs
    /// about 264 bytes inside its 0x7C template — and a stack that stops at the
    /// requested length hands back a truncated buffer with SW 90 00 rather than
    /// an error. Observed on a YubiKey over CCID.
    let expectedResponseLength: Int
}

enum PIVCryptoError: Error, LocalizedError {
    case badCertificate
    case noPublicKey
    case unknownKeyType
    case unsupportedKey(type: String, bits: Int)
    case keyTooSmallForDigest
    case verificationFailed(String)

    var errorDescription: String? {
        switch self {
        case .badCertificate:
            return "Card returned bytes that are not a valid X.509 certificate"
        case .noPublicKey:
            return "Could not extract a public key from the certificate"
        case .unknownKeyType:
            return "Certificate public key has an unrecognized type"
        case .unsupportedKey(let type, let bits):
            return "Unsupported key: \(type) \(bits)-bit"
        case .keyTooSmallForDigest:
            return "Key is too small to hold the PKCS#1 padded digest"
        case .verificationFailed(let reason):
            return "Signature verification failed: \(reason)"
        }
    }
}

enum PIVCrypto {

    /// DER prefix for a SHA-256 DigestInfo (RFC 8017 A.2.4).
    private static let sha256DigestInfoPrefix: [UInt8] = [
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48,
        0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    ]

    static func certificate(fromDER der: Data) throws -> SecCertificate {
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            throw PIVCryptoError.badCertificate
        }
        return certificate
    }

    static func subjectSummary(of certificate: SecCertificate) -> String {
        SecCertificateCopySubjectSummary(certificate) as String? ?? "Unknown Subject"
    }

    /// Builds the challenge for a card whose public key came from `certificate`.
    ///
    /// The card signs `challengeBlock` with the CARD AUTH private key. We then
    /// verify that signature against the original `nonce` using the certificate's
    /// public key — if it checks out, the card physically holds the matching
    /// private key rather than merely carrying a copied certificate.
    static func makeChallenge(for certificate: SecCertificate) throws -> PoPChallenge {
        guard let publicKey = SecCertificateCopyKey(certificate) else {
            throw PIVCryptoError.noPublicKey
        }

        guard let attributes = SecKeyCopyAttributes(publicKey) as? [CFString: Any],
              let keyType = attributes[kSecAttrKeyType] as? String,
              let keyBits = attributes[kSecAttrKeySizeInBits] as? Int
        else {
            throw PIVCryptoError.unknownKeyType
        }

        var nonce = Data(count: 64)
        let status = nonce.withUnsafeMutableBytes { raw -> OSStatus in
            guard let base = raw.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, 64, base)
        }
        guard status == errSecSuccess else {
            throw PIVCryptoError.verificationFailed("Could not generate a random nonce")
        }

        if keyType == (kSecAttrKeyTypeRSA as String) {
            let algorithm: PIVAlgorithm
            switch keyBits {
            case 2048: algorithm = .rsa2048
            case 3072: algorithm = .rsa3072
            default: throw PIVCryptoError.unsupportedKey(type: "RSA", bits: keyBits)
            }

            let digest = [UInt8](SHA256.hash(data: nonce))
            let block = try pkcs1v15Block(
                digestInfo: sha256DigestInfoPrefix + digest,
                modulusSize: SecKeyGetBlockSize(publicKey)
            )

            return PoPChallenge(
                algorithm: algorithm,
                challengeBlock: Data(block),
                nonce: nonce,
                verificationAlgorithm: .rsaSignatureMessagePKCS1v15SHA256,
                publicKey: publicKey,
                // Signature is one modulus wide, plus the 0x7C/0x82 TLV framing.
                expectedResponseLength: SecKeyGetBlockSize(publicKey) + 16
            )
        }

        if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            // ECC signs a bare digest — no padding envelope. The card returns an
            // X9.62 DER SEQUENCE {r, s}, which is what the X962 verify variants expect.
            if keyBits <= 256 {
                return PoPChallenge(
                    algorithm: .eccP256,
                    challengeBlock: Data(SHA256.hash(data: nonce)),
                    nonce: nonce,
                    verificationAlgorithm: .ecdsaSignatureMessageX962SHA256,
                    publicKey: publicKey,
                    // X9.62 DER {r,s} for P-256 is ~72 bytes; 128 is ample.
                    expectedResponseLength: 128
                )
            } else if keyBits <= 384 {
                return PoPChallenge(
                    algorithm: .eccP384,
                    challengeBlock: Data(SHA384.hash(data: nonce)),
                    nonce: nonce,
                    verificationAlgorithm: .ecdsaSignatureMessageX962SHA384,
                    publicKey: publicKey,
                    // X9.62 DER {r,s} for P-384 is ~104 bytes; 160 is ample.
                    expectedResponseLength: 160
                )
            }
            throw PIVCryptoError.unsupportedKey(type: "ECC", bits: keyBits)
        }

        throw PIVCryptoError.unsupportedKey(type: keyType, bits: keyBits)
    }

    /// Verifies the card's signature over the original nonce.
    static func verify(signature: Data, challenge: PoPChallenge) throws -> Bool {
        guard SecKeyIsAlgorithmSupported(challenge.publicKey, .verify, challenge.verificationAlgorithm) else {
            throw PIVCryptoError.verificationFailed("Key does not support \(challenge.verificationAlgorithm.rawValue)")
        }

        var error: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(
            challenge.publicKey,
            challenge.verificationAlgorithm,
            challenge.nonce as CFData,
            signature as CFData,
            &error
        )

        // A false return with an error attached means the signature was well-formed
        // but did not match; that is a legitimate "card failed PoP" result, not a crash.
        if let error = error?.takeRetainedValue(), !verified {
            let description = CFErrorCopyDescription(error) as String? ?? "unknown"
            if description.lowercased().contains("verif") || description.lowercased().contains("match") {
                return false
            }
            throw PIVCryptoError.verificationFailed(description)
        }

        return verified
    }

    /// EM = 0x00 || 0x01 || 0xFF padding || 0x00 || DigestInfo (RFC 8017 §9.2).
    /// Internal rather than private so the test harness can exercise it directly.
    static func pkcs1v15Block(digestInfo: [UInt8], modulusSize: Int) throws -> [UInt8] {
        // Three bytes of framing: leading 0x00, block type 0x01, and the 0x00 separator.
        guard modulusSize >= digestInfo.count + 11 else { throw PIVCryptoError.keyTooSmallForDigest }

        var block = [UInt8](repeating: 0xFF, count: modulusSize)
        block[0] = 0x00
        block[1] = 0x01
        block[modulusSize - digestInfo.count - 1] = 0x00
        block.replaceSubrange((modulusSize - digestInfo.count)..<modulusSize, with: digestInfo)
        return block
    }
}
