import Foundation
import Security

/// Pulls display-worthy facts out of an X.509 certificate.
///
/// iOS deliberately exposes very little certificate structure — there is no
/// equivalent of `SecCertificateCopyValues`, which is macOS-only, and nothing at
/// all for validity dates. The options are a full ASN.1 dependency
/// (`swift-certificates`) or a narrow hand-rolled read. This is the narrow read:
/// it walks only as far as the `validity` field and never descends into any
/// structure it does not need, which keeps it small enough to verify by eye and
/// to cover with tests.
enum CertificateDetails {

    // MARK: - Key

    /// "RSA 2048", "ECC P-256", etc. Derived from the public key, so it reflects
    /// what the card actually carries rather than what we hoped for.
    static func keyDescription(of certificate: SecCertificate) -> String? {
        guard let key = SecCertificateCopyKey(certificate),
              let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
              let type = attributes[kSecAttrKeyType] as? String,
              let bits = attributes[kSecAttrKeySizeInBits] as? Int
        else { return nil }

        if type == (kSecAttrKeyTypeRSA as String) { return "RSA \(bits)" }
        if type == (kSecAttrKeyTypeECSECPrimeRandom as String) { return "ECC P-\(bits)" }
        return "\(bits)-bit key"
    }

    // MARK: - Validity

    /// Reads `notBefore` / `notAfter` out of the DER.
    ///
    /// ```
    /// Certificate  ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    /// TBSCertificate ::= SEQUENCE {
    ///     version [0] EXPLICIT DEFAULT v1,   -- context tag 0xA0, optional
    ///     serialNumber  INTEGER,
    ///     signature     SEQUENCE,
    ///     issuer        SEQUENCE,
    ///     validity      SEQUENCE,            <-- the target
    ///     subject       SEQUENCE, ... }
    /// ```
    ///
    /// Returns nil rather than throwing: a missing date should quietly omit a row,
    /// never fail a scan that already validated.
    static func validity(fromDER der: Data) -> (notBefore: Date, notAfter: Date)? {
        let bytes = [UInt8](der)

        guard let certificate = TLV.elements(in: bytes).first, certificate.tag == 0x30,
              let tbs = TLV.elements(in: certificate.value).first, tbs.tag == 0x30
        else { return nil }

        let fields = TLV.elements(in: tbs.value)
        guard !fields.isEmpty else { return nil }

        // The version field is optional. When present it is context tag [0] (0xA0)
        // and pushes every later field along by one.
        let validityIndex = (fields[0].tag == 0xA0) ? 4 : 3
        guard fields.count > validityIndex, fields[validityIndex].tag == 0x30 else { return nil }

        let dates = TLV.elements(in: fields[validityIndex].value)
        guard dates.count >= 2,
              let notBefore = asn1Time(tag: dates[0].tag, value: dates[0].value),
              let notAfter = asn1Time(tag: dates[1].tag, value: dates[1].value)
        else { return nil }

        return (notBefore, notAfter)
    }

    /// ASN.1 UTCTime (0x17) is `YYMMDDHHMMSSZ`; GeneralizedTime (0x18) is
    /// `YYYYMMDDHHMMSSZ`. Per RFC 5280 a two-digit year below 50 means 20xx.
    static func asn1Time(tag: UInt8, value: [UInt8]) -> Date? {
        guard let raw = String(bytes: value, encoding: .ascii) else { return nil }

        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMddHHmmss'Z'"

        switch tag {
        case 0x18:
            return formatter.date(from: raw)

        case 0x17:
            // UTCTime carries a two-digit year. RFC 5280 §4.1.2.5.1 fixes the
            // window: 00-49 means 20xx, 50-99 means 19xx.
            //
            // `DateFormatter.twoDigitStartDate` is supposed to express exactly
            // this and does not reliably do so when `dateFormat` is set directly
            // — a test asserting 50 -> 1950 caught it returning 2050. Expanding
            // the year by hand and parsing four digits is deterministic.
            guard raw.count >= 13, let shortYear = Int(raw.prefix(2)) else { return nil }
            let year = shortYear < 50 ? 2000 + shortYear : 1900 + shortYear
            return formatter.date(from: "\(year)\(raw.dropFirst(2))")

        default:
            return nil
        }
    }
}
