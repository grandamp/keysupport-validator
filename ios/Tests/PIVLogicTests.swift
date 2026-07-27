import Foundation

var failures = 0
var checks = 0

func check(_ label: String, _ condition: @autoclosure () throws -> Bool) {
    checks += 1
    do {
        if try condition() {
            print("  ok   \(label)")
        } else {
            failures += 1
            print("  FAIL \(label)")
        }
    } catch {
        failures += 1
        print("  FAIL \(label) — threw \(error)")
    }
}

func checkThrows(_ label: String, _ body: () throws -> Void) {
    checks += 1
    do {
        try body()
        failures += 1
        print("  FAIL \(label) — expected a throw, got none")
    } catch {
        print("  ok   \(label) (threw \(type(of: error)))")
    }
}

// MARK: - TLV length encoding

print("TLV length encoding")
check("0x00 -> 1 byte short form", try TLV.encodeLength(0) == [0x00])
check("0x7F -> short form", try TLV.encodeLength(0x7F) == [0x7F])
check("0x80 -> 0x81 form", try TLV.encodeLength(0x80) == [0x81, 0x80])
check("0xFF -> 0x81 form", try TLV.encodeLength(0xFF) == [0x81, 0xFF])
check("0x100 -> 0x82 form", try TLV.encodeLength(0x100) == [0x82, 0x01, 0x00])
check("266 -> 0x82 0x01 0x0A", try TLV.encodeLength(266) == [0x82, 0x01, 0x0A])
checkThrows("length beyond 0xFFFF rejected") { _ = try TLV.encodeLength(0x10000) }

print("TLV length decoding")
check("short form reads back", try TLV.readLength([0x7F], at: 0) == (0x7F, 1))
check("0x81 form reads back", try TLV.readLength([0x81, 0x80], at: 0) == (0x80, 2))
check("0x82 form reads back", try TLV.readLength([0x82, 0x01, 0x0A], at: 0) == (266, 3))
checkThrows("indefinite form rejected") { _ = try TLV.readLength([0x80], at: 0) }
checkThrows("truncated length rejected") { _ = try TLV.readLength([0x82, 0x01], at: 0) }

// Round trip every boundary length.
print("TLV encode/decode round trip")
var roundTripOK = true
for length in [0, 1, 0x7F, 0x80, 0xFF, 0x100, 266, 0x1234, 0xFFFF] {
    let encoded = try! TLV.encodeLength(length)
    let (value, width) = try! TLV.readLength(encoded, at: 0)
    if value != length || width != encoded.count { roundTripOK = false }
}
check("all boundary lengths round trip", roundTripOK)

// MARK: - TLV value extraction

print("TLV value extraction")

// A realistic 0x53 wrapper: CertInfo (0x71) first, then the cert (0x70).
// This exercises sibling-skipping, which is where hand-rolled parsers usually break.
let certPayload = [UInt8](repeating: 0xAB, count: 300)
var wrapperBody = try! TLV.encode(tag: 0x71, value: [0x00])
wrapperBody += try! TLV.encode(tag: 0x70, value: certPayload)
let wrapper = try! TLV.encode(tag: 0x53, value: wrapperBody)

check("0x53 wrapper has 0x82 length (300+ bytes)", wrapper[1] == 0x82)
let unwrapped = try! TLV.value(ofTag: 0x53, in: wrapper)
check("unwrapped body matches", unwrapped == wrapperBody)
check("extracts 0x71 CertInfo", try TLV.value(ofTag: 0x71, in: unwrapped) == [0x00])
check("extracts 0x70 past the 0x71 sibling", try TLV.value(ofTag: 0x70, in: unwrapped) == certPayload)
check("optionalValue finds 0x71", TLV.optionalValue(ofTag: 0x71, in: unwrapped) == [0x00])
check("optionalValue returns nil for absent tag", TLV.optionalValue(ofTag: 0x99, in: unwrapped) == nil)
checkThrows("absent tag throws") { _ = try TLV.value(ofTag: 0x99, in: unwrapped) }

// Cert with no CertInfo sibling — the common case.
let bare = try! TLV.encode(tag: 0x53, value: try! TLV.encode(tag: 0x70, value: certPayload))
check("extracts 0x70 with no sibling",
      try TLV.value(ofTag: 0x70, in: try TLV.value(ofTag: 0x53, in: bare)) == certPayload)

// MARK: - Short-read detection
//
// Regression cover for a defect found against a YubiKey: a GET DATA asking for
// Le=256 returned exactly 256 bytes with SW 90 00 for an object that declares
// 793. The status word reports success, so the only signal is the TLV header.

print("Short-read detection")

check("declared length of a complete object equals its size",
      TLV.declaredTotalLength(wrapper) == wrapper.count)

// Truncate to 256 bytes, exactly as the card stack did.
let truncated = Array(wrapper.prefix(256))
check("truncated buffer still reports the full declared length",
      TLV.declaredTotalLength(truncated) == wrapper.count)
check("truncation is detectable (declared > received)",
      (TLV.declaredTotalLength(truncated) ?? 0) > truncated.count)
check("parsing a truncated buffer throws rather than silently succeeding",
      (try? TLV.value(ofTag: 0x53, in: truncated)) == nil)

// The exact header seen on the wire: 53 82 03 15 -> 4 header bytes + 789 = 793.
check("real-world header 53 82 03 15 declares 793",
      TLV.declaredTotalLength([0x53, 0x82, 0x03, 0x15]) == 793)
// And the ECC case: 53 82 01 7F -> 4 + 383 = 387.
check("real-world header 53 82 01 7F declares 387",
      TLV.declaredTotalLength([0x53, 0x82, 0x01, 0x7F]) == 387)

check("single-byte buffer is undecidable", TLV.declaredTotalLength([0x53]) == nil)
check("short-form header measured correctly",
      TLV.declaredTotalLength([0x53, 0x05, 1, 2, 3, 4, 5]) == 7)

// MARK: - The GENERAL AUTHENTICATE template (the real payload shape)

print("GENERAL AUTHENTICATE 0x7C template")

// RSA-2048: a 256-byte challenge block. This is the case that overflows a short
// APDU and forces command chaining, so the exact byte count matters.
let rsaChallenge = [UInt8](repeating: 0x5A, count: 256)
var template = try! TLV.encode(tag: 0x81, value: rsaChallenge)
template += [0x82, 0x00]
let popPayload = try! TLV.encode(tag: 0x7C, value: template)

check("0x81 field is 1+3+256 = 260 bytes", template.count == 260 + 2)
check("full 7C payload is 266 bytes", popPayload.count == 266)
check("payload exceeds 255 -> chaining required", popPayload.count > 255)
check("template parses back to the challenge",
      try TLV.value(ofTag: 0x81, in: try TLV.value(ofTag: 0x7C, in: popPayload)) == rsaChallenge)
check("empty 0x82 response slot present",
      try TLV.value(ofTag: 0x82, in: try TLV.value(ofTag: 0x7C, in: popPayload)) == [])

// Chunking math the reader uses: 250-byte chunks over a 266-byte payload.
let chunkSize = 250
var chunks: [[UInt8]] = []
var offset = 0
while true {
    let remaining = popPayload.count - offset
    let isFinal = remaining <= chunkSize
    let length = isFinal ? remaining : chunkSize
    chunks.append(Array(popPayload[offset..<(offset + length)]))
    if isFinal { break }
    offset += length
}
check("266-byte payload splits into 2 chunks", chunks.count == 2)
check("chunk sizes are 250 + 16", chunks.map(\.count) == [250, 16])
check("chunks reassemble to the original", chunks.flatMap { $0 } == popPayload)

// P-256: 32-byte digest, must fit in a single short APDU.
let ecChallenge = [UInt8](repeating: 0x11, count: 32)
var ecTemplate = try! TLV.encode(tag: 0x81, value: ecChallenge)
ecTemplate += [0x82, 0x00]
let ecPayload = try! TLV.encode(tag: 0x7C, value: ecTemplate)
check("P-256 payload is 38 bytes", ecPayload.count == 38)
check("P-256 payload fits one short APDU", ecPayload.count <= 250)

// Parsing a card's signature response: 7C { 82 <sig> }
let fakeSignature = [UInt8](repeating: 0xC3, count: 256)
let response = try! TLV.encode(tag: 0x7C, value: try! TLV.encode(tag: 0x82, value: fakeSignature))
check("extracts signature from 7C/82 response",
      try TLV.value(ofTag: 0x82, in: try TLV.value(ofTag: 0x7C, in: response)) == fakeSignature)

// MARK: - PKCS#1 v1.5

print("PKCS#1 v1.5 padding")

let sha256Prefix: [UInt8] = [
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
]
let digest = [UInt8](repeating: 0x77, count: 32)
let digestInfo = sha256Prefix + digest
let em = try! PIVCrypto.pkcs1v15Block(digestInfo: digestInfo, modulusSize: 256)

check("EM is exactly the modulus size", em.count == 256)
check("EM starts 00 01", em[0] == 0x00 && em[1] == 0x01)
check("DigestInfo is 51 bytes", digestInfo.count == 51)
check("separator 0x00 sits at 256-51-1 = 204", em[204] == 0x00)
check("padding between 2..<204 is all 0xFF", em[2..<204].allSatisfy { $0 == 0xFF })
check("padding run is 202 bytes", em[2..<204].count == 202)
check("DigestInfo occupies the tail", Array(em[205...]) == digestInfo)
check("no stray 0x00 inside the padding", !em[2..<204].contains(0x00))

// 3072-bit key.
let em3072 = try! PIVCrypto.pkcs1v15Block(digestInfo: digestInfo, modulusSize: 384)
check("3072-bit EM is 384 bytes", em3072.count == 384)
check("3072-bit separator at 384-51-1 = 332", em3072[332] == 0x00)
check("3072-bit tail is the DigestInfo", Array(em3072[333...]) == digestInfo)

checkThrows("modulus too small for digest is rejected") {
    _ = try PIVCrypto.pkcs1v15Block(digestInfo: digestInfo, modulusSize: 32)
}

// MARK: - Distinguished name parsing

print("Distinguished name parsing")

// The shape a PIV subject takes: a long serial, then repeated OUs narrowing
// from department to bureau. All values fictional — no real cardholder or
// issuer detail belongs in a repository.
let piv = DistinguishedName(
    "SERIALNUMBER=00000000000000, OU=Example Bureau, "
    + "OU=Example Department, O=Example Organization, C=ZZ"
)
check("parses 5 fields", piv.fields.count == 5)
check("SERIALNUMBER labelled Card Serial", piv.fields[0].label == "Card Serial")
check("serial value preserved", piv.fields[0].value == "00000000000000")
check("repeated OU both retained",
      piv.fields[1].value == "Example Bureau"
      && piv.fields[2].value == "Example Department")
check("O labelled Organization", piv.fields[3].label == "Organization")
check("C value parsed", piv.fields[4].value == "ZZ")
check("field order preserved", piv.fields.map(\.label)
      == ["Card Serial", "Organizational Unit", "Organizational Unit", "Organization", "Country"])

// RFC 4514 escaping: a comma inside a value must not split the field.
let escaped = DistinguishedName(#"CN=Acme\, Inc, C=US"#)
check("escaped comma does not split", escaped.fields.count == 2)
check("escaped comma unescaped in value", escaped.fields[0].value == "Acme, Inc")

check("unknown attribute keeps its name",
      DistinguishedName("FOO=bar").fields.first?.label == "FOO")
check("lowercase attribute normalised",
      DistinguishedName("cn=Jane").fields.first?.label == "Name")
check("garbage yields no fields", DistinguishedName("not a dn at all").isEmpty)
check("empty string yields no fields", DistinguishedName("").isEmpty)
check("empty value skipped", DistinguishedName("CN=, O=Gov").fields.count == 1)

// MARK: - Positional TLV walking (needed for X.509)

print("TLV element walking")

var seq = try! TLV.encode(tag: 0x02, value: [0x01])          // INTEGER
seq += try! TLV.encode(tag: 0x30, value: [0xAA])             // SEQUENCE
seq += try! TLV.encode(tag: 0x30, value: [0xBB, 0xCC])       // SEQUENCE
let walked = TLV.elements(in: seq)
check("walks 3 elements", walked.count == 3)
check("tags in order", walked.map(\.tag) == [0x02, 0x30, 0x30])
check("distinguishes same-tag siblings by position",
      walked[1].value == [0xAA] && walked[2].value == [0xBB, 0xCC])
check("malformed tail stops cleanly rather than throwing",
      TLV.elements(in: seq + [0x30, 0x82]).count == 3)
check("empty input yields no elements", TLV.elements(in: []).isEmpty)

// MARK: - ASN.1 time

print("ASN.1 time parsing")

let utc = DateFormatter()
utc.locale = Locale(identifier: "en_US_POSIX")
utc.timeZone = TimeZone(identifier: "UTC")
utc.dateFormat = "yyyy-MM-dd HH:mm:ss"

func asn1(_ tag: UInt8, _ text: String) -> String? {
    guard let d = CertificateDetails.asn1Time(tag: tag, value: Array(text.utf8)) else { return nil }
    return utc.string(from: d)
}

check("UTCTime parsed", asn1(0x17, "260727120000Z") == "2026-07-27 12:00:00")
check("GeneralizedTime parsed", asn1(0x18, "20260727120000Z") == "2026-07-27 12:00:00")
// RFC 5280 4.1.2.5.1: 00-49 -> 20xx, 50-99 -> 19xx.
check("two-digit year 49 -> 2049", (asn1(0x17, "490101000000Z") ?? "").hasPrefix("2049"))
check("two-digit year 50 -> 1950", (asn1(0x17, "500101000000Z") ?? "").hasPrefix("1950"))
check("unknown time tag rejected", asn1(0x99, "260727120000Z") == nil)
check("garbage rejected", asn1(0x17, "not-a-time") == nil)

// MARK: - Certificate validity from DER

print("Certificate validity")

if let certPath = ProcessInfo.processInfo.environment["TEST_CERT_DER"],
   let der = FileManager.default.contents(atPath: certPath) {
    if let validity = CertificateDetails.validity(fromDER: der) {
        check("validity extracted from a real certificate", true)
        check("notAfter is after notBefore", validity.notAfter > validity.notBefore)
        let days = validity.notAfter.timeIntervalSince(validity.notBefore) / 86_400
        check("span is the 365 days openssl was asked for", abs(days - 365) < 2)
    } else {
        failures += 1; checks += 1
        print("  FAIL could not extract validity from the generated certificate")
    }
} else {
    print("  SKIP no TEST_CERT_DER fixture")
}
check("garbage DER yields nil, not a crash",
      CertificateDetails.validity(fromDER: Data([0x30, 0x03, 0x02, 0x01, 0x01])) == nil)
check("empty DER yields nil", CertificateDetails.validity(fromDER: Data()) == nil)

// MARK: - Success-screen rows

print("Credential detail rows")

let summary = CredentialSummary(
    subject: "SERIALNUMBER=0123, OU=Example Bureau, O=Example Organization, C=ZZ",
    certificatePath: ["CN=Example Root", "CN=Example Issuing CA", "CN=Example Leaf"],
    keyDescription: "RSA 2048",
    notBefore: Date(timeIntervalSince1970: 1_767_225_600),
    notAfter: Date(timeIntervalSince1970: 1_798_761_600),
    checkedAt: Date(timeIntervalSince1970: 1_767_225_600)
)
let detailRows = CredentialDetails.rows(for: summary)
let labels = detailRows.map(\.label)

check("subject attributes lead the list",
      Array(labels.prefix(4)) == ["Card Serial", "Organizational Unit", "Organization", "Country"])
check("key row present", labels.contains("Key"))
check("issuer taken from second-to-last path entry",
      detailRows.first { $0.label == "Issued By" }?.value == "CN=Example Issuing CA")
check("validity rows present", labels.contains("Valid From") && labels.contains("Valid Until"))
check("checked row present", labels.contains("Checked"))

// Nil values must drop out rather than render blank rows.
let sparse = CredentialSummary(subject: "CN=Someone", certificatePath: [],
                               keyDescription: nil, notBefore: nil, notAfter: nil,
                               checkedAt: Date(timeIntervalSince1970: 0))
let sparseLabels = CredentialDetails.rows(for: sparse).map(\.label)
check("absent key omitted", !sparseLabels.contains("Key"))
check("absent dates omitted",
      !sparseLabels.contains("Valid From") && !sparseLabels.contains("Valid Until"))
check("absent path omits issuer", !sparseLabels.contains("Issued By"))
check("checked row always present", sparseLabels.contains("Checked"))
check("issuer nil when path holds only a leaf",
      CredentialDetails.issuer(from: ["CN=Only Leaf"]) == nil)

// MARK: - Gzip

print("Gzip decompression")

let fixtures = CommandLine.arguments.dropFirst()
if fixtures.isEmpty {
    print("  SKIP no gzip fixtures passed")
} else {
    for path in fixtures {
        let name = (path as NSString).lastPathComponent
        guard let gz = FileManager.default.contents(atPath: path),
              let original = FileManager.default.contents(atPath: path.replacingOccurrences(of: ".gz", with: ""))
        else {
            failures += 1
            print("  FAIL \(name) — could not load fixture")
            continue
        }
        check("\(name) detected as gzip", gz.looksGzipped)
        check("\(name) round trips to original bytes", try gz.gunzipped() == original)
    }
}

// A DER certificate (starts 0x30) must not be mistaken for gzip.
check("DER SEQUENCE not flagged as gzip", !Data([0x30, 0x82, 0x04, 0x00]).looksGzipped)
checkThrows("garbage gzip rejected") { _ = try Data([0x1F, 0x8B, 0x08, 0x00, 0x00]).gunzipped() }

print("")
print("\(checks - failures)/\(checks) checks passed")
exit(failures == 0 ? 0 : 1)
