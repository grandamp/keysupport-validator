import Foundation

/// Minimal BER-TLV reader/writer covering the subset of encodings PIV uses:
/// the 0x53 data-object wrapper from SP 800-73-4 and the 0x7C dynamic
/// authentication template used by GENERAL AUTHENTICATE.
///
/// Everything here works on `[UInt8]` rather than `Data` on purpose. `Data`
/// slices keep the parent's indices, so `data[0]` traps on a subdata result —
/// a trap that is very easy to introduce while parsing nested structures.
enum TLVError: Error, LocalizedError {
    case truncated
    case tagNotFound(UInt8)
    case lengthTooLarge(Int)
    case unsupportedLengthEncoding

    var errorDescription: String? {
        switch self {
        case .truncated:
            return "TLV data ended unexpectedly"
        case .tagNotFound(let tag):
            return String(format: "TLV tag 0x%02X not found in response", tag)
        case .lengthTooLarge(let length):
            return "TLV length \(length) exceeds the supported range"
        case .unsupportedLengthEncoding:
            return "TLV length uses an encoding this parser does not support"
        }
    }
}

enum TLV {

    /// Decodes a BER length at `offset`, returning the value and the width of
    /// the length field itself.
    static func readLength(_ bytes: [UInt8], at offset: Int) throws -> (value: Int, width: Int) {
        guard offset < bytes.count else { throw TLVError.truncated }
        let first = Int(bytes[offset])
        if first < 0x80 { return (first, 1) }

        let byteCount = first & 0x7F
        // 0x80 is the indefinite form, which PIV never uses. More than four
        // length bytes would overflow the Int arithmetic below on 32-bit.
        guard byteCount > 0, byteCount <= 4 else { throw TLVError.unsupportedLengthEncoding }
        guard offset + byteCount < bytes.count else { throw TLVError.truncated }

        var value = 0
        for index in 1...byteCount {
            value = (value << 8) | Int(bytes[offset + index])
        }
        return (value, byteCount + 1)
    }

    /// Encodes a length using the shortest valid definite form.
    static func encodeLength(_ length: Int) throws -> [UInt8] {
        switch length {
        case ..<0x80:
            return [UInt8(length)]
        case ..<0x100:
            return [0x81, UInt8(length)]
        case ..<0x10000:
            return [0x82, UInt8(length >> 8), UInt8(length & 0xFF)]
        default:
            throw TLVError.lengthTooLarge(length)
        }
    }

    /// Builds `tag || length || value`.
    static func encode(tag: UInt8, value: [UInt8]) throws -> [UInt8] {
        var out: [UInt8] = [tag]
        out.append(contentsOf: try encodeLength(value.count))
        out.append(contentsOf: value)
        return out
    }

    /// Returns the value bytes of the first occurrence of `tag` at this nesting
    /// level, stepping over any sibling TLVs that precede it.
    static func value(ofTag tag: UInt8, in bytes: [UInt8]) throws -> [UInt8] {
        var offset = 0
        while offset < bytes.count {
            let currentTag = bytes[offset]
            offset += 1

            let (length, width) = try readLength(bytes, at: offset)
            offset += width
            guard offset + length <= bytes.count else { throw TLVError.truncated }

            if currentTag == tag {
                return Array(bytes[offset..<(offset + length)])
            }
            offset += length
        }
        throw TLVError.tagNotFound(tag)
    }

    /// Non-throwing lookup for genuinely optional elements such as CertInfo.
    static func optionalValue(ofTag tag: UInt8, in bytes: [UInt8]) -> [UInt8]? {
        try? value(ofTag: tag, in: bytes)
    }
}
