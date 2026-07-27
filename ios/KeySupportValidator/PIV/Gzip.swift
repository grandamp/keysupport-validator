import Foundation
import Compression

/// PIV cards are allowed to store the certificate in tag 0x70 gzip-compressed,
/// flagged by bit 0 of the CertInfo byte in tag 0x71.
///
/// Foundation has no gzip support. Apple's `COMPRESSION_ZLIB` is *raw DEFLATE*
/// with no zlib or gzip container, so the fix is to strip the RFC 1952 header
/// and trailer ourselves and hand the bare DEFLATE stream to the Compression
/// framework. This is the one piece of the Android reader that has no direct
/// iOS equivalent.
enum GzipError: Error, LocalizedError {
    case malformedHeader
    case inflateFailed

    var errorDescription: String? {
        switch self {
        case .malformedHeader: return "Certificate gzip header is malformed"
        case .inflateFailed: return "Failed to decompress the certificate"
        }
    }
}

extension Data {

    /// True when the payload carries the RFC 1952 magic bytes.
    var looksGzipped: Bool {
        let bytes = [UInt8](self)
        return bytes.count >= 2 && bytes[0] == 0x1F && bytes[1] == 0x8B
    }

    func gunzipped() throws -> Data {
        let bytes = [UInt8](self)

        // 10-byte fixed header + 8-byte trailer is the minimum possible member.
        guard bytes.count > 18, bytes[0] == 0x1F, bytes[1] == 0x8B, bytes[2] == 0x08 else {
            throw GzipError.malformedHeader
        }

        let flags = bytes[3]
        var cursor = 10

        if flags & 0x04 != 0 { // FEXTRA
            guard cursor + 1 < bytes.count else { throw GzipError.malformedHeader }
            let extraLength = Int(bytes[cursor]) | (Int(bytes[cursor + 1]) << 8)
            cursor += 2 + extraLength
        }
        if flags & 0x08 != 0 { cursor = try Self.skipCString(bytes, from: cursor) } // FNAME
        if flags & 0x10 != 0 { cursor = try Self.skipCString(bytes, from: cursor) } // FCOMMENT
        if flags & 0x02 != 0 { cursor += 2 }                                        // FHCRC

        let deflatedEnd = bytes.count - 8
        guard cursor < deflatedEnd else { throw GzipError.malformedHeader }

        // The trailer's ISIZE field gives the uncompressed length, which sizes
        // the output buffer exactly. Cap it so a corrupt card response cannot
        // ask us to allocate an absurd amount; PIV certificates are a few KB.
        let sizeOffset = bytes.count - 4
        let declaredSize = Int(bytes[sizeOffset])
            | Int(bytes[sizeOffset + 1]) << 8
            | Int(bytes[sizeOffset + 2]) << 16
            | Int(bytes[sizeOffset + 3]) << 24

        let ceiling = 1 << 20
        let capacity = (declaredSize > 0 && declaredSize <= ceiling) ? declaredSize : ceiling

        let deflated = Array(bytes[cursor..<deflatedEnd])
        var output = Data(count: capacity)

        let written = output.withUnsafeMutableBytes { raw -> Int in
            guard let destination = raw.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return deflated.withUnsafeBufferPointer { source -> Int in
                guard let sourceBase = source.baseAddress else { return 0 }
                return compression_decode_buffer(
                    destination, capacity,
                    sourceBase, deflated.count,
                    nil, COMPRESSION_ZLIB
                )
            }
        }

        guard written > 0 else { throw GzipError.inflateFailed }
        return output.prefix(written)
    }

    /// Advances past a NUL-terminated header field.
    private static func skipCString(_ bytes: [UInt8], from start: Int) throws -> Int {
        var index = start
        while index < bytes.count, bytes[index] != 0x00 { index += 1 }
        guard index < bytes.count else { throw GzipError.malformedHeader }
        return index + 1
    }
}
