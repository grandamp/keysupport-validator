import Foundation
import CryptoTokenKit
import Security

// A macOS command-line exercise of the PIV logic against a real card over
// USB/CCID, using CryptoTokenKit instead of CoreNFC.
//
// This shares TLV.swift, PIVCrypto.swift, and Gzip.swift verbatim with the iOS
// app — only the transport is reimplemented. That means a green run here proves
// the APDU sequences, TLV parsing, decompression, PKCS#1 construction, and the
// Proof of Possession round trip all work against real hardware, leaving only
// the CoreNFC transport and SwiftUI layer needing a physical iPhone.
//
// macOS has no NFC API of any kind, so the contactless path cannot be covered here.

// MARK: - Output helpers

let bold = "\u{001B}[1m", dim = "\u{001B}[2m", reset = "\u{001B}[0m"
let green = "\u{001B}[32m", red = "\u{001B}[31m", yellow = "\u{001B}[33m"

func step(_ text: String)  { print("\(bold)==> \(text)\(reset)") }
func ok(_ text: String)    { print("    \(green)ok\(reset)   \(text)") }
func fail(_ text: String)  { print("    \(red)FAIL\(reset) \(text)") }
func info(_ text: String)  { print("    \(dim)\(text)\(reset)") }
func warn(_ text: String)  { print("    \(yellow)warn\(reset) \(text)") }

func hex(_ data: Data, limit: Int = 32) -> String {
    let bytes = [UInt8](data)
    let shown = bytes.prefix(limit).map { String(format: "%02X", $0) }.joined(separator: " ")
    return bytes.count > limit ? "\(shown) … (\(bytes.count) bytes)" : shown
}

struct ProbeError: Error, LocalizedError {
    let message: String
    var errorDescription: String? { message }
    init(_ message: String) { self.message = message }
}

// MARK: - Transport

/// Mirrors `PIVReader.send` / `sendGeneralAuthenticate`, but over TKSmartCard.
/// Command chaining is driven manually rather than delegated to
/// `useCommandChaining` so the chunking arithmetic under test is the same code
/// path the iOS reader uses.
final class CardTransport {
    private let card: TKSmartCard

    init(card: TKSmartCard) {
        self.card = card
        card.useCommandChaining = false
        card.useExtendedLength = false
    }

    func send(cla: UInt8 = 0x00, ins: UInt8, p1: UInt8, p2: UInt8, data: Data?, le: Int?) async throws -> (Data, UInt8, UInt8) {
        card.cla = cla
        // CryptoTokenKit returns (sw, response) — note the order. This resolves
        // to the synchronous overload, which is what you want inside a session.
        let (sw, response) = try card.send(
            ins: ins, p1: p1, p2: p2,
            data: data,
            le: le
        )
        return (response, UInt8(sw >> 8), UInt8(sw & 0xFF))
    }

    func selectPIVApplet() async throws {
        let aid = Data([0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00])
        let (response, sw1, sw2) = try await send(ins: 0xA4, p1: 0x04, p2: 0x00, data: aid, le: 256)
        guard sw1 == 0x90, sw2 == 0x00 else {
            throw ProbeError(String(format: "SELECT PIV failed: SW %02X%02X", sw1, sw2))
        }
        info("application template: \(hex(response))")
    }

    func readCardAuthCertificate() async throws -> Data {
        let objectID = Data([0x5C, 0x03, 0x5F, 0xC1, 0x01])

        var (payload, sw1, sw2) = try await send(ins: 0xCB, p1: 0x3F, p2: 0xFF, data: objectID, le: 256)
        if sw1 != 0x90 || sw2 != 0x00 {
            warn(String(format: "GET DATA with Le returned SW %02X%02X — retrying without Le", sw1, sw2))
            (payload, sw1, sw2) = try await send(ins: 0xCB, p1: 0x3F, p2: 0xFF, data: objectID, le: nil)
        }
        guard sw1 == 0x90, sw2 == 0x00 else {
            if sw1 == 0x6A, sw2 == 0x82 {
                throw ProbeError("Slot 9E is empty (SW 6A82 — file not found). Provision a Card Authentication key and certificate first.")
            }
            throw ProbeError(String(format: "GET DATA failed: SW %02X%02X", sw1, sw2))
        }

        info("raw object: \(hex(payload))")

        let wrapper = try TLV.value(ofTag: 0x53, in: [UInt8](payload))
        let certificateBytes = Data(try TLV.value(ofTag: 0x70, in: wrapper))
        let certInfo = TLV.optionalValue(ofTag: 0x71, in: wrapper)?.first ?? 0x00
        info(String(format: "CertInfo (tag 0x71) = 0x%02X", certInfo))

        if (certInfo & 0x01) == 0x01 || certificateBytes.looksGzipped {
            ok("certificate is gzip-compressed — decompressing")
            let inflated = try certificateBytes.gunzipped()
            info("\(certificateBytes.count) bytes -> \(inflated.count) bytes")
            return inflated
        }
        ok("certificate stored uncompressed (\(certificateBytes.count) bytes)")
        return certificateBytes
    }

    /// Same chunking rules as `PIVReader.sendGeneralAuthenticate`.
    func generalAuthenticate(payload: [UInt8], algorithm: PIVAlgorithm) async throws -> Data {
        let chunkSize = 250
        var offset = 0
        var chunkIndex = 0

        while true {
            let remaining = payload.count - offset
            let isFinal = remaining <= chunkSize
            let length = isFinal ? remaining : chunkSize
            let chunk = Data(payload[offset..<(offset + length)])
            chunkIndex += 1

            info("chunk \(chunkIndex): \(length) bytes, CLA \(isFinal ? "0x00 (final)" : "0x10 (more)")")

            let (response, sw1, sw2) = try await send(
                cla: isFinal ? 0x00 : 0x10,
                ins: 0x87, p1: algorithm.rawValue, p2: 0x9E,
                data: chunk,
                le: isFinal ? 256 : nil
            )
            guard sw1 == 0x90, sw2 == 0x00 else {
                throw ProbeError(String(format: "GENERAL AUTHENTICATE failed on chunk %d: SW %02X%02X", chunkIndex, sw1, sw2))
            }
            if isFinal { return response }
            offset += length
        }
    }
}

// MARK: - VSS

func validateWithVSS(certificateDER: Data) async {
    step("Validating against KeySupport VSS")
    do {
        let response = try await VSSClient().validate(certificateDER: certificateDER)
        if response.validationResult?.result == "SUCCESS" {
            ok("VSS returned SUCCESS")
            info("subject: \(response.x509SubjectName ?? "—")")
            for (index, name) in (response.x509CertificatePath ?? []).enumerated() {
                info("  \(index + 1). \(name)")
            }
        } else {
            let reason = response.validationResult?.invalidityReasonText
                ?? response.error ?? response.message ?? "unknown"
            warn("VSS did not return SUCCESS: \(reason)")
            info("Expected for a self-signed test certificate — it chains to no Federal PKI trust anchor.")
            info("This still exercises the request encoding, JSON contract, and the failure path.")
        }
    } catch {
        fail("VSS call failed: \(error.localizedDescription)")
    }
}

// MARK: - Main

func run() async -> Int32 {
    let args = CommandLine.arguments
    let shouldValidate = args.contains("--validate")

    step("Locating a smart card reader")
    guard let manager = TKSmartCardSlotManager.default else {
        fail("No smart card slot manager. Is this running on macOS with a reader attached?")
        return 1
    }
    let names = manager.slotNames
    guard let slotName = names.first else {
        fail("No readers found. Plug in a CCID reader or a YubiKey.")
        return 1
    }
    for name in names { info("reader: \(name)") }
    ok("using \(slotName)")

    guard let slot = await manager.getSlot(withName: slotName) else {
        fail("Could not open slot \(slotName)")
        return 1
    }
    guard let card = slot.makeSmartCard() else {
        fail("No card present in \(slotName)")
        return 1
    }

    let transport = CardTransport(card: card)

    do {
        guard try await card.beginSession() else {
            fail("Could not begin a card session")
            return 1
        }
        defer { card.endSession() }

        step("Selecting the PIV applet")
        try await transport.selectPIVApplet()
        ok("PIV applet selected")

        step("Reading the Card Authentication certificate (5FC101)")
        let der = try await transport.readCardAuthCertificate()
        let certificate = try PIVCrypto.certificate(fromDER: der)
        ok("parsed a valid X.509 certificate")
        info("subject: \(PIVCrypto.subjectSummary(of: certificate))")
        info("DER: \(hex(der, limit: 16))")

        step("Proof of Possession")
        let challenge = try PIVCrypto.makeChallenge(for: certificate)
        info(String(format: "algorithm reference: 0x%02X", challenge.algorithm.rawValue))
        info("challenge block: \(challenge.challengeBlock.count) bytes")

        var template = try TLV.encode(tag: 0x81, value: [UInt8](challenge.challengeBlock))
        template.append(contentsOf: [0x82, 0x00])
        let payload = try TLV.encode(tag: 0x7C, value: template)
        info("7C template: \(payload.count) bytes\(payload.count > 255 ? " — exceeds a short APDU, chaining" : " — single APDU")")

        let response = try await transport.generalAuthenticate(payload: payload, algorithm: challenge.algorithm)
        let inner = try TLV.value(ofTag: 0x7C, in: [UInt8](response))
        let signature = try TLV.value(ofTag: 0x82, in: inner)
        ok("card returned a \(signature.count)-byte signature")

        if try PIVCrypto.verify(signature: Data(signature), challenge: challenge) {
            ok("\(green)Proof of Possession VERIFIED\(reset) — the card holds the private key")
        } else {
            fail("Proof of Possession FAILED — signature did not verify against the certificate")
            return 1
        }

        if shouldValidate {
            await validateWithVSS(certificateDER: der)
        } else {
            info("(pass --validate to also submit the certificate to the VSS endpoint)")
        }

        print("")
        print("\(green)\(bold)All card operations succeeded.\(reset)")
        return 0

    } catch {
        print("")
        fail(error.localizedDescription)
        return 1
    }
}

exit(await run())
