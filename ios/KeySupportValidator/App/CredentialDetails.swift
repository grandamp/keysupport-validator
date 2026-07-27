import Foundation

/// Everything known about a credential that passed validation.
struct CredentialSummary: Equatable {
    /// Subject distinguished name, as returned by VSS.
    let subject: String
    /// Trust chain from VSS. May be empty — at least one production card has
    /// validated SUCCESS with no path attached.
    let certificatePath: [String]
    /// "RSA 2048", "ECC P-256" — read from the certificate's public key.
    let keyDescription: String?
    let notBefore: Date?
    let notAfter: Date?
    /// When validation completed, so a screenshot of a green screen is not
    /// ambiguous about when it was taken.
    let checkedAt: Date
}

//
// ═══════════════════════════════════════════════════════════════════════════
//  THIS IS THE FILE TO EDIT TO CHANGE WHAT THE SUCCESS SCREEN SHOWS.
//
//  Every row beneath the two green check marks is produced by `rows(for:)`
//  below. To tune the screen:
//
//    • hide a row      → delete or comment out its `add(...)` line
//    • reorder rows    → move the `add(...)` lines
//    • rename a label  → edit the string in the `add(...)` call
//    • add a new row   → one more `add(...)` line; nil values drop out on
//                        their own, so no availability checks are needed
//
//  Nothing outside this file needs to change for any of that. `ContentView`
//  renders whatever list comes back, in order.
// ═══════════════════════════════════════════════════════════════════════════
//
enum CredentialDetails {

    struct Detail: Identifiable, Equatable {
        let id = UUID()
        let label: String
        let value: String

        static func == (a: Detail, b: Detail) -> Bool {
            a.label == b.label && a.value == b.value
        }
    }

    /// Ordered rows for the success screen.
    static func rows(for summary: CredentialSummary) -> [Detail] {
        var rows: [Detail] = []

        /// Appends a row, skipping it entirely when the value is nil or blank.
        func add(_ label: String, _ value: String?) {
            guard let value, !value.trimmingCharacters(in: .whitespaces).isEmpty else { return }
            rows.append(Detail(label: label, value: value))
        }

        // ─── Subject, split from DN syntax into its individual attributes ───
        // Card Serial, Organizational Unit (often twice), Organization, Country…
        for field in DistinguishedName(summary.subject).fields {
            add(field.label, field.value)
        }

        // ─── Certificate facts ───
        add("Key", summary.keyDescription)
        add("Issued By", issuer(from: summary.certificatePath))
        add("Valid From", summary.notBefore.map(format))
        add("Valid Until", summary.notAfter.map(format))

        // ─── Provenance of this check ───
        add("Checked", format(summary.checkedAt))

        return rows
    }

    /// The issuing CA, taken as the entry directly above the leaf in the chain
    /// VSS returns. Nil when the path is absent or holds only the leaf — the
    /// certificate's own issuer field is an ASN.1 `Name`, and decoding it would
    /// cost far more than this row is worth.
    static func issuer(from path: [String]) -> String? {
        guard path.count >= 2 else { return nil }
        return path[path.count - 2]
    }

    static func format(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm 'UTC'"
        formatter.timeZone = TimeZone(identifier: "UTC")
        return formatter.string(from: date)
    }
}
