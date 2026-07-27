import Foundation

/// Splits an RFC 4514 distinguished name into ordered, human-labelled fields.
///
/// VSS returns the subject as a single string such as:
///
///     SERIALNUMBER=00000000000000, OU=Example Bureau,
///     OU=Example Department, O=Example Organization, C=ZZ
///
/// Rendering that verbatim gives the reader a wall of X.500 syntax to decode.
/// Splitting it into labelled rows costs nothing and makes the identity legible
/// at a glance, which matters for a screen whose whole job is answering
/// "whose card is this, and is it good?".
struct DistinguishedName {

    struct Field: Identifiable {
        let id = UUID()
        let label: String
        let value: String
    }

    let fields: [Field]

    /// True when the string could not be parsed as a DN at all, in which case
    /// callers should fall back to showing it raw rather than showing nothing.
    var isEmpty: Bool { fields.isEmpty }

    init(_ dn: String) {
        // Split on commas that are not backslash-escaped. RFC 4514 permits
        // "Dept of Something\, Inc" inside a single value.
        var parts: [String] = []
        var current = ""
        var escaped = false

        for character in dn {
            if escaped {
                current.append(character)
                escaped = false
            } else if character == "\\" {
                escaped = true
            } else if character == "," {
                parts.append(current)
                current = ""
            } else {
                current.append(character)
            }
        }
        if !current.isEmpty { parts.append(current) }

        fields = parts.compactMap { part in
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            guard let separator = trimmed.firstIndex(of: "=") else { return nil }

            let attribute = trimmed[trimmed.startIndex..<separator]
                .trimmingCharacters(in: .whitespaces)
                .uppercased()
            let value = trimmed[trimmed.index(after: separator)...]
                .trimmingCharacters(in: .whitespaces)

            guard !attribute.isEmpty, !value.isEmpty else { return nil }
            return Field(label: Self.label(for: attribute), value: String(value))
        }
    }

    /// Maps X.500 attribute types to plain English. Unknown types keep their
    /// original name rather than being dropped — an unexpected attribute is
    /// still information.
    private static func label(for attribute: String) -> String {
        switch attribute {
        case "CN":                      return "Name"
        case "SERIALNUMBER":            return "Card Serial"
        case "OU":                      return "Organizational Unit"
        case "O":                       return "Organization"
        case "C":                       return "Country"
        case "L":                       return "Locality"
        case "ST", "S":                 return "State"
        case "E", "EMAIL", "EMAILADDRESS": return "Email"
        case "T", "TITLE":              return "Title"
        case "GIVENNAME", "G":          return "Given Name"
        case "SURNAME", "SN":           return "Surname"
        case "DC":                      return "Domain Component"
        case "UID":                     return "User ID"
        default:                        return attribute
        }
    }
}
