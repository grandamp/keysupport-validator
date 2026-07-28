package net.keysupport.cardread

import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

data class CredentialRow(val label: String, val value: String)

object CredentialDetails {
    fun getRows(cert: X509Certificate, checkDate: Date? = null): List<CredentialRow> {
        val rows = mutableListOf<CredentialRow>()

        // Subject Attributes
        val subjectDn = cert.subjectX500Principal.name
        val parsedDn = parseDn(subjectDn)
        
        parsedDn.firstOrNull { it.first == "SERIALNUMBER" }?.let { rows.add(CredentialRow("CARD SERIAL", it.second)) }
        parsedDn.filter { it.first == "OU" }.forEach { (_, value) ->
            rows.add(CredentialRow("ORGANIZATIONAL UNIT", value))
        }
        parsedDn.firstOrNull { it.first == "O" }?.let { rows.add(CredentialRow("ORGANIZATION", it.second)) }
        parsedDn.firstOrNull { it.first == "C" }?.let { rows.add(CredentialRow("COUNTRY", it.second)) }

        // Key Info
        val pubKey = cert.publicKey
        val keyDesc = when (pubKey) {
            is RSAPublicKey -> "RSA ${pubKey.modulus.bitLength()}"
            is ECPublicKey -> "ECC P-${pubKey.params.curve.field.fieldSize}"
            else -> pubKey.algorithm
        }
        rows.add(CredentialRow("KEY", keyDesc))

        // Validity Dates
        val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm 'UTC'", Locale.US)
        dateFormat.timeZone = TimeZone.getTimeZone("UTC")
        
        rows.add(CredentialRow("VALID FROM", dateFormat.format(cert.notBefore)))
        rows.add(CredentialRow("VALID UNTIL", dateFormat.format(cert.notAfter)))
        
        if (checkDate != null) {
            rows.add(CredentialRow("CHECKED", dateFormat.format(checkDate)))
        }

        return rows
    }

    private fun parseDn(dn: String): List<Pair<String, String>> {
        // Basic naive RFC 4514 split by comma, ignoring escaped commas.
        // In a real app we might want a proper LdapName parser, but this works for standard Federal subjects.
        val pairs = mutableListOf<Pair<String, String>>()
        val parts = dn.split("(?<!\\\\),".toRegex()).map { it.trim() }
        for (part in parts) {
            val splitIdx = part.indexOf('=')
            if (splitIdx > 0) {
                val key = part.substring(0, splitIdx).trim()
                val value = part.substring(splitIdx + 1).replace("\\,", ",").trim()
                pairs.add(key to value)
            }
        }
        // DNs are usually reversed (most specific to least). The iOS app seems to print them in the order they appear.
        // Wait, standard X500Principal returns them in reverse. We will reverse it so serial is first.
        return pairs.reversed()
    }
}
