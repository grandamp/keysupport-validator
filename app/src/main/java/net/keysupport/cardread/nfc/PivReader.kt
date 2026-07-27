package net.keysupport.cardread.nfc

import android.nfc.tech.IsoDep
import android.util.Log
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.zip.GZIPInputStream

class PivReader(private val isoDep: IsoDep) {

    companion object {
        private const val TAG = "PivReader"
        private val PIV_APPLET_AID = byteArrayOf(
            0x00.toByte(), 0xA4.toByte(), 0x04.toByte(), 0x00.toByte(), 0x0B.toByte(),
            0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x03.toByte(), 0x08.toByte(),
            0x00.toByte(), 0x00.toByte(), 0x10.toByte(), 0x00.toByte(), 0x01.toByte(),
            0x00.toByte()
        )
        private val GET_DATA_CARD_AUTH = byteArrayOf(
            0x00.toByte(), 0xCB.toByte(), 0x3F.toByte(), 0xFF.toByte(), 0x05.toByte(),
            0x5C.toByte(), 0x03.toByte(), 0x5F.toByte(), 0xC1.toByte(), 0x01.toByte(),
            0x00.toByte()
        )
        private val GET_DATA_CARD_AUTH_NO_LE = byteArrayOf(
            0x00.toByte(), 0xCB.toByte(), 0x3F.toByte(), 0xFF.toByte(), 0x05.toByte(),
            0x5C.toByte(), 0x03.toByte(), 0x5F.toByte(), 0xC1.toByte(), 0x01.toByte()
        )
    }

    fun readCardAuthCertificate(): ByteArray {
        isoDep.connect()
        try {
            isoDep.timeout = 5000

            val selectResponse = transceive(PIV_APPLET_AID)
            if (!isSuccess(selectResponse)) {
                throw Exception("Failed to select PIV Applet: ${toHex(selectResponse)}")
            }
            Log.d(TAG, "PIV Applet selected successfully")

            var certResponse = transceive(GET_DATA_CARD_AUTH)
            if (!isSuccess(certResponse)) {
                certResponse = transceive(GET_DATA_CARD_AUTH_NO_LE)
                if (!isSuccess(certResponse)) {
                    throw Exception("Failed to get CardAuth certificate: ${toHex(certResponse.takeLast(2).toByteArray())}")
                }
            }

            return extractCertDer(certResponse)
        } finally {
            // Keep connection open for PoP if needed, or caller manages it? 
            // Wait, we need to leave isoDep open for performPoP!
            // Let's remove isoDep.close() from here and let the caller manage it, or we reconnect.
            // Wait, we can't reconnect easily without losing applet selection state.
            // I'll comment out close() here, but we should close it in MainActivity.
        }
    }
    
    fun performPoP(cert: X509Certificate): Boolean {
        val pubKey = cert.publicKey
        val nonce = ByteArray(64)
        SecureRandom().nextBytes(nonce)

        val algRef: Byte
        val challengeBlock: ByteArray
        val sigAlg: String

        if (pubKey is RSAPublicKey) {
            val bitLen = pubKey.modulus.bitLength()
            val keyBytes = bitLen / 8
            val md = MessageDigest.getInstance("SHA-256")
            val hash = md.digest(nonce)
            sigAlg = "SHA256withRSA"
            
            algRef = when (bitLen) {
                2048 -> 0x07.toByte() // 0x07 is RSA 2048 in PIV
                3072 -> 0x05.toByte() // Note: 3072 is typically 0x05 in some specs, but let's check
                else -> throw Exception("Unsupported RSA key size: $bitLen")
            }
            
            val digestInfo = intArrayOf(
                0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
            ).map { it.toByte() }.toByteArray() + hash
            
            challengeBlock = ByteArray(keyBytes)
            challengeBlock[0] = 0x00
            challengeBlock[1] = 0x01
            for (i in 2 until keyBytes - digestInfo.size - 1) {
                challengeBlock[i] = 0xFF.toByte()
            }
            challengeBlock[keyBytes - digestInfo.size - 1] = 0x00
            System.arraycopy(digestInfo, 0, challengeBlock, keyBytes - digestInfo.size, digestInfo.size)
            
        } else if (pubKey is ECPublicKey) {
            val fieldSize = pubKey.params.curve.field.fieldSize
            if (fieldSize <= 256) {
                algRef = 0x11.toByte()
                val md = MessageDigest.getInstance("SHA-256")
                challengeBlock = md.digest(nonce)
                sigAlg = "SHA256withECDSA"
            } else {
                algRef = 0x14.toByte()
                val md = MessageDigest.getInstance("SHA-384")
                challengeBlock = md.digest(nonce)
                sigAlg = "SHA384withECDSA"
            }
        } else {
            throw Exception("Unsupported key type: ${pubKey.algorithm}")
        }

        val tlv = ByteArrayOutputStream()
        tlv.write(0x7C)
        val len81 = challengeBlock.size
        val len81Size = if (len81 < 0x80) 1 else if (len81 <= 0xFF) 2 else 3
        val totalLen = 1 + len81Size + len81 + 2
        writeTlvLength(tlv, totalLen)
        
        tlv.write(0x81)
        writeTlvLength(tlv, len81)
        tlv.write(challengeBlock)
        
        tlv.write(0x82)
        tlv.write(0x00)
        
        val payload = tlv.toByteArray()
        
        val resp = sendGeneralAuthenticate(algRef, payload)
        if (!isSuccess(resp)) {
            throw Exception("GENERAL AUTHENTICATE failed: ${toHex(resp.takeLast(2).toByteArray())}")
        }
        
        val sigBytes = extractSignatureFrom7C(resp)
        
        val sig = Signature.getInstance(sigAlg)
        sig.initVerify(pubKey)
        sig.update(nonce)
        return sig.verify(sigBytes)
    }

    private fun sendGeneralAuthenticate(algRef: Byte, payload: ByteArray): ByteArray {
        if (payload.size <= 250) {
            val cmd = ByteArrayOutputStream()
            cmd.write(byteArrayOf(0x00, 0x87.toByte(), algRef, 0x9E.toByte(), payload.size.toByte()))
            cmd.write(payload)
            cmd.write(0x00)
            return transceive(cmd.toByteArray())
        } else if (isoDep.isExtendedLengthApduSupported) {
            val cmd = ByteArrayOutputStream()
            cmd.write(byteArrayOf(0x00, 0x87.toByte(), algRef, 0x9E.toByte(), 0x00))
            cmd.write((payload.size shr 8) and 0xFF)
            cmd.write(payload.size and 0xFF)
            cmd.write(payload)
            cmd.write(0x00)
            cmd.write(0x00)
            return transceive(cmd.toByteArray())
        } else {
            var offset = 0
            var resp = ByteArray(0)
            while (offset < payload.size) {
                val isLast = (payload.size - offset) <= 250
                val chunkLen = if (isLast) payload.size - offset else 250
                val cla = if (isLast) 0x00.toByte() else 0x10.toByte()
                
                val cmd = ByteArrayOutputStream()
                cmd.write(byteArrayOf(cla, 0x87.toByte(), algRef, 0x9E.toByte(), chunkLen.toByte()))
                cmd.write(payload, offset, chunkLen)
                if (isLast) cmd.write(0x00)
                
                resp = transceive(cmd.toByteArray())
                if (!isSuccess(resp) && !isLast) {
                    throw Exception("Chaining failed: ${toHex(resp)}")
                }
                offset += chunkLen
            }
            return resp
        }
    }

    private fun extractSignatureFrom7C(response: ByteArray): ByteArray {
        var offset = 0
        if (response[offset] != 0x7C.toByte()) throw Exception("Expected Tag 7C in Auth response")
        offset++
        offset += getTlvLengthSize(response, offset)
        
        if (response[offset] != 0x82.toByte()) throw Exception("Expected Tag 82 in Auth response")
        offset++
        
        val sigLen = getTlvLength(response, offset)
        val lenSize = getTlvLengthSize(response, offset)
        offset += lenSize
        
        return response.copyOfRange(offset, offset + sigLen)
    }

    private fun writeTlvLength(out: ByteArrayOutputStream, length: Int) {
        if (length < 0x80) {
            out.write(length)
        } else if (length <= 0xFF) {
            out.write(0x81)
            out.write(length)
        } else if (length <= 0xFFFF) {
            out.write(0x82)
            out.write(length shr 8)
            out.write(length and 0xFF)
        } else {
            throw IllegalArgumentException("Length too large")
        }
    }

    private fun transceive(command: ByteArray): ByteArray {
        var response = isoDep.transceive(command)
        Log.d(TAG, "Command: ${toHex(command)}")
        Log.d(TAG, "Response: ${toHex(response)}")
        
        val result = ByteArrayOutputStream()
        
        while (true) {
            val sw1 = response[response.size - 2].toInt() and 0xFF
            val sw2 = response[response.size - 1].toInt() and 0xFF

            if (sw1 == 0x61) {
                result.write(response, 0, response.size - 2)
                val getResponseCmd = byteArrayOf(0x00.toByte(), 0xC0.toByte(), 0x00.toByte(), 0x00.toByte(), sw2.toByte())
                response = isoDep.transceive(getResponseCmd)
            } else if (sw1 == 0x6C) {
                val reissueCmd = command.copyOf(command.size + 1)
                reissueCmd[reissueCmd.size - 1] = sw2.toByte()
                response = isoDep.transceive(reissueCmd)
            } else {
                if (response.size >= 2) {
                    result.write(response, 0, response.size - 2)
                    result.write(response, response.size - 2, 2)
                } else {
                    result.write(response)
                }
                break
            }
        }
        return result.toByteArray()
    }

    private fun isSuccess(response: ByteArray): Boolean {
        if (response.size < 2) return false
        val sw1 = response[response.size - 2].toInt() and 0xFF
        val sw2 = response[response.size - 1].toInt() and 0xFF
        return sw1 == 0x90 && sw2 == 0x00
    }

    private fun extractCertDer(response: ByteArray): ByteArray {
        var offset = 0
        if (response[offset] != 0x53.toByte()) throw Exception("Expected Tag 53, got ${toHex(byteArrayOf(response[offset]))}")
        offset++
        offset += getTlvLengthSize(response, offset)

        if (response[offset] != 0x70.toByte()) {
             var found70 = false
             while (offset < response.size - 4) {
                 if (response[offset] == 0x70.toByte()) {
                     found70 = true
                     break
                 }
                 val tag = response[offset]
                 offset++
                 val len = getTlvLength(response, offset)
                 val lenSize = getTlvLengthSize(response, offset)
                 offset += lenSize + len
             }
             if (!found70) {
                 throw Exception("Expected Tag 70 not found in payload")
             }
        }
        offset++
        
        val certLength = getTlvLength(response, offset)
        val lenSize = getTlvLengthSize(response, offset)
        offset += lenSize
        
        val certBytes = response.copyOfRange(offset, offset + certLength)
        
        if (certBytes.size > 2 && certBytes[0] == 0x1F.toByte() && certBytes[1] == 0x8B.toByte()) {
            val gis = GZIPInputStream(ByteArrayInputStream(certBytes))
            val decompressed = gis.readBytes()
            gis.close()
            return decompressed
        }
        
        if (certBytes.size > 0 && certBytes[0] != 0x30.toByte()) {
            throw Exception("Expected X.509 DER Sequence (0x30) or Gzip (0x1F) but got ${toHex(byteArrayOf(certBytes[0]))}")
        }
        
        return certBytes
    }

    private fun getTlvLength(data: ByteArray, offset: Int): Int {
        val lenByte = data[offset].toInt() and 0xFF
        if (lenByte < 0x80) return lenByte
        val numBytes = lenByte and 0x7F
        var length = 0
        for (i in 1..numBytes) {
            length = (length shl 8) or (data[offset + i].toInt() and 0xFF)
        }
        return length
    }

    private fun getTlvLengthSize(data: ByteArray, offset: Int): Int {
        val lenByte = data[offset].toInt() and 0xFF
        if (lenByte < 0x80) return 1
        return 1 + (lenByte and 0x7F)
    }

    private fun toHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02X".format(it) }
    }
}
