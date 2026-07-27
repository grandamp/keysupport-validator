package net.keysupport.cardread

import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.provider.Settings
import android.util.Base64
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.keysupport.cardread.network.VssClient
import net.keysupport.cardread.network.VssRequest
import net.keysupport.cardread.nfc.PivReader
import net.keysupport.cardread.ui.theme.CardReadTheme
import java.io.ByteArrayInputStream
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class MainActivity : ComponentActivity(), NfcAdapter.ReaderCallback {

    private var nfcAdapter: NfcAdapter? = null
    
    private var uiState by mutableStateOf<ScanState>(ScanState.Idle)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        
        setContent {
            CardReadTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    MainScreen(
                        state = uiState,
                        onOpenSettings = {
                            startActivity(Intent(Settings.ACTION_NFC_SETTINGS))
                        },
                        modifier = Modifier.padding(innerPadding)
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (nfcAdapter?.isEnabled != true) {
            uiState = ScanState.NfcDisabled
        } else {
            if (uiState is ScanState.NfcDisabled) {
                uiState = ScanState.Idle
            }
            nfcAdapter?.enableReaderMode(
                this,
                this,
                NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                null
            )
        }
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableReaderMode(this)
    }

    override fun onTagDiscovered(tag: Tag?) {
        if (tag == null) return
        
        uiState = ScanState.Scanning
        
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val isoDep = IsoDep.get(tag)
                if (isoDep != null) {
                    val reader = PivReader(isoDep)
                    val certBytes = reader.readCardAuthCertificate()
                    
                    val factory = CertificateFactory.getInstance("X.509")
                    val cert = factory.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
                    
                    withContext(Dispatchers.Main) {
                        uiState = ScanState.ScanningPoP
                    }

                    val isPopValid = reader.performPoP(cert)
                    
                    if (!isPopValid) {
                        withContext(Dispatchers.Main) {
                            uiState = ScanState.Error("Proof of Possession signature validation failed.", "PoP Failed")
                        }
                        return@launch
                    }

                    withContext(Dispatchers.Main) {
                        uiState = ScanState.ValidatingNetwork
                    }

                    val base64Cert = Base64.encodeToString(certBytes, Base64.NO_WRAP)
                    val request = VssRequest(validationPolicyId = "2.16.840.1.101.10.2.18.2.2.1", x509Certificate = base64Cert)

                    val response = try {
                        VssClient.api.validateCertificate(request)
                    } catch (e: UnknownHostException) {
                        withContext(Dispatchers.Main) { uiState = ScanState.Error("No Internet Connection", "Network Error") }
                        return@launch
                    } catch (e: ConnectException) {
                        withContext(Dispatchers.Main) { uiState = ScanState.Error("Could not connect to validation server", "Network Error") }
                        return@launch
                    } catch (e: SocketTimeoutException) {
                        withContext(Dispatchers.Main) { uiState = ScanState.Error("Connection to server timed out", "Network Error") }
                        return@launch
                    } catch (e: Exception) {
                        withContext(Dispatchers.Main) { uiState = ScanState.Error("Network Error: ${e.message}", "Error") }
                        return@launch
                    }

                    withContext(Dispatchers.Main) {
                        if (response.validationResult?.result == "SUCCESS") {
                            uiState = ScanState.Success(
                                subject = response.x509SubjectName ?: cert.subjectX500Principal.name,
                                path = response.x509CertificatePath
                            )
                        } else {
                            val reason = response.validationResult?.invalidityReasonText
                                ?: response.error
                                ?: response.message
                                ?: "Revoked/Expired"
                                
                            val title = when {
                                reason.contains("revoked", ignoreCase = true) -> "Revoked"
                                reason.contains("NotAfter", ignoreCase = true) || reason.contains("expired", ignoreCase = true) -> "Expired"
                                else -> "Validation Error"
                            }
                                
                            uiState = ScanState.Error("Credential Validation Failed: $reason", title)
                        }
                    }

                } else {
                    withContext(Dispatchers.Main) {
                        uiState = ScanState.Error("Card does not support IsoDep")
                    }
                }
            } catch (e: Exception) {
                Log.e("MainActivity", "NFC Read Error", e)
                withContext(Dispatchers.Main) {
                    uiState = ScanState.Error(e.message ?: "Unknown Error", "Read Error")
                }
            }
        }
    }
}

sealed class ScanState {
    object Idle : ScanState()
    object NfcDisabled : ScanState()
    object Scanning : ScanState()
    object ScanningPoP : ScanState()
    object ValidatingNetwork : ScanState()
    data class Success(val subject: String, val path: List<String>?) : ScanState()
    data class Error(val message: String, val title: String = "Error") : ScanState()
}

@Composable
fun MainScreen(state: ScanState, onOpenSettings: () -> Unit, modifier: Modifier = Modifier) {
    val haptic = LocalHapticFeedback.current

    LaunchedEffect(state) {
        if (state is ScanState.Success || state is ScanState.Error) {
            // Trigger a haptic bump when reaching a final result state
            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
        }
    }

    val backgroundColor = when (state) {
        is ScanState.Idle, is ScanState.NfcDisabled -> androidx.compose.material3.MaterialTheme.colorScheme.background
        is ScanState.Scanning, is ScanState.ScanningPoP, is ScanState.ValidatingNetwork -> androidx.compose.material3.MaterialTheme.colorScheme.surfaceVariant
        is ScanState.Success -> Color(0xFFE8F5E9)
        is ScanState.Error -> Color(0xFFFFEBEE)
    }

    val textColor = when (state) {
        is ScanState.Idle, is ScanState.NfcDisabled -> androidx.compose.material3.MaterialTheme.colorScheme.onBackground
        is ScanState.Scanning, is ScanState.ScanningPoP, is ScanState.ValidatingNetwork -> androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant
        is ScanState.Success -> Color(0xFF1B5E20)
        is ScanState.Error -> Color(0xFFB71C1C)
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(backgroundColor),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(16.dp)) {
            when (state) {
                is ScanState.NfcDisabled -> {
                    Text("NFC is Disabled", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = textColor)
                    Text("Please enable NFC to scan credentials", modifier = Modifier.padding(top = 8.dp, bottom = 16.dp), color = textColor)
                    Button(onClick = onOpenSettings) {
                        Text("Open Settings")
                    }
                }
                is ScanState.Idle -> {
                    Text("Ready to Scan", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = textColor)
                    Text("Tap PIV/TWIC card to the back of the device", modifier = Modifier.padding(top = 8.dp), color = textColor)
                }
                is ScanState.Scanning -> {
                    Text("Reading Certificate...", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = textColor)
                }
                is ScanState.ScanningPoP -> {
                    Text("Verifying Smart Card...", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = textColor)
                    Text("Performing Proof of Possession", modifier = Modifier.padding(top = 8.dp), color = textColor)
                }
                is ScanState.ValidatingNetwork -> {
                    Text("Validating Card Authentication Certificate", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = textColor)
                    CircularProgressIndicator(modifier = Modifier.padding(top = 16.dp), color = textColor)
                }
                is ScanState.Success -> {
                    Text("Proof of Possession Success!", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = textColor)
                    Text(state.subject, modifier = Modifier.padding(top = 16.dp), color = textColor)

                    if (!state.path.isNullOrEmpty()) {
                        var expanded by remember { mutableStateOf(false) }
                        
                        Spacer(modifier = Modifier.height(24.dp))
                        
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { expanded = !expanded },
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFC8E6C9))
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text("Certificate Path (Tap to ${if (expanded) "collapse" else "expand"})", fontWeight = FontWeight.Bold, color = textColor)
                                if (expanded) {
                                    Spacer(modifier = Modifier.height(8.dp))
                                    state.path.forEachIndexed { index, certName ->
                                        Text("${index + 1}. $certName", fontSize = 12.sp, color = textColor, modifier = Modifier.padding(bottom = 4.dp))
                                    }
                                }
                            }
                        }
                    }
                }
                is ScanState.Error -> {
                    Text(state.title, fontSize = 24.sp, fontWeight = FontWeight.Bold, color = textColor)
                    Text(state.message, modifier = Modifier.padding(top = 16.dp), color = textColor)
                }
            }
        }
    }
}
