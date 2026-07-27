package net.keysupport.cardread.network

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import retrofit2.http.Body
import retrofit2.http.POST
import java.util.concurrent.TimeUnit

@Serializable
data class VssRequest(
    val validationPolicyId: String,
    val x509Certificate: String
)

@Serializable
data class ValidationResult(
    val result: String? = null,
    val isAffirmativelyInvalid: Boolean? = null,
    val invalidityReasonText: String? = null
)

@Serializable
data class VssResponse(
    val validationPolicyId: String? = null,
    val x509SubjectName: String? = null,
    val x509CertificatePath: List<String>? = null,
    val error: String? = null,
    val status: String? = null,
    val message: String? = null,
    val validationResult: ValidationResult? = null
)

interface VssApi {
    @POST("vss/v2/validate")
    suspend fun validateCertificate(@Body request: VssRequest): VssResponse
}

object VssClient {
    private val logging = HttpLoggingInterceptor().apply {
        level = HttpLoggingInterceptor.Level.BODY
    }
    
    private val client = OkHttpClient.Builder()
        .addInterceptor(logging)
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()
        
    private val json = Json { ignoreUnknownKeys = true }
    
    val api: VssApi by lazy {
        Retrofit.Builder()
            .baseUrl("https://home.keysupport.net/")
            .client(client)
            .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
            .build()
            .create(VssApi::class.java)
    }
}
