package com.projectkepler.burp

import burp.api.montoya.http.message.HttpRequestResponse
import java.util.Base64
import java.util.UUID

/**
 * Data class representing a captured attack entry.
 * Why: Using a data class provides automatic equals(), hashCode(), and toString() implementations,
 * making state management and comparison within the UI and storage layers more reliable.
 */
data class AttackEntry(
    val id: String = UUID.randomUUID().toString(),
    val host: String,
    val port: Int,
    val protocol: String,
    val method: String,
    val url: String,
    val requestBase64: String?,
    val responseBase64: String?,
    val timestamp: Long = System.currentTimeMillis(),
    val testerName: String,
    val category: String,
    val status: String,
    val notes: String,
    var deleted: Boolean = false
) {
    /**
     * Secondary constructor for creating an entry from Montoya's HttpRequestResponse.
     * Why: This separates the Burp-specific API logic from the core data model.
     * It extracts the necessary service and message details for persistent storage.
     */
    constructor(
        message: HttpRequestResponse,
        testerName: String,
        category: String,
        status: String,
        notes: String
    ) : this(
        host = message.httpService().host(),
        port = message.httpService().port(),
        protocol = if (message.httpService().secure()) "https" else "http",
        method = message.request().method(),
        url = message.request().url(),
        requestBase64 = Base64.getEncoder().encodeToString(message.request().toByteArray().getBytes()),
        responseBase64 = message.response()?.let { Base64.getEncoder().encodeToString(it.toByteArray().getBytes()) },
        testerName = testerName,
        category = category,
        status = status,
        notes = notes
    )

    /**
     * Decodes the Base64 request into a byte array.
     */
    fun getRequestBytes(): ByteArray? = requestBase64?.let { Base64.getDecoder().decode(it) }

    /**
     * Decodes the Base64 response into a byte array.
     */
    fun getResponseBytes(): ByteArray? = responseBase64?.let { Base64.getDecoder().decode(it) }

    /**
     * Security check: Ensure ID is never empty for storage indexing.
     */
    fun hasValidId(): Boolean = id.isNotEmpty()
}
