package com.projectkepler.burp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.util.Base64

/**
 * Simple unit tests for AttackEntry using standard JUnit assertions.
 * Why: Validates core data class functionality and Base64 encoding/decoding.
 * Security Implication: Ensures attack data integrity during persistence.
 */
class SimpleAttackEntryTest {

    @Test
    fun `should generate unique IDs for different instances`() {
        val entry1 = AttackEntry(
            host = "example.com",
            port = 443,
            protocol = "https",
            method = "POST",
            url = "/api/login",
            requestBase64 = "QUJD",
            responseBase64 = "REVG",
            testerName = "alice",
            category = "XSS",
            status = "Vulnerable",
            notes = "Test entry"
        )

        val entry2 = AttackEntry(
            host = "example.com",
            port = 443,
            protocol = "https",
            method = "POST",
            url = "/api/login",
            requestBase64 = "QUJD",
            responseBase64 = "REVG",
            testerName = "alice",
            category = "XSS",
            status = "Vulnerable",
            notes = "Test entry"
        )

        // Why: Ensure each attack gets a unique ID even with identical data
        // Security Implication: Prevents data corruption when storing/retrieving attacks
        assertNotEquals(entry1.id, entry2.id)
        assertTrue(entry1.id.isNotEmpty())
        assertTrue(entry2.id.isNotEmpty())
    }

    @Test
    fun `should handle null request and response gracefully`() {
        val entry = AttackEntry(
            host = "example.com",
            port = 80,
            protocol = "http",
            method = "GET",
            url = "/",
            requestBase64 = null,
            responseBase64 = null,
            testerName = "bob",
            category = "IDOR",
            status = "Safe",
            notes = ""
        )

        // Why: Null-safety test - prevents NPE when Burp returns null traffic
        assertNull(entry.requestBase64)
        assertNull(entry.responseBase64)
        assertNull(entry.getRequestBytes())
        assertNull(entry.getResponseBytes())
    }

    @Test
    fun `should correctly decode Base64 request bytes`() {
        val originalData = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        val base64Encoded = Base64.getEncoder().encodeToString(originalData.toByteArray())

        val entry = AttackEntry(
            host = "example.com",
            port = 443,
            protocol = "https",
            method = "GET",
            url = "/",
            requestBase64 = base64Encoded,
            responseBase64 = null,
            testerName = "tester",
            category = "SQL Injection",
            status = "Needs Investigation",
            notes = "Testing Base64 decoding"
        )

        val decoded = entry.getRequestBytes()

        // Why: Verify Base64 encoding/decoding preserves binary data
        // Security Implication: Ensures captured traffic is not corrupted during storage
        assertNotNull(decoded)
        assertEquals(originalData, String(decoded!!))
    }

    @Test
    fun `should correctly decode Base64 response bytes`() {
        val originalResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Response</html>"
        val base64Encoded = Base64.getEncoder().encodeToString(originalResponse.toByteArray())

        val entry = AttackEntry(
            host = "evil.com",
            port = 443,
            protocol = "https",
            method = "POST",
            url = "/admin",
            requestBase64 = "QUJD",
            responseBase64 = base64Encoded,
            testerName = "hacker",
            category = "Auth Bypass",
            status = "Vulnerable",
            notes = "Critical finding"
        )

        val decoded = entry.getResponseBytes()

        assertNotNull(decoded)
        assertEquals(originalResponse, String(decoded!!))
    }

    @Test
    fun `should validate ID is not empty`() {
        val entry = AttackEntry(
            id = "test-123",
            host = "target.com",
            port = 8080,
            protocol = "http",
            method = "PUT",
            url = "/api/users/1",
            requestBase64 = "data",
            responseBase64 = "response",
            testerName = "pentester",
            category = "CSRF",
            status = "Vulnerable",
            notes = "CSRF token missing"
        )

        // Why: Ensure storage indexing never breaks due to empty IDs
        assertTrue(entry.hasValidId())
        assertEquals("test-123", entry.id)
    }

    @Test
    fun `should detect invalid empty ID`() {
        val entry = AttackEntry(
            id = "",
            host = "target.com",
            port = 443,
            protocol = "https",
            method = "DELETE",
            url = "/api/users/admin",
            requestBase64 = null,
            responseBase64 = null,
            testerName = "tester",
            category = "Other",
            status = "Safe",
            notes = ""
        )

        assertFalse(entry.hasValidId())
    }

    @Test
    fun `should default deleted flag to false`() {
        val entry = AttackEntry(
            host = "newsite.com",
            port = 443,
            protocol = "https",
            method = "GET",
            url = "/",
            requestBase64 = null,
            responseBase64 = null,
            testerName = "analyst",
            category = "Information Disclosure",
            status = "Needs Investigation",
            notes = "Initial recon"
        )

        assertFalse(entry.deleted)
    }

    @Test
    fun `should allow mutable deleted flag`() {
        val entry = AttackEntry(
            host = "testsite.com",
            port = 80,
            protocol = "http",
            method = "POST",
            url = "/upload",
            requestBase64 = "data",
            responseBase64 = "resp",
            testerName = "tester",
            category = "RCE",
            status = "Vulnerable",
            notes = "File upload vulnerability"
        )

        entry.deleted = true
        assertTrue(entry.deleted)

        entry.deleted = false
        assertFalse(entry.deleted)
    }

    @Test
    fun `should preserve timestamp if provided`() {
        val customTimestamp = 1234567890L
        val entry = AttackEntry(
            host = "archive.com",
            port = 443,
            protocol = "https",
            method = "GET",
            url = "/old-data",
            requestBase64 = null,
            responseBase64 = null,
            timestamp = customTimestamp,
            testerName = "archiver",
            category = "Other",
            status = "Safe",
            notes = "Historical data"
        )

        assertEquals(customTimestamp, entry.timestamp)
    }

    @Test
    fun `should generate current timestamp by default`() {
        val before = System.currentTimeMillis()
        val entry = AttackEntry(
            host = "realtime.com",
            port = 443,
            protocol = "https",
            method = "GET",
            url = "/live",
            requestBase64 = null,
            responseBase64 = null,
            testerName = "live-tester",
            category = "XSS",
            status = "Safe",
            notes = "Real-time test"
        )
        val after = System.currentTimeMillis()

        // Why: Verify timestamp is automatically set to current time
        assertTrue(entry.timestamp >= before)
        assertTrue(entry.timestamp <= after)
    }

    @Test
    fun `should handle binary data in Base64 encoding`() {
        // Simulate binary data (e.g., PNG header)
        val binaryData = byteArrayOf(
            0x89.toByte(), 0x50, 0x4E, 0x47, // PNG header
            0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x0D
        )
        val base64Binary = Base64.getEncoder().encodeToString(binaryData)

        val entry = AttackEntry(
            host = "media.com",
            port = 443,
            protocol = "https",
            method = "GET",
            url = "/image.png",
            requestBase64 = base64Binary,
            responseBase64 = null,
            testerName = "tester",
            category = "Other",
            status = "Safe",
            notes = "Binary content test"
        )

        val decoded = entry.getRequestBytes()

        // Why: Ensure binary data (images, compressed files) is preserved exactly
        // Security Implication: Prevents corruption of captured binary traffic
        assertNotNull(decoded)
        assertArrayEquals(binaryData, decoded)
    }

    @Test
    fun `data class should provide working equals and hashCode`() {
        val entry1 = AttackEntry(
            id = "same-id",
            host = "test.com",
            port = 443,
            protocol = "https",
            method = "GET",
            url = "/test",
            requestBase64 = "ABC",
            responseBase64 = "DEF",
            timestamp = 1000L,
            testerName = "tester",
            category = "XSS",
            status = "Safe",
            notes = "note",
            deleted = false
        )

        val entry2 = entry1.copy()

        // Why: Data classes provide automatic equals/hashCode for reliable comparisons
        assertEquals(entry1, entry2)
        assertEquals(entry1.hashCode(), entry2.hashCode())
    }

    @Test
    fun `should support copy with modifications`() {
        val original = AttackEntry(
            host = "original.com",
            port = 443,
            protocol = "https",
            method = "GET",
            url = "/",
            requestBase64 = null,
            responseBase64 = null,
            testerName = "original",
            category = "SQL Injection",
            status = "Safe",
            notes = "original notes"
        )

        val modified = original.copy(
            testerName = "modified",
            notes = "updated notes"
        )

        // Why: Verify copy() preserves all fields except modified ones
        assertEquals("original.com", modified.host)
        assertEquals("modified", modified.testerName)
        assertEquals("updated notes", modified.notes)
        assertEquals(original.id, modified.id)
    }
}
