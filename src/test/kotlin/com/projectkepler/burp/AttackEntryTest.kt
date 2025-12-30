package com.projectkepler.burp

import burp.api.montoya.http.HttpService

import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.core.ByteArray
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.mockk.every
import io.mockk.mockk

class AttackEntryTest : BehaviorSpec({

    Given("A raw HTTP RequestResponse") {
        val mockReqResp = mockk<HttpRequestResponse>()
        val mockReq = mockk<HttpRequest>()
        val mockResp = mockk<HttpResponse>()
        val mockService = mockk<HttpService>()

        // Mock HttpService
        every { mockReqResp.httpService() } returns mockService
        every { mockService.host() } returns "example.com"
        every { mockService.port() } returns 443
        every { mockService.secure() } returns true

        // Helper to mock ByteArray since static factory fails in tests
        fun mockByteArray(bytes: kotlin.ByteArray): ByteArray {
            val mock = mockk<ByteArray>()
            every { mock.getBytes() } returns bytes
            every { mock.length() } returns bytes.size
            every { mock.toString() } returns String(bytes)
            return mock
        }

        // Mock Request
        val reqBytes = "GET / HTTP/1.1".toByteArray()
        every { mockReqResp.request() } returns mockReq
        every { mockReq.method() } returns "GET"
        every { mockReq.url() } returns "https://example.com/"
        every { mockReq.toByteArray() } returns mockByteArray(reqBytes)

        // Mock Response
        val respBytes = "HTTP/1.1 200 OK".toByteArray()
        every { mockReqResp.response() } returns mockResp
        every { mockResp.toByteArray() } returns mockByteArray(respBytes)

        When("AttackEntry is created from the message") {
            val entry = AttackEntry(
                message = mockReqResp,
                testerName = "TestUser",
                category = "SQLi",
                status = "Vulnerable",
                notes = "Test Notes"
            )

            Then("It should correctly extract properties") {
                entry.host shouldBe "example.com"
                entry.port shouldBe 443
                entry.protocol shouldBe "https"
                entry.method shouldBe "GET"
                entry.testerName shouldBe "TestUser"
            }

            Then("It should encode request and response to Base64") {
                entry.requestBase64.shouldNotBeNull()
                entry.responseBase64.shouldNotBeNull()
            }

            Then("It should generate a valid UUID") {
                entry.id.shouldNotBeEmpty()
                entry.hasValidId() shouldBe true
            }

            Then("It can decode the Base64 bytes back") {
                val decodedReq = String(entry.getRequestBytes()!!)
                decodedReq shouldBe "GET / HTTP/1.1"

                val decodedResp = String(entry.getResponseBytes()!!)
                decodedResp shouldBe "HTTP/1.1 200 OK"
            }
        }
    }

    Given("An AttackEntry created manually") {
        val entry = AttackEntry(
            host = "localhost",
            port = 8080,
            protocol = "http",
            method = "POST",
            url = "http://localhost:8080/api",
            requestBase64 = null,
            responseBase64 = null,
            testerName = "Dev",
            category = "XSS",
            status = "Fixed",
            notes = "Manual entry"
        )

        Then("It should have default values properly set") {
            entry.deleted shouldBe false
        }
    }
})
