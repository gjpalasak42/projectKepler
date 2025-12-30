package com.projectkepler.burp

/**
 * Configuration model for the ProjectKepler extension.
 * Why: Using a dedicated data class for configuration allows for easy JSON serialization
 * and centralizes default settings for the attack history tracking (tester name, categories, etc.).
 */
data class ExtensionConfig(
    var testerName: String = "Tester",
    var categories: MutableList<String> = mutableListOf(
        "SQL Injection",
        "XSS",
        "CSRF",
        "IDOR",
        "Auth Bypass",
        "RCE",
        "Information Disclosure",
        "Other"
    ),
    var statuses: MutableList<String> = mutableListOf(
        "Vulnerable",
        "Safe",
        "Needs Investigation"
    )
)
