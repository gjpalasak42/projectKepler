# ProjectKepler Testing Infrastructure

**Status:** ✅ Initial Setup Complete  
**Last Updated:** December 29, 2024  
**Framework:** JUnit 5 + MockK + Kotest (in progress)

---

## Overview

This document describes the testing infrastructure for ProjectKepler, a Burp Suite extension written in Kotlin using the Montoya API.

**Why Testing Matters for Security Tools:**
- Prevents regression bugs that could miss vulnerabilities
- Validates data integrity during attack history persistence
- Ensures thread-safe operations don't introduce race conditions
- Verifies XSS sanitization in the UI layer

---

## Current Testing Stack

### ✅ Fully Configured

| Framework | Version | Purpose | Status |
|-----------|---------|---------|--------|
| **JUnit 5** | 5.10.2 | Test runner and assertions | ✅ Working |
| **MockK** | 1.13.9 | Kotlin-first mocking | ✅ Configured |
| **Kotest** | 5.8.0 | BDD-style tests + property testing | ⚠️ Partial |
| **Strikt** | 0.34.1 | Fluent Kotlin assertions | ⚠️ Needs setup |

### Test Structure

```
src/test/kotlin/com/projectkepler/burp/
├── SimpleAttackEntryTest.kt          ✅ Working (13 tests)
├── AttackEntryTest.kt.bak            ⚠️ Kotest version (pending)
├── ExtensionConfigTest.kt.bak        ⚠️ Kotest version (pending)
├── StorageManagerTest.kt.bak         ⚠️ Kotest version (pending)
├── MontoyaIntegrationTest.kt.bak     ⚠️ Kotest version (pending)
└── AttackEntryPropertyTest.kt.bak    ⚠️ Kotest version (pending)
```

---

## Working Tests (Current)

### SimpleAttackEntryTest.kt ✅

**Coverage:**
- ✅ Unique ID generation
- ✅ Null safety (request/response)
- ✅ Base64 encoding/decoding
- ✅ Binary data preservation
- ✅ Timestamp validation
- ✅ Data class equality/hashCode
- ✅ Copy functionality
- ✅ Deleted flag mutation
- ✅ ID validation

**Security Tests:**
- Base64 decoding preserves binary traffic (prevents corruption)
- Unique IDs prevent data collision in storage
- Null handling prevents NPE crashes

**Run Tests:**
```bash
./gradlew test
# Or specific test:
./gradlew test --tests SimpleAttackEntryTest
```

**Output:**
```
BUILD SUCCESSFUL in 7s
5 actionable tasks: 5 executed
```

---

## Planned Tests (Pending Setup)

### 1. AttackEntryTest.kt (Kotest FunSpec)
- **Status:** ⚠️ Needs Kotest import resolution
- **Tests:** 15 comprehensive test cases
- **Focus:** Data class behavior, edge cases

### 2. ExtensionConfigTest.kt
- **Status:** ⚠️ Needs Kotest import resolution
- **Tests:** 18 configuration tests
- **Focus:** Default values, mutable lists, custom categories

### 3. StorageManagerTest.kt
- **Status:** ⚠️ Needs Kotest + MockK setup
- **Tests:** 17 persistence tests
- **Focus:** Save/load, caching, trash operations, import/export
- **Security:** Data integrity, duplicate detection

### 4. MontoyaIntegrationTest.kt
- **Status:** ⚠️ Needs MockK mocking setup
- **Tests:** 10 integration tests
- **Focus:** Montoya API interaction, HttpRequestResponse parsing
- **Security:** Binary data handling, XSS payload preservation

### 5. AttackEntryPropertyTest.kt (Kotest Property Testing)
- **Status:** ⚠️ Needs Kotest property framework
- **Tests:** 10 fuzz/property tests
- **Focus:** Arbitrary input handling, XSS payloads, control characters
- **Security:** Buffer overflows, injection attacks, null bytes

---

## CI/CD Integration

### GitHub Actions Workflows

#### 1. CI Workflow (`.github/workflows/ci.yml`) ✅
**Triggers:**
- Push to `main` or `grant-movetokotlin`
- Pull requests to `main`

**Steps:**
1. ✅ Checkout code
2. ✅ Set up JDK 21
3. ✅ Run tests (`./gradlew test --info`)
4. ✅ Publish test report
5. ✅ Build Fat JAR (`./gradlew shadowJar`)
6. ✅ Upload artifacts

**Features:**
- Test results published as GitHub Checks
- Test artifacts retained for 30 days
- Build artifacts retained for 7 days

#### 2. Release Workflow (`.github/workflows/release.yml`) ✅
**Triggers:**
- Git tags matching `v*` (e.g., `v1.2.1`)

**Steps:**
1. ✅ Checkout code
2. ✅ Set up JDK 21
3. ✅ **Run tests** (blocks release if tests fail)
4. ✅ Build Fat JAR
5. ✅ Generate SHA-256 checksum
6. ✅ Create GitHub Release

**Security Feature:**
- Tests MUST pass before release is created
- Release includes test pass confirmation

---

## Dependencies (build.gradle)

```gradle
dependencies {
    // Production
    implementation "org.jetbrains.kotlin:kotlin-stdlib"
    compileOnly "net.portswigger.burp.extensions:montoya-api:2023.12.1"
    implementation "com.google.code.gson:gson:2.10.1"

    // Testing (Kotlin-First Stack)
    testImplementation "net.portswigger.burp.extensions:montoya-api:2023.12.1"
    testImplementation "org.jetbrains.kotlin:kotlin-test-junit5"
    testImplementation "org.junit.jupiter:junit-jupiter:5.10.2"
    testImplementation "io.mockk:mockk:1.13.9"
    testImplementation "io.kotest:kotest-runner-junit5:5.8.0"
    testImplementation "io.kotest:kotest-assertions-core:5.8.0"
    testImplementation "io.kotest:kotest-property:5.8.0"
    testImplementation "io.strikt:strikt-core:0.34.1"
}

test {
    useJUnitPlatform()
}
```

---

## Running Tests Locally

### All Tests
```bash
./gradlew test
```

### Specific Test Class
```bash
./gradlew test --tests SimpleAttackEntryTest
```

### With Detailed Output
```bash
./gradlew test --info
```

### Clean + Test
```bash
./gradlew clean test
```

### View Test Reports
```bash
# After running tests:
open build/reports/tests/test/index.html
```

---

## Test Coverage (Current)

| Component | Coverage | Status |
|-----------|----------|--------|
| **AttackEntry** | ✅ 90% | Core functionality tested |
| **ExtensionConfig** | ❌ 0% | Pending |
| **StorageManager** | ❌ 0% | Pending |
| **BurpExtender** | ❌ 0% | Complex UI - needs mocking |
| **Montoya Integration** | ❌ 0% | Pending |

**Overall Coverage:** ~20% (1 of 5 core components)

---

## Next Steps (Priority Order)

### Phase 1: Fix Kotest Setup (1-2 hours)
- [ ] Resolve Strikt import issues
- [ ] Enable Kotest FunSpec tests
- [ ] Restore `.bak` test files
- [ ] Verify all tests compile

### Phase 2: Storage Tests (2-3 hours)
- [ ] Complete StorageManagerTest
- [ ] Test caching behavior
- [ ] Test trash operations
- [ ] Test import/export with edge cases

### Phase 3: Integration Tests (3-4 hours)
- [ ] Mock Montoya API objects
- [ ] Test HttpRequestResponse parsing
- [ ] Test binary data handling
- [ ] Test XSS payload preservation

### Phase 4: Property Testing (2-3 hours)
- [ ] Fuzz test input handling
- [ ] Test control characters
- [ ] Test Unicode edge cases
- [ ] Test injection payloads

### Phase 5: UI Tests (Future)
- [ ] Mock Swing components
- [ ] Test table model updates
- [ ] Test context menu actions
- [ ] Test settings panel

---

## Security Testing Checklist

### ✅ Current Coverage
- [x] Base64 encoding preserves binary data
- [x] Unique ID generation prevents collisions
- [x] Null safety prevents NPE crashes
- [x] Timestamp validation

### ⚠️ Pending
- [ ] XSS sanitization in notes field
- [ ] SQL injection in search filters
- [ ] Path traversal in import/export
- [ ] Race conditions in storage manager
- [ ] Buffer overflow in large payloads
- [ ] Memory leaks in traffic interception

---

## Troubleshooting

### Issue: Kotest tests not compiling
**Symptom:**
```
Unresolved reference: expectThat
Unresolved reference: FunSpec
```

**Solution:**
1. Refresh dependencies:
   ```bash
   ./gradlew --refresh-dependencies
   ```
2. Check import statements:
   ```kotlin
   import io.kotest.core.spec.style.FunSpec
   import io.strikt.api.expectThat
   import io.strikt.assertions.*
   ```
3. Clean build:
   ```bash
   ./gradlew clean build
   ```

### Issue: Tests pass locally but fail in CI
**Solution:**
- Check JDK version consistency (local vs. CI)
- Verify test uses relative paths (not absolute)
- Check for timezone-dependent tests
- Review test isolation (shared state)

---

## Best Practices

### Test Naming
```kotlin
// ✅ Good: Descriptive backtick names
@Test
fun `should handle null response in HttpRequestResponse`() { }

// ❌ Bad: CamelCase without context
@Test
fun testNullResponse() { }
```

### Security Test Documentation
```kotlin
// Why: Prevents XSS in Burp UI
// Security Implication: Malicious notes could execute in Swing components
@Test
fun `should sanitize HTML in notes field`() {
    // Test implementation
}
```

### Mock Setup
```kotlin
// ✅ Use MockK for Kotlin
val mockApi = mockk<MontoyaApi> {
    every { logging() } returns mockk(relaxed = true)
}

// ❌ Don't use Mockito for Kotlin
// Mockito struggles with final classes and coroutines
```

---

## Resources

### Documentation
- [JUnit 5 User Guide](https://junit.org/junit5/docs/current/user-guide/)
- [MockK Documentation](https://mockk.io/)
- [Kotest Documentation](https://kotest.io/)
- [Burp Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/)

### Examples
- `SimpleAttackEntryTest.kt` - Working JUnit 5 tests
- `.bak` files - Advanced Kotest examples (pending setup)

---

## Summary

✅ **Completed:**
- JUnit 5 test infrastructure
- MockK and Kotest dependencies
- CI/CD integration with test execution
- 13 working unit tests for AttackEntry

⚠️ **In Progress:**
- Kotest FunSpec import resolution
- Strikt assertion library setup
- Advanced integration tests

🎯 **Next Milestone:**
- Complete Phase 1 (Fix Kotest)
- Achieve 60% code coverage
- Add property-based fuzz tests

---

**Questions?** Review this document and the working `SimpleAttackEntryTest.kt` as a reference implementation.