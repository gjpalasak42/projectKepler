package com.projectkepler.burp

import burp.api.montoya.logging.Logging
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.shouldBe
import io.mockk.mockk
import java.io.File
import java.nio.file.Files

class StorageManagerTest : BehaviorSpec({

    lateinit var tempStorageFile: File
    lateinit var tempConfigFile: File
    lateinit var storageManager: StorageManager
    val mockLogging = mockk<Logging>(relaxed = true)

    beforeSpec {
        tempStorageFile = Files.createTempFile("attacks", ".json").toFile()
        tempConfigFile = Files.createTempFile("config", ".json").toFile()
        storageManager = StorageManager(tempStorageFile.absolutePath, tempConfigFile.absolutePath, mockLogging)
    }

    afterSpec {
        tempStorageFile.delete()
        tempConfigFile.delete()
    }

    Given("An empty storage") {
        // Clear file content for fresh start
        tempStorageFile.writeText("")

        When("Loading attacks") {
            val attacks = storageManager.loadAttacks()
            Then("It should return an empty list") {
                attacks.shouldHaveSize(0)
            }
        }

        When("Saving a new attack") {
            val entry = AttackEntry(
                host = "test.com", port = 80, protocol = "http", method = "GET", url = "http://test.com",
                requestBase64 = null, responseBase64 = null, testerName = "Tester",
                category = "Bug", status = "New", notes = "Note"
            )
            storageManager.saveAttack(entry)

            Then("It should be persisted to disk") {
                val loaded = storageManager.loadAttacks()
                loaded.shouldHaveSize(1)
                loaded[0].host shouldBe "test.com"
            }
        }
    }

    Given("Existing attacks") {
        // Prepare state
        tempStorageFile.writeText("")
        val entry1 = AttackEntry(
            id = java.util.UUID.randomUUID().toString(),
            host = "site1.com", port = 80, protocol = "http", method = "GET", url = "/",
            requestBase64 = null, responseBase64 = null, testerName = "User",
            category = "A", status = "Open", notes = ""
        )
        val entry2 = AttackEntry(
            id = java.util.UUID.randomUUID().toString(),
            host = "site2.com", port = 80, protocol = "http", method = "GET", url = "/",
            requestBase64 = null, responseBase64 = null, testerName = "User",
            category = "A", status = "Open", notes = ""
        )
        storageManager.saveAttack(entry1)
        storageManager.saveAttack(entry2)

        When("Soft deleting an attack") {
            storageManager.deleteAttacks(setOf(entry1.id), permanent = false)

            Then("It should be marked as deleted but still exist") {
                val loaded = storageManager.loadAttacks()
                loaded.find { it.id == entry1.id }?.deleted shouldBe true
                loaded.find { it.id == entry2.id }?.deleted shouldBe false
            }
        }

        When("Restoring the attack") {
            storageManager.restoreAttacks(setOf(entry1.id))
            
            Then("It should be marked as not deleted") {
                val loaded = storageManager.loadAttacks()
                loaded.find { it.id == entry1.id }?.deleted shouldBe false
            }
        }

        When("Updating an attack") {
            val updated = entry2.copy(notes = "Updated Notes")
            storageManager.updateAttack(updated)

            Then("The change should be persisted") {
                val loaded = storageManager.loadAttacks()
                val target = loaded.find { it.id == entry2.id }
                target?.notes shouldBe "Updated Notes"
            }
        }

        When("Hard deleting an attack") {
            storageManager.deleteAttacks(setOf(entry2.id), permanent = true)

            Then("It should be removed completely") {
                val loaded = storageManager.loadAttacks()
                loaded.find { it.id == entry2.id } shouldBe null
                loaded.shouldHaveSize(1) // Only entry1 remains
            }
        }
    }

    Given("Trash management") {
        tempStorageFile.writeText("")
        val trashItem = AttackEntry(
            host = "trash.com", port = 80, protocol = "http", method = "GET", url = "/",
            requestBase64 = null, responseBase64 = null, testerName = "User",
            category = "Junk", status = "Open", notes = "", deleted = true
        )
        val keepItem = trashItem.copy(id = java.util.UUID.randomUUID().toString(), deleted = false)
        
        storageManager.saveAttack(trashItem)
        storageManager.saveAttack(keepItem)

        When("Emptying trash") {
            storageManager.emptyTrash()

            Then("Deleted items should be removed") {
                val loaded = storageManager.loadAttacks()
                loaded.shouldHaveSize(1)
                loaded[0].id shouldBe keepItem.id
            }
        }
    }
})
