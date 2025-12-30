package com.projectkepler.burp

import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldNotContain
import io.mockk.mockk
import io.mockk.verify
import io.mockk.slot

class AttackTableModelTest : BehaviorSpec({

    val mockStorage = mockk<StorageManager>(relaxed = true)
    lateinit var tableModel: AttackTableModel

    fun createEntry(id: String, deleted: Boolean = false) = AttackEntry(
        id = id,
        host = "host", port = 80, protocol = "http", method = "GET", url = "/",
        requestBase64 = null, responseBase64 = null, testerName = "User",
        category = "Cat", status = "Open", notes = "", deleted = deleted
    )

    Given("A table model with data") {
        tableModel = AttackTableModel(mockStorage)
        val entry1 = createEntry("1", deleted = false)
        val entry2 = createEntry("2", deleted = true)
        val entry3 = createEntry("3", deleted = false)
        
        tableModel.setAttacks(listOf(entry1, entry2, entry3))

        When("Showing active attacks (default)") {
            tableModel.showDeleted = false

            Then("Only non-deleted items are displayed") {
                tableModel.rowCount shouldBe 2
                tableModel.getAttackAt(0)?.id shouldBe "1"
                tableModel.getAttackAt(1)?.id shouldBe "3"
            }
        }

        When("Showing deleted attacks") {
            tableModel.showDeleted = true

            Then("Only deleted items are displayed") {
                tableModel.rowCount shouldBe 1
                tableModel.getAttackAt(0)?.id shouldBe "2"
            }
        }

        When("Updating selection") {
            tableModel.showDeleted = false
            tableModel.setWrappedSelected("1", true)
            
            Then("Selected IDs should update") {
                tableModel.getSelectedIds() shouldContain "1"
            }
            
            Then("ValueAt check column should be true") {
                tableModel.getValueAt(0, 0) shouldBe true // Row 0 is entry1
            }
        }
        
        When("Editing a cell value (Status)") {
            tableModel.showDeleted = false
            // Row 0 is entry1. Column 5 is Status.
            tableModel.setValueAt("Fixed", 0, 5)

            Then("It should call updateAttack on storage") {
                val slot = slot<AttackEntry>()
                verify { mockStorage.updateAttack(capture(slot)) }
                slot.captured.status shouldBe "Fixed"
                slot.captured.id shouldBe "1"
            }

            Then("It should update local display") {
                tableModel.getAttackAt(0)?.status shouldBe "Fixed"
            }
        }
    }
})
