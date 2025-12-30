package com.projectkepler.burp

import javax.swing.table.AbstractTableModel
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Custom table model for displaying AttackEntry records.
 * Why: Using AbstractTableModel provides a reactive bridge between the data layer and Burp's Swing-based UI.
 * It allows us to handle complex selection states and filtering without blocking the UI thread.
 */
class AttackTableModel(private val storageManager: StorageManager) : AbstractTableModel() {
    private var allAttacks: MutableList<AttackEntry> = mutableListOf()
    var displayedAttacks: List<AttackEntry> = emptyList()
        private set

    private val columnNames = arrayOf("", "Time", "Category", "Method", "URL", "Status", "Tester")
    private val selectedIds = mutableSetOf<String>()

    var showDeleted: Boolean = false
        set(value) {
            field = value
            refreshDisplay()
        }

    /**
     * Updates the underlying data set.
     * Why: This triggers a full display refresh to ensure the UI stays in sync with the StorageManager.
     */
    fun setAttacks(attacks: List<AttackEntry>) {
        allAttacks = attacks.toMutableList()
        refreshDisplay()
    }

    /**
     * Filters the attacks based on deletion status and resets selection.
     * Why: Separating 'allAttacks' from 'displayedAttacks' allows us to toggle between
     * the active history and the trash without re-reading from disk.
     */
    private fun refreshDisplay() {
        displayedAttacks = allAttacks.filter { it.deleted == showDeleted }
        selectedIds.clear()
        fireTableDataChanged()
    }

    fun getAttackAt(rowIndex: Int): AttackEntry? = displayedAttacks.getOrNull(rowIndex)

    fun getSelectedIds(): Set<String> = selectedIds.toSet()

    fun setAllSelected(selected: Boolean) {
        if (selected) {
            displayedAttacks.forEach { selectedIds.add(it.id) }
        } else {
            selectedIds.clear()
        }
        fireTableDataChanged()
    }

    val isAllSelected: Boolean
        get() = displayedAttacks.isNotEmpty() && displayedAttacks.all { it.id in selectedIds }

    fun clearSelection() {
        selectedIds.clear()
        fireTableDataChanged()
    }

    override fun getRowCount(): Int = displayedAttacks.size

    override fun getColumnCount(): Int = columnNames.size

    override fun getColumnName(column: Int): String = columnNames[column]

    override fun getColumnClass(columnIndex: Int): Class<*> = when (columnIndex) {
        0 -> java.lang.Boolean::class.java
        else -> String::class.java
    }

    companion object {
        const val COL_CHECKBOX = 0
        const val COL_TIME = 1
        const val COL_CATEGORY = 2
        const val COL_METHOD = 3
        const val COL_URL = 4
        const val COL_STATUS = 5
        const val COL_TESTER = 6

        private val DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault())
    }

    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean = 
        columnIndex == COL_CHECKBOX || columnIndex == COL_CATEGORY || columnIndex == COL_STATUS

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val attack = displayedAttacks.getOrNull(rowIndex) ?: return ""
        return when (columnIndex) {
            COL_CHECKBOX -> attack.id in selectedIds
            COL_TIME -> DATE_FORMATTER.format(Instant.ofEpochMilli(attack.timestamp))
            COL_CATEGORY -> attack.category
            COL_METHOD -> attack.method
            COL_URL -> attack.url
            COL_STATUS -> attack.status
            COL_TESTER -> attack.testerName
            else -> ""
        }
    }

    override fun setValueAt(aValue: Any?, rowIndex: Int, columnIndex: Int) {
        if (columnIndex == COL_CHECKBOX && aValue is Boolean) {
            val attack = displayedAttacks.getOrNull(rowIndex) ?: return
            if (aValue) {
                selectedIds.add(attack.id)
            } else {
                selectedIds.remove(attack.id)
            }
            fireTableCellUpdated(rowIndex, columnIndex)
        } else if (columnIndex == COL_CATEGORY || columnIndex == COL_STATUS) {
            val attack = displayedAttacks.getOrNull(rowIndex) ?: return
            val valStr = aValue as? String ?: return
            
            var updatedEntry = attack
            if (columnIndex == COL_CATEGORY) {
                updatedEntry = attack.copy(category = valStr)
            } else if (columnIndex == COL_STATUS) {
                updatedEntry = attack.copy(status = valStr)
            }
            
            // Persist changes
            storageManager.updateAttack(updatedEntry)
            
            // Update local memory - Optimized to avoid full refresh and selection loss
            val allIndex = allAttacks.indexOfFirst { it.id == attack.id }
            if (allIndex != -1) {
                allAttacks[allIndex] = updatedEntry
            }
            
            // Since displayedAttacks is immutable List, we must create a new list
            // but we can just replace the item at the index
            // Actually displayedAttacks is derived. We should probably make it mutable or recreate it efficiently.
            // But to preserve selection, we just need to NOT clear selectedIds.
            
            // Re-filtering might be expensive if list is huge, but necessary if modification changes filter criteria (e.g. deleted).
            // Updates to Category/Status do NOT affect deleted status, so we can just update displayedAttacks in place if it were mutable.
            // Since it's currently a List (read-only interface) backed by logic.
            
            // Let's optimize: Update the specific item in displayedAttacks if possible.
            // But displayedAttacks is set by refreshDisplay, which filters allAttacks.
            // If we don't call refreshDisplay, displayedAttacks is stale.
            // We can recreate displayedAttacks without clearing selection?
            
            // Option: Just update the list
            displayedAttacks = allAttacks.filter { it.deleted == showDeleted }
            // Do NOT clear selectedIds
            fireTableRowsUpdated(rowIndex, rowIndex)
        }
    }

    fun setWrappedSelected(id: String, selected: Boolean) {
        if (selected) selectedIds.add(id) else selectedIds.remove(id)
        fireTableDataChanged()
    }
}
