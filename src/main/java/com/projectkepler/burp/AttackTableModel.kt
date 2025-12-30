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

    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean = 
        columnIndex == 0 || columnIndex == 2 || columnIndex == 5

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val attack = displayedAttacks.getOrNull(rowIndex) ?: return ""
        return when (columnIndex) {
            0 -> attack.id in selectedIds
            1 -> DATE_FORMATTER.format(Instant.ofEpochMilli(attack.timestamp))
            2 -> attack.category
            3 -> attack.method
            4 -> attack.url
            5 -> attack.status
            6 -> attack.testerName
            else -> ""
        }
    }

    override fun setValueAt(aValue: Any?, rowIndex: Int, columnIndex: Int) {
        if (columnIndex == 0 && aValue is Boolean) {
            val attack = displayedAttacks.getOrNull(rowIndex) ?: return
            if (aValue) {
                selectedIds.add(attack.id)
            } else {
                selectedIds.remove(attack.id)
            }
            fireTableCellUpdated(rowIndex, columnIndex)
        } else if (columnIndex == 2 || columnIndex == 5) {
            val attack = displayedAttacks.getOrNull(rowIndex) ?: return
            val valStr = aValue as? String ?: return
            
            var updatedEntry = attack
            if (columnIndex == 2) { // Category
                updatedEntry = attack.copy(category = valStr)
            } else if (columnIndex == 5) { // Status
                updatedEntry = attack.copy(status = valStr)
            }
            
            // Persist changes
            storageManager.updateAttack(updatedEntry)
            
            // Update local memory
            val allIndex = allAttacks.indexOfFirst { it.id == attack.id }
            if (allIndex != -1) {
                allAttacks[allIndex] = updatedEntry
            }
            refreshDisplay()
        }
    }

    fun setWrappedSelected(id: String, selected: Boolean) {
        if (selected) selectedIds.add(id) else selectedIds.remove(id)
        fireTableDataChanged()
    }

    companion object {
        private val DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault())
    }
}
