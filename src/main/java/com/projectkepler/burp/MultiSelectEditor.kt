package com.projectkepler.burp

import java.awt.Component
import java.awt.Dialog
import java.awt.FlowLayout
import java.awt.event.ActionListener
import javax.swing.*
import javax.swing.table.TableCellEditor

/**
 * A custom cell editor that opens a dialog to select multiple items.
 */
class MultiSelectEditor(
    private val owner: Component,
    private val availableItems: List<String>
) : AbstractCellEditor(), TableCellEditor {

    private var currentSelection: String = ""
    private val button = JButton()
    private val dialog = JDialog(SwingUtilities.getWindowAncestor(owner), "Select Categories", Dialog.ModalityType.APPLICATION_MODAL)
    private val checkBoxes = mutableListOf<JCheckBox>()

    init {
        button.addActionListener {
            // Open dialog
            val parent = SwingUtilities.getWindowAncestor(owner)
            dialog.setLocationRelativeTo(parent)
            
            // Sync checkboxes
            val selected = currentSelection.split(", ").filter { it.isNotBlank() }.toSet()
            checkBoxes.forEach { cb ->
                cb.isSelected = cb.text in selected
            }
            
            dialog.isVisible = true
        }
        button.border = BorderFactory.createEmptyBorder()

        // Build Dialog
        dialog.layout = BoxLayout(dialog.contentPane, BoxLayout.Y_AXIS)
        
        val checkPanel = JPanel()
        checkPanel.layout = BoxLayout(checkPanel, BoxLayout.Y_AXIS)
        availableItems.forEach { item ->
            val cb = JCheckBox(item)
            checkBoxes.add(cb)
            checkPanel.add(cb)
        }
        dialog.add(JScrollPane(checkPanel))

        val btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        val okBtn = JButton("OK")
        okBtn.addActionListener {
            currentSelection = checkBoxes.filter { it.isSelected }
                .joinToString(", ") { it.text }
            dialog.dispose()
            fireEditingStopped()
        }
        btnPanel.add(okBtn)
        dialog.add(btnPanel)
        
        dialog.pack()
    }

    override fun getTableCellEditorComponent(
        table: JTable?,
        value: Any?,
        isSelected: Boolean,
        row: Int,
        column: Int
    ): Component {
        currentSelection = value as? String ?: ""
        button.text = currentSelection
        return button
    }

    override fun getCellEditorValue(): Any {
        return currentSelection
    }
}
