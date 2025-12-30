package com.projectkepler.burp

import java.awt.Component
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JTable
import javax.swing.UIManager
import javax.swing.table.TableCellRenderer

/**
 * Custom table header renderer that displays a checkbox for bulk selection.
 * Why: Implementing TableCellRenderer allows us to integrate a functional checkbox
 * directly into the JTable header, enabling "select all" functionality which is
 * expected in modern offensive security tools for bulk operations.
 */
class CheckBoxHeader(private val table: JTable, private val targetColumnIndex: Int) : JCheckBox(), TableCellRenderer {
    private var listenerInitialized = false

    init {
        horizontalAlignment = JLabel.CENTER
        isOpaque = true
        initMouseListener()
    }

    private fun initMouseListener() {
        if (!listenerInitialized) {
            val header = table.tableHeader
            header.addMouseListener(object : MouseAdapter() {
                override fun mouseClicked(e: MouseEvent) {
                    handleClick(e)
                }
            })
            listenerInitialized = true
        }
    }

    override fun getTableCellRendererComponent(
        table: JTable, value: Any?,
        isSelected: Boolean, hasFocus: Boolean, row: Int, column: Int
    ): Component {
        val header = table.tableHeader
        if (header != null) {
            foreground = header.foreground
            background = header.background
            font = header.font
        }

        val model = table.model
        if (model is AttackTableModel) {
            this.isSelected = model.isAllSelected
        }

        border = UIManager.getBorder("TableHeader.cellBorder")

        return this
    }

    private fun handleClick(e: MouseEvent) {
        val columnIndex = table.columnModel.getColumnIndexAtX(e.x)
        if (columnIndex == targetColumnIndex) {
            val newState = !isSelected
            this.isSelected = newState
            table.tableHeader.repaint()

            val model = table.model
            if (model is AttackTableModel) {
                model.setAllSelected(newState)
            }
        }
    }
}
