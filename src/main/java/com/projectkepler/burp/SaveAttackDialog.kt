package com.projectkepler.burp

import java.awt.*
import javax.swing.*

/**
 * Dialog for capturing metadata about a saved attack.
 * Why: Providing a structured dialog ensures that security testers consistently categorize
 * and document their findings (SQLi, XSS, etc.) before they are committed to persistent storage.
 */
class SaveAttackDialog(owner: Frame, config: ExtensionConfig) : JDialog(owner, "Save Attack to History", true) {
    private lateinit var categoryComboBox: JComboBox<String>
    private lateinit var statusComboBox: JComboBox<String>
    private lateinit var notesArea: JTextArea
    var isSaved = false
        private set

    val category: String
        get() = categoryComboBox.selectedItem as String

    val status: String
        get() = statusComboBox.selectedItem as String

    val notes: String
        get() = notesArea.text

    init {
        initComponents(config)
        pack()
        setLocationRelativeTo(owner)
    }

    private fun initComponents(config: ExtensionConfig) {
        layout = BorderLayout(10, 10)
        val formPanel = JPanel(GridBagLayout())
        val gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL

        // Category
        gbc.gridx = 0
        gbc.gridy = 0
        formPanel.add(JLabel("Category:"), gbc)

        gbc.gridx = 1
        categoryComboBox = JComboBox(config.categories.toTypedArray())
        categoryComboBox.isEditable = true // Allow custom categories
        formPanel.add(categoryComboBox, gbc)

        // Status
        gbc.gridx = 0
        gbc.gridy = 1
        formPanel.add(JLabel("Status:"), gbc)

        gbc.gridx = 1
        statusComboBox = JComboBox(config.statuses.toTypedArray())
        formPanel.add(statusComboBox, gbc)

        // Notes
        gbc.gridx = 0
        gbc.gridy = 2
        gbc.anchor = GridBagConstraints.NORTHWEST
        formPanel.add(JLabel("Notes:"), gbc)

        gbc.gridx = 1
        gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.BOTH
        notesArea = JTextArea(5, 30)
        notesArea.lineWrap = true
        notesArea.wrapStyleWord = true
        formPanel.add(JScrollPane(notesArea), gbc)

        add(formPanel, BorderLayout.CENTER)

        // Buttons
        val buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        val saveButton = JButton("Save")
        val cancelButton = JButton("Cancel")

        saveButton.addActionListener {
            isSaved = true
            dispose()
        }

        cancelButton.addActionListener { dispose() }

        buttonPanel.add(saveButton)
        buttonPanel.add(cancelButton)
        add(buttonPanel, BorderLayout.SOUTH)
    }
}
