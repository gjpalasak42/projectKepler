package com.projectkepler.burp

import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.util.concurrent.ExecutorService
import javax.swing.JButton
import javax.swing.JFileChooser
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingUtilities

/**
 * UI panel for managing extension-wide settings and data operations.
 * Why: Centralizing settings and I/O operations (Export/Import) ensures a consistent
 * user experience and prevents blocking the main Burp UI thread by offloading
 * disk operations to a background executor.
 */
class SettingsPanel(
    private val storageManager: StorageManager,
    private val backgroundExecutor: ExecutorService
) : JPanel() {
    private val testerNameField: JTextField
    private val categoriesArea: JTextArea
    private val statusesArea: JTextArea

    init {
        layout = BorderLayout()

        // Form Panel
        val formPanel = JPanel(GridBagLayout())
        val gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.anchor = GridBagConstraints.NORTHWEST

        // Tester Name
        gbc.gridx = 0
        gbc.gridy = 0
        formPanel.add(JLabel("Tester Name:"), gbc)

        gbc.gridx = 1
        gbc.weightx = 1.0
        testerNameField = JTextField(20)
        formPanel.add(testerNameField, gbc)

        // Categories
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.weightx = 0.0
        formPanel.add(JLabel("Categories (one per line):"), gbc)

        gbc.gridx = 1
        gbc.weightx = 1.0
        gbc.weighty = 0.5
        gbc.fill = GridBagConstraints.BOTH
        categoriesArea = JTextArea(10, 30)
        formPanel.add(JScrollPane(categoriesArea), gbc)

        // Statuses
        gbc.gridx = 0
        gbc.gridy = 2
        gbc.weightx = 0.0
        gbc.weighty = 0.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        formPanel.add(JLabel("Statuses (one per line):"), gbc)

        gbc.gridx = 1
        gbc.weightx = 1.0
        gbc.weighty = 0.5
        gbc.fill = GridBagConstraints.BOTH
        statusesArea = JTextArea(5, 30)
        formPanel.add(JScrollPane(statusesArea), gbc)

        add(formPanel, BorderLayout.CENTER)

        // Buttons
        val buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT))

        val exportButton = JButton("Export History")
        exportButton.addActionListener { exportHistory() }
        buttonPanel.add(exportButton)

        val importButton = JButton("Import History")
        importButton.addActionListener { importHistory() }
        buttonPanel.add(importButton)

        val saveButton = JButton("Save Settings")
        saveButton.addActionListener { saveSettings() }
        buttonPanel.add(saveButton)

        add(buttonPanel, BorderLayout.SOUTH)

        loadSettingsAsync()
    }

    private fun loadSettingsAsync() {
        backgroundExecutor.execute {
            val config = storageManager.loadConfig()
            SwingUtilities.invokeLater {
                testerNameField.text = config.testerName
                categoriesArea.text = config.categories.joinToString("\n")
                statusesArea.text = config.statuses.joinToString("\n")
            }
        }
    }

    private fun saveSettings() {
        val config = ExtensionConfig()
        config.testerName = testerNameField.text.trim()

        val categories = categoriesArea.text.split("\n".toRegex())
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toMutableList()
        config.categories = categories

        val statuses = statusesArea.text.split("\n".toRegex())
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toMutableList()
        config.statuses = statuses

        backgroundExecutor.execute {
            storageManager.saveConfig(config)
            SwingUtilities.invokeLater {
                JOptionPane.showMessageDialog(
                    this@SettingsPanel,
                    "Settings Saved!",
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE
                )
            }
        }
    }

    private fun exportHistory() {
        val fileChooser = JFileChooser()
        fileChooser.dialogTitle = "Export Attack History"
        val userSelection = fileChooser.showSaveDialog(this)

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            var fileToSave = fileChooser.selectedFile
            if (!fileToSave.name.lowercase().endsWith(".json")) {
                fileToSave = java.io.File(fileToSave.absolutePath + ".json")
            }
            val finalFileToSave = fileToSave
            backgroundExecutor.execute {
                try {
                    storageManager.exportAttacks(finalFileToSave)
                    SwingUtilities.invokeLater {
                        JOptionPane.showMessageDialog(
                            this@SettingsPanel,
                            "History exported successfully!",
                            "Success",
                            JOptionPane.INFORMATION_MESSAGE
                        )
                    }
                } catch (e: Exception) {
                    SwingUtilities.invokeLater {
                        JOptionPane.showMessageDialog(
                            this@SettingsPanel,
                            "Error exporting history: " + e.message,
                            "Error",
                            JOptionPane.ERROR_MESSAGE
                        )
                    }
                }
            }
        }
    }

    private fun importHistory() {
        val fileChooser = JFileChooser()
        fileChooser.dialogTitle = "Import Attack History"
        val userSelection = fileChooser.showOpenDialog(this)

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            val fileToOpen = fileChooser.selectedFile
            backgroundExecutor.execute {
                try {
                    storageManager.importAttacks(fileToOpen)
                    SwingUtilities.invokeLater {
                        JOptionPane.showMessageDialog(
                            this@SettingsPanel,
                            "History imported successfully! Please refresh the Attack History tab.",
                            "Success",
                            JOptionPane.INFORMATION_MESSAGE
                        )
                    }
                } catch (e: Exception) {
                    SwingUtilities.invokeLater {
                        JOptionPane.showMessageDialog(
                            this@SettingsPanel,
                            "Error importing history: " + e.message,
                            "Error",
                            JOptionPane.ERROR_MESSAGE
                        )
                    }
                }
            }
        }
    }
}
