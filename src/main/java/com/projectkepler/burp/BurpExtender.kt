package com.projectkepler.burp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray.byteArray
import burp.api.montoya.logging.Logging
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.HttpResponseEditor
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import java.awt.BorderLayout
import java.awt.Component
import java.util.concurrent.Executors
import javax.swing.*

/**
 * Main entry point for the ProjectKepler Burp Suite extension.
 * Why: Implementing BurpExtension allows us to use the modern Montoya API,
 * providing better performance and stability over the legacy Extender API.
 * This refactor ensures thread-safe traffic processing and modernization of the UI logic.
 */
class BurpExtender : BurpExtension {
    private lateinit var api: MontoyaApi
    private val logging: Logging by lazy { api.logging() }

    private lateinit var storageManager: StorageManager
    private lateinit var mainPanel: JPanel

    /**
     * Why: Using a dedicated background executor for I/O operations (saving/loading attacks)
     * ensures the Burp Suite UI remains responsive even when handling large datasets.
     */
    private val backgroundExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "ProjectKepler-Worker").apply { isDaemon = true }
    }

    private lateinit var attackTable: JTable
    private lateinit var tableModel: AttackTableModel
    private lateinit var requestViewer: HttpRequestEditor
    private lateinit var responseViewer: HttpResponseEditor

    private lateinit var notesDetailArea: JTextArea
    private lateinit var trashToggle: JToggleButton
    private lateinit var deleteButton: JButton
    private lateinit var restoreButton: JButton
    private lateinit var emptyTrashButton: JButton

    override fun initialize(api: MontoyaApi) {
        this.api = api
        api.extension().setName("Attack History")

        val storagePath = System.getProperty("user.home") + "/.burp_attack_history.json"
        val configPath = System.getProperty("user.home") + "/.burp_attack_history_config.json"

        storageManager = StorageManager(storagePath, configPath, logging)

        logging.logToOutput("ProjectKepler: Attack History Recorder Loaded.")
        logging.logToOutput("Storage path: $storagePath")

        api.userInterface().registerSuiteTab("Attack History", initializeUI())
        api.userInterface().registerContextMenuItemsProvider(contextMenuItemsProvider())

        refreshTable()
    }

    private fun initializeUI(): Component {
        mainPanel = JPanel(BorderLayout())
        val mainTabs = JTabbedPane()

        // --- Tab 1: Attack History ---
        val historyPanel = JPanel(BorderLayout())

        // Toolbar
        val toolbar = JToolBar().apply { isFloatable = false }

        val refreshButton = JButton("Refresh").apply {
            addActionListener { refreshTable() }
        }
        toolbar.add(refreshButton)
        toolbar.addSeparator()

        trashToggle = JToggleButton("Show Trash").apply {
            addActionListener {
                tableModel.showDeleted = isSelected
                updateToolbarState()
            }
        }
        toolbar.add(trashToggle)
        toolbar.addSeparator()

        deleteButton = JButton("Delete Selected").apply {
            addActionListener { deleteSelected() }
        }
        toolbar.add(deleteButton)

        restoreButton = JButton("Restore Selected").apply {
            addActionListener { restoreSelected() }
            isVisible = false
        }
        toolbar.add(restoreButton)

        emptyTrashButton = JButton("Empty Trash").apply {
            addActionListener { emptyTrash() }
            isVisible = false
        }
        toolbar.add(emptyTrashButton)

        historyPanel.add(toolbar, BorderLayout.NORTH)

        // Table Setup
        tableModel = AttackTableModel(storageManager)
        attackTable = JTable(tableModel)
        attackTable.autoCreateRowSorter = true

        // Set custom header for bulk selection
        val checkBoxHeader = CheckBoxHeader(attackTable, 0)
        attackTable.columnModel.getColumn(0).apply {
            headerRenderer = checkBoxHeader
            maxWidth = 30
            minWidth = 30
        }

        // Cell Editors
        val config = storageManager.loadConfig()
        
        // Status Editor
        val statusCombo = JComboBox(config.statuses.toTypedArray())
        attackTable.columnModel.getColumn(5).cellEditor = DefaultCellEditor(statusCombo)

        // Category Editor
        val categoryEditor = MultiSelectEditor(attackTable, config.categories)
        attackTable.columnModel.getColumn(2).cellEditor = categoryEditor

        // Custom Context Menu Logic
        attackTable.componentPopupMenu = null // Remove default
        attackTable.addMouseListener(object : java.awt.event.MouseAdapter() {
            override fun mouseReleased(e: java.awt.event.MouseEvent) {
                if (e.isPopupTrigger) showMenu(e)
            }
            override fun mousePressed(e: java.awt.event.MouseEvent) {
                if (e.isPopupTrigger) showMenu(e)
            }

            private fun showMenu(e: java.awt.event.MouseEvent) {
                val row = attackTable.rowAtPoint(e.point)
                
                // Smart Selection: If clicking on a row NOT in the current visual selection, 
                // clear others and select only this one.
                if (row >= 0 && !attackTable.isRowSelected(row)) {
                    attackTable.setRowSelectionInterval(row, row)
                }

                val menu = JPopupMenu()
                
                // Burp Actions
                menu.add(JMenuItem("Send to Repeater").apply {
                    addActionListener {
                        processContextSelection { entry ->
                            entry.getRequestBytes()?.let { req ->
                                api.repeater().sendToRepeater(
                                    HttpRequest.httpRequest(burp.api.montoya.core.ByteArray.byteArray(*req)),
                                    entry.url // Name
                                )
                            }
                        }
                    }
                })
                
                menu.add(JMenuItem("Send to Intruder").apply {
                    addActionListener {
                        processContextSelection { entry ->
                             entry.getRequestBytes()?.let { req ->
                                val service = burp.api.montoya.http.HttpService.httpService(entry.host, entry.port, entry.protocol == "https")
                                val request = HttpRequest.httpRequest(service, burp.api.montoya.core.ByteArray.byteArray(*req))
                                api.intruder().sendToIntruder(request)
                            }
                        }
                    }
                })
                
                menu.addSeparator()

                // Management Actions
                val isTrashMode = trashToggle.isSelected
                if (isTrashMode) {
                    menu.add(JMenuItem("Restore").apply { 
                         addActionListener { restoreSelected(getContextSelectedIds()) } 
                    })
                    menu.add(JMenuItem("Delete Permanently").apply { 
                        addActionListener { deleteSelected(getContextSelectedIds()) } 
                    })
                } else {
                    menu.add(JMenuItem("Delete").apply { 
                        addActionListener { deleteSelected(getContextSelectedIds()) } 
                    })
                }

                menu.show(e.component, e.x, e.y)
            }
        })

        // Request/Response Viewers using Montoya UI factory
        requestViewer = api.userInterface().createHttpRequestEditor()
        responseViewer = api.userInterface().createHttpResponseEditor()

        // Details Panel (Notes)
        val detailsPanel = JPanel(BorderLayout()).apply {
            border = BorderFactory.createTitledBorder("Notes")
        }
        notesDetailArea = JTextArea().apply { isEditable = false }
        detailsPanel.add(JScrollPane(notesDetailArea), BorderLayout.CENTER)

        // Tabs for Request/Response
        val messageTabs = JTabbedPane()
        messageTabs.addTab("Request", requestViewer.uiComponent())
        messageTabs.addTab("Response", responseViewer.uiComponent())
        messageTabs.addTab("Details", detailsPanel)

        // Split Pane
        val splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT).apply {
            topComponent = JScrollPane(attackTable)
            bottomComponent = messageTabs
            resizeWeight = 0.5
        }

        historyPanel.add(splitPane, BorderLayout.CENTER)

        attackTable.selectionModel.addListSelectionListener { e ->
            if (!e.valueIsAdjusting) {
                val selectedRow = attackTable.selectedRow
                if (selectedRow != -1) {
                    val modelRow = attackTable.convertRowIndexToModel(selectedRow)
                    val entry = tableModel.getAttackAt(modelRow)
                    if (entry != null) {
                        val requestBytes = entry.getRequestBytes()
                        val responseBytes = entry.getResponseBytes()

                        requestViewer.setRequest(
                            requestBytes?.let { HttpRequest.httpRequest(byteArray(*it)) }
                        )
                        responseViewer.setResponse(
                            responseBytes?.let { HttpResponse.httpResponse(byteArray(*it)) }
                        )

                        /**
                         * Safety: Always sanitize user input before rendering it in any custom Burp UI tabs.
                         * Why: Prevents potential XSS vulnerabilities within the Burp Suite UI context
                         * when viewing notes provided by other testers or imported data.
                         */
                        val sanitizedNotes = entry.notes
                            .replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                            .replace("\"", "&quot;")
                            .replace("'", "&#x27;")
                        notesDetailArea.text = "Category: ${entry.category}\nStatus: ${entry.status}\n\n$sanitizedNotes"
                    }
                }
            }
        }

        mainTabs.addTab("Attack History", historyPanel)

        // --- Tab 2: Settings ---
        val settingsPanel = SettingsPanel(storageManager, backgroundExecutor)
        mainTabs.addTab("Settings", settingsPanel)

        mainPanel.add(mainTabs, BorderLayout.CENTER)
        return mainPanel
    }

    private fun contextMenuItemsProvider(): ContextMenuItemsProvider {
        return object : ContextMenuItemsProvider {
            override fun provideMenuItems(invocation: ContextMenuEvent): List<Component> {
                val menuList = mutableListOf<Component>()
                val messages = invocation.selectedRequestResponses()

                if (messages.isNotEmpty()) {
                    val saveItem = JMenuItem("Save to Attack History")
                    saveItem.addActionListener {
                        backgroundExecutor.execute {
                            val config = storageManager.loadConfig()
                            SwingUtilities.invokeLater {
                                val parent = JOptionPane.getFrameForComponent(mainPanel)
                                val dialog = SaveAttackDialog(parent, config)
                                dialog.isVisible = true

                                if (dialog.isSaved) {
                                    backgroundExecutor.execute {
                                        messages.forEach { message ->
                                            val entry = AttackEntry(
                                                message,
                                                config.testerName,
                                                dialog.category,
                                                dialog.status,
                                                dialog.notes
                                            )
                                            storageManager.saveAttack(entry)
                                            logging.logToOutput("Saved attack: ${entry.url}")
                                        }
                                        refreshTable()
                                    }
                                }
                            }
                        }
                    }
                    menuList.add(saveItem)
                }
                return menuList
            }
        }
    }

    private fun updateToolbarState() {
        val isTrashMode = trashToggle.isSelected
        deleteButton.text = if (isTrashMode) "Delete Permanently" else "Delete Selected"
        restoreButton.isVisible = isTrashMode
        emptyTrashButton.isVisible = isTrashMode
    }

    private fun refreshTable() {
        backgroundExecutor.execute {
            val attacks = storageManager.loadAttacks()
            SwingUtilities.invokeLater { tableModel.setAttacks(attacks) }
        }
    }

    private fun deleteSelected(ids: Set<String> = tableModel.getSelectedIds()) {
        if (ids.isEmpty()) return

        val isTrashMode = trashToggle.isSelected
        if (isTrashMode) {
            val confirm = JOptionPane.showConfirmDialog(
                mainPanel,
                "Permanently delete ${ids.size} items?",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION
            )
            if (confirm != JOptionPane.YES_OPTION) return
        }

        backgroundExecutor.execute {
            val updatedAttacks = storageManager.deleteAttacks(ids, isTrashMode)
            SwingUtilities.invokeLater { tableModel.setAttacks(updatedAttacks) }
        }
    }

    private fun restoreSelected(ids: Set<String> = tableModel.getSelectedIds()) {
        if (ids.isEmpty()) return

        backgroundExecutor.execute {
            val updatedAttacks = storageManager.restoreAttacks(ids)
            SwingUtilities.invokeLater { tableModel.setAttacks(updatedAttacks) }
        }
    }

    private fun emptyTrash() {
        val confirm = JOptionPane.showConfirmDialog(
            mainPanel,
            "Empty all items from trash?",
            "Empty Trash",
            JOptionPane.YES_NO_OPTION
        )

        if (confirm == JOptionPane.YES_OPTION) {
            backgroundExecutor.execute {
                val updatedAttacks = storageManager.emptyTrash()
                SwingUtilities.invokeLater { tableModel.setAttacks(updatedAttacks) }
            }
        }
    }


    private fun getContextSelectedAttacks(): List<AttackEntry> {
        return attackTable.selectedRows.toList().mapNotNull { viewRow ->
            val modelRow = attackTable.convertRowIndexToModel(viewRow)
            tableModel.getAttackAt(modelRow)
        }
    }

    private fun processContextSelection(action: (AttackEntry) -> Unit) {
        getContextSelectedAttacks().forEach(action)
    }

    private fun getContextSelectedIds(): Set<String> {
        return getContextSelectedAttacks().map { it.id }.toSet()
    }
}
