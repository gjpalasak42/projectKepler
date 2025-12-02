package burp;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ITab, IMessageEditorController {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private StorageManager storageManager;
    private JPanel mainPanel;
    
    // Background executor for file I/O operations
    private final ExecutorService backgroundExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "AttackHistory-IO");
        t.setDaemon(true);
        return t;
    });
    
    // UI Components
    private JTable attackTable;
    private AttackTableModel tableModel;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse currentMessage;
    private JTextArea notesDetailArea;
    private JToggleButton trashToggle;
    private JButton deleteButton;
    private JButton restoreButton;
    private JButton emptyTrashButton;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        // Initialize Storage
        String storagePath = System.getProperty("user.home") + "/.burp_attack_history.json";
        String configPath = System.getProperty("user.home") + "/.burp_attack_history_config.json";
        this.storageManager = new StorageManager(storagePath, configPath, stderr);

        // Register Context Menu
        callbacks.registerContextMenuFactory(this);

        // Initialize UI
        SwingUtilities.invokeLater(() -> {
            initializeUI();
            callbacks.addSuiteTab(BurpExtender.this);
            // Load data after UI is fully initialized and visible
            refreshTable();
        });

        stdout.println("Attack History Recorder Loaded.");
        stdout.println("Saving to: " + storagePath);
    }

    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout());
        JTabbedPane mainTabs = new JTabbedPane();

        // --- Tab 1: Attack History ---
        JPanel historyPanel = new JPanel(new BorderLayout());

        // Toolbar
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        
        JButton refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> refreshTable());
        toolbar.add(refreshButton);
        
        toolbar.addSeparator();
        
        trashToggle = new JToggleButton("Show Trash");
        trashToggle.addActionListener(e -> {
            tableModel.setShowDeleted(trashToggle.isSelected());
            updateToolbarState();
        });
        toolbar.add(trashToggle);
        
        toolbar.addSeparator();
        
        deleteButton = new JButton("Delete Selected");
        deleteButton.addActionListener(e -> deleteSelected());
        toolbar.add(deleteButton);
        
        restoreButton = new JButton("Restore Selected");
        restoreButton.addActionListener(e -> restoreSelected());
        restoreButton.setVisible(false); // Hidden by default
        toolbar.add(restoreButton);
        
        emptyTrashButton = new JButton("Empty Trash");
        emptyTrashButton.addActionListener(e -> emptyTrash());
        emptyTrashButton.setVisible(false); // Hidden by default
        toolbar.add(emptyTrashButton);

        historyPanel.add(toolbar, BorderLayout.NORTH);

        // Table Setup
        tableModel = new AttackTableModel();
        attackTable = new JTable(tableModel);
        attackTable.setAutoCreateRowSorter(true);
        
        // Set checkbox column width and header
        attackTable.getColumnModel().getColumn(0).setMaxWidth(30);
        attackTable.getColumnModel().getColumn(0).setMinWidth(30);
        attackTable.getColumnModel().getColumn(0).setHeaderRenderer(new CheckBoxHeader(attackTable, 0));
        
        // Context Menu for Table
        JPopupMenu tablePopup = new JPopupMenu();
        JMenuItem deleteItem = new JMenuItem("Delete");
        deleteItem.addActionListener(e -> deleteSelected());
        tablePopup.add(deleteItem);
        
        JMenuItem restoreItem = new JMenuItem("Restore");
        restoreItem.addActionListener(e -> restoreSelected());
        tablePopup.add(restoreItem);

        attackTable.setComponentPopupMenu(tablePopup);
        
        // Defer loading data until after UI is fully initialized

        // Request/Response Viewers
        requestViewer = callbacks.createMessageEditor(this, false);
        responseViewer = callbacks.createMessageEditor(this, false);

        // Details Panel (Notes)
        JPanel detailsPanel = new JPanel(new BorderLayout());
        detailsPanel.setBorder(BorderFactory.createTitledBorder("Notes"));
        notesDetailArea = new JTextArea();
        notesDetailArea.setEditable(false); // Read-only in this view for now
        detailsPanel.add(new JScrollPane(notesDetailArea), BorderLayout.CENTER);

        // Tabs for Request/Response
        JTabbedPane messageTabs = new JTabbedPane();
        messageTabs.addTab("Request", requestViewer.getComponent());
        messageTabs.addTab("Response", responseViewer.getComponent());
        messageTabs.addTab("Details", detailsPanel);

        // Split Pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(new JScrollPane(attackTable));
        splitPane.setBottomComponent(messageTabs);
        splitPane.setResizeWeight(0.5);

        historyPanel.add(splitPane, BorderLayout.CENTER);
        
        // Selection Listener
        attackTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = attackTable.getSelectedRow();
                if (selectedRow != -1) {
                    int modelRow = attackTable.convertRowIndexToModel(selectedRow);
                    AttackEntry entry = tableModel.getAttackAt(modelRow);
                    if (entry != null) {
                        requestViewer.setMessage(entry.getRequest(), true);
                        responseViewer.setMessage(entry.getResponse(), false);
                        notesDetailArea.setText("Category: " + entry.getCategory() + "\n" +
                                              "Status: " + entry.getStatus() + "\n\n" +
                                              entry.getNotes());
                        currentMessage = new IHttpRequestResponse() { // Simple wrapper for the controller
                            @Override public byte[] getRequest() { return entry.getRequest(); }
                            @Override public void setRequest(byte[] message) {}
                            @Override public byte[] getResponse() { return entry.getResponse(); }
                            @Override public void setResponse(byte[] message) {}
                            @Override public String getComment() { return entry.getNotes(); }
                            @Override public void setComment(String comment) {}
                            @Override public String getHighlight() { return null; }
                            @Override public void setHighlight(String color) {}
                            @Override public IHttpService getHttpService() {
                                return helpers.buildHttpService(entry.getHost(), entry.getPort(), entry.getProtocol());
                            }
                            @Override public void setHttpService(IHttpService httpService) {}
                        };
                    }
                }
            }
        });

        mainTabs.addTab("Attack History", historyPanel);

        // --- Tab 2: Settings ---
        SettingsPanel settingsPanel = new SettingsPanel(storageManager, backgroundExecutor);
        mainTabs.addTab("Settings", settingsPanel);

        mainPanel.add(mainTabs, BorderLayout.CENTER);
    }
    
    private void updateToolbarState() {
        boolean isTrashMode = trashToggle.isSelected();
        deleteButton.setVisible(!isTrashMode);
        restoreButton.setVisible(isTrashMode);
        emptyTrashButton.setVisible(isTrashMode);
        
        // Update context menu items visibility if possible, or just handle in logic
        // For simplicity, we'll leave them but they might not do anything if invalid
    }

    private void refreshTable() {
        // Run file I/O off the EDT to prevent UI blocking
        backgroundExecutor.execute(() -> {
            List<AttackEntry> attacks = storageManager.loadAttacks();
            // Update UI on the EDT
            SwingUtilities.invokeLater(() -> tableModel.setAttacks(attacks));
        });
    }
    
    private void deleteSelected() {
        Set<String> selectedIds = tableModel.getSelectedIds();
        int[] selectedRows = attackTable.getSelectedRows();
        for (int row : selectedRows) {
            int modelRow = attackTable.convertRowIndexToModel(row);
            AttackEntry entry = tableModel.getAttackAt(modelRow);
            if (entry != null) {
                selectedIds.add(entry.getId());
            }
        }

        if (selectedIds.isEmpty()) return;

        // Capture toggle state on the EDT before running background task
        final boolean isTrashMode = trashToggle.isSelected();
        
        backgroundExecutor.execute(() -> {
            List<AttackEntry> allAttacks = storageManager.loadAttacks();
            boolean changed = false;
            
            if (isTrashMode) {
                 // Permanent deletion
                 int initialSize = allAttacks.size();
                 allAttacks.removeIf(a -> selectedIds.contains(a.getId()));
                 if (allAttacks.size() < initialSize) changed = true;
            } else {
                for (AttackEntry attack : allAttacks) {
                    if (selectedIds.contains(attack.getId())) {
                        attack.setDeleted(true);
                        changed = true;
                    }
                }
            }

            if (changed) {
                 storageManager.overwriteAttacks(allAttacks); 
            }
            
            // Refresh UI on the EDT
            refreshTable();
        });
    }

    private void restoreSelected() {
        Set<String> selectedIds = tableModel.getSelectedIds();
        int[] selectedRows = attackTable.getSelectedRows();
        for (int row : selectedRows) {
            int modelRow = attackTable.convertRowIndexToModel(row);
            AttackEntry entry = tableModel.getAttackAt(modelRow);
            if (entry != null) {
                selectedIds.add(entry.getId());
            }
        }

        if (selectedIds.isEmpty()) return;

        backgroundExecutor.execute(() -> {
            List<AttackEntry> allAttacks = storageManager.loadAttacks();
            boolean changed = false;
            
            for (AttackEntry attack : allAttacks) {
                if (selectedIds.contains(attack.getId())) {
                    attack.setDeleted(false);
                    changed = true;
                }
            }

            if (changed) {
                storageManager.overwriteAttacks(allAttacks);
            }
            
            // Refresh UI on the EDT
            refreshTable();
        });
    }
    
    private void emptyTrash() {
        int confirm = JOptionPane.showConfirmDialog(mainPanel, 
            "Are you sure you want to permanently delete all items in the trash?", 
            "Empty Trash", 
            JOptionPane.YES_NO_OPTION);
            
        if (confirm == JOptionPane.YES_OPTION) {
            backgroundExecutor.execute(() -> {
                List<AttackEntry> allAttacks = storageManager.loadAttacks();
                allAttacks.removeIf(AttackEntry::isDeleted);
                storageManager.overwriteAttacks(allAttacks);
                
                // Refresh UI on the EDT
                refreshTable();
            });
        }
    }


    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuList = new ArrayList<>();
        JMenuItem saveItem = new JMenuItem("Save to Attack History");
        
        saveItem.addActionListener(e -> {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            if (messages != null && messages.length > 0) {
                // Load config off the EDT first, then show dialog
                backgroundExecutor.execute(() -> {
                    ExtensionConfig config = storageManager.loadConfig();
                    
                    // Show dialog on the EDT
                    SwingUtilities.invokeLater(() -> {
                        Frame parent = JOptionPane.getFrameForComponent(getUiComponent());
                        SaveAttackDialog dialog = new SaveAttackDialog(parent, config);
                        dialog.setVisible(true);

                        if (dialog.isSaved()) {
                            // Capture dialog values on the EDT
                            String category = dialog.getCategory();
                            String status = dialog.getStatus();
                            String notes = dialog.getNotes();
                            String testerName = config.getTesterName();
                            
                            // Save attacks off the EDT
                            backgroundExecutor.execute(() -> {
                                for (IHttpRequestResponse message : messages) {
                                    AttackEntry entry = new AttackEntry(
                                        message, 
                                        helpers, 
                                        testerName, 
                                        category, 
                                        status, 
                                        notes
                                    );
                                    storageManager.saveAttack(entry);
                                    stdout.println("Saved attack: " + entry.getUrl());
                                }
                                // Refresh UI after all saves complete
                                refreshTable();
                            });
                        }
                    });
                });
            }
        });

        menuList.add(saveItem);
        return menuList;
    }

    @Override
    public String getTabCaption() {
        return "Attack History";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    // IMessageEditorController Implementation
    @Override
    public IHttpService getHttpService() {
        return currentMessage != null ? currentMessage.getHttpService() : null;
    }

    @Override
    public byte[] getRequest() {
        return currentMessage != null ? currentMessage.getRequest() : null;
    }

    @Override
    public byte[] getResponse() {
        return currentMessage != null ? currentMessage.getResponse() : null;
    }
}
