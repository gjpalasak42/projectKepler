package burp;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ITab, IMessageEditorController {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private StorageManager storageManager;
    private JPanel mainPanel;
    
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
        
        // Load initial data
        refreshTable();

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
        SettingsPanel settingsPanel = new SettingsPanel(storageManager);
        mainTabs.addTab("Settings", settingsPanel);

        mainPanel.add(mainTabs, BorderLayout.CENTER);

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
        new SwingWorker<List<AttackEntry>, Void>() {
            @Override
            protected List<AttackEntry> doInBackground() throws Exception {
                return storageManager.loadAttacks();
            }

            @Override
            protected void done() {
                try {
                    List<AttackEntry> attacks = get();
                    tableModel.setAttacks(attacks);
                } catch (Exception e) {
                    stderr.println("Error refreshing table: " + e.getMessage());
                    e.printStackTrace(stderr);
                }
            }
        }.execute();
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

        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                List<AttackEntry> allAttacks = storageManager.loadAttacks();
                boolean changed = false;
                
                if (trashToggle.isSelected()) {
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
                return null;
            }

            @Override
            protected void done() {
                try {
                    get(); // Check for exceptions
                    refreshTable();
                } catch (Exception e) {
                    stderr.println("Error deleting attacks: " + e.getMessage());
                    e.printStackTrace(stderr);
                }
            }
        }.execute();
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

        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
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
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    refreshTable();
                } catch (Exception e) {
                    stderr.println("Error restoring attacks: " + e.getMessage());
                    e.printStackTrace(stderr);
                }
            }
        }.execute();
    }
    
    private void emptyTrash() {
        int confirm = JOptionPane.showConfirmDialog(mainPanel, 
            "Are you sure you want to permanently delete all items in the trash?", 
            "Empty Trash", 
            JOptionPane.YES_NO_OPTION);
            
        if (confirm == JOptionPane.YES_OPTION) {
            new SwingWorker<Void, Void>() {
                @Override
                protected Void doInBackground() throws Exception {
                    List<AttackEntry> allAttacks = storageManager.loadAttacks();
                    allAttacks.removeIf(AttackEntry::isDeleted);
                    storageManager.overwriteAttacks(allAttacks);
                    return null;
                }

                @Override
                protected void done() {
                    try {
                        get();
                        refreshTable();
                    } catch (Exception e) {
                        stderr.println("Error emptying trash: " + e.getMessage());
                        e.printStackTrace(stderr);
                    }
                }
            }.execute();
        }
    }


    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuList = new ArrayList<>();
        JMenuItem saveItem = new JMenuItem("Save to Attack History");
        
        saveItem.addActionListener(e -> {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            if (messages != null && messages.length > 0) {
                // Show Dialog
                SwingUtilities.invokeLater(() -> {
                    // Load Config
                    ExtensionConfig config = storageManager.loadConfig();

                    // Find parent window for dialog
                    Frame parent = JOptionPane.getFrameForComponent(getUiComponent());
                    SaveAttackDialog dialog = new SaveAttackDialog(parent, config);
                    dialog.setVisible(true);

                    if (dialog.isSaved()) {
                        for (IHttpRequestResponse message : messages) {
                            AttackEntry entry = new AttackEntry(
                                message, 
                                helpers, 
                                config.getTesterName(), 
                                dialog.getCategory(), 
                                dialog.getStatus(), 
                                dialog.getNotes()
                            );
                            storageManager.saveAttack(entry);
                            stdout.println("Saved attack: " + entry.getUrl());
                            SwingUtilities.invokeLater(this::refreshTable); // Refresh UI after save
                        }
                    }
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
