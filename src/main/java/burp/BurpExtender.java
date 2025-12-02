package burp;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
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
        SwingUtilities.invokeLater(this::initializeUI);

        stdout.println("Attack History Recorder Loaded.");
        stdout.println("Saving to: " + storagePath);
    }

    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout());
        JTabbedPane mainTabs = new JTabbedPane();

        // --- Tab 1: Attack History ---
        JPanel historyPanel = new JPanel(new BorderLayout());

        // Table Setup
        tableModel = new AttackTableModel();
        attackTable = new JTable(tableModel);
        attackTable.setAutoCreateRowSorter(true);
        
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
        
        // Refresh Button
        JButton refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> refreshTable());
        historyPanel.add(refreshButton, BorderLayout.NORTH);

        // Selection Listener
        attackTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = attackTable.getSelectedRow();
                if (selectedRow != -1) {
                    int modelRow = attackTable.convertRowIndexToModel(selectedRow);
                    AttackEntry entry = tableModel.getAttackAt(modelRow);
                    if (entry != null) {
                        // currentMessage = callbacks.getHelpers().buildHttpMessage(entry.getRequest(), entry.getResponse()); // Incorrect and unnecessary
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

        callbacks.addSuiteTab(BurpExtender.this);
    }

    private void refreshTable() {
        // Run file I/O off the EDT to prevent UI blocking
        backgroundExecutor.execute(() -> {
            List<AttackEntry> attacks = storageManager.loadAttacks();
            // Update UI on the EDT
            SwingUtilities.invokeLater(() -> tableModel.setAttacks(attacks));
        });
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

