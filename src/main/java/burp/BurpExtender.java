package burp;

import javax.swing.*;
import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

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


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        // Initialize Storage
        String storagePath = System.getProperty("user.home") + "/.burp_attack_history.json";
        this.storageManager = new StorageManager(storagePath, stderr);

        // Register Context Menu
        callbacks.registerContextMenuFactory(this);

        // Initialize UI
        SwingUtilities.invokeLater(this::initializeUI);

        stdout.println("Attack History Recorder Loaded.");
        stdout.println("Saving to: " + storagePath);
    }

    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout());

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

        mainPanel.add(splitPane, BorderLayout.CENTER);
        
        // Refresh Button
        JButton refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> refreshTable());
        mainPanel.add(refreshButton, BorderLayout.NORTH);

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

        callbacks.addSuiteTab(BurpExtender.this);
    }

    private void refreshTable() {
        List<AttackEntry> attacks = storageManager.loadAttacks();
        tableModel.setAttacks(attacks);
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
                    // Find parent window for dialog
                    Frame parent = JOptionPane.getFrameForComponent(getUiComponent());
                    SaveAttackDialog dialog = new SaveAttackDialog(parent);
                    dialog.setVisible(true);

                    if (dialog.isSaved()) {
                        for (IHttpRequestResponse message : messages) {
                            AttackEntry entry = new AttackEntry(
                                message, 
                                helpers, 
                                "Tester", // TODO: Make configurable
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

