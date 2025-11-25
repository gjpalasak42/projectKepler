package burp;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private StorageManager storageManager;
    private JPanel mainPanel;

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

        // Initialize UI (Placeholder for now)
        SwingUtilities.invokeLater(() -> {
            mainPanel = new JPanel(new BorderLayout());
            mainPanel.add(new JLabel("Attack History Table will go here"), BorderLayout.CENTER);
            callbacks.addSuiteTab(BurpExtender.this);
        });

        stdout.println("Attack History Recorder Loaded.");
        stdout.println("Saving to: " + storagePath);
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
}
