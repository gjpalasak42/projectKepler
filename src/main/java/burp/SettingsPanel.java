package burp;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.stream.Collectors;

public class SettingsPanel extends JPanel {
    private final StorageManager storageManager;
    private final ExecutorService backgroundExecutor;
    private final JTextField testerNameField;
    private final JTextArea categoriesArea;
    private final JTextArea statusesArea;

    public SettingsPanel(StorageManager storageManager, ExecutorService backgroundExecutor) {
        this.storageManager = storageManager;
        this.backgroundExecutor = backgroundExecutor;
        setLayout(new BorderLayout());

        // Form Panel
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.NORTHWEST;

        // Tester Name
        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("Tester Name:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        testerNameField = new JTextField(20);
        formPanel.add(testerNameField, gbc);

        // Categories
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        formPanel.add(new JLabel("Categories (one per line):"), gbc);

        gbc.gridx = 1; gbc.weightx = 1.0; gbc.weighty = 0.5; gbc.fill = GridBagConstraints.BOTH;
        categoriesArea = new JTextArea(10, 30);
        formPanel.add(new JScrollPane(categoriesArea), gbc);

        // Statuses
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0; gbc.weighty = 0; gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(new JLabel("Statuses (one per line):"), gbc);

        gbc.gridx = 1; gbc.weightx = 1.0; gbc.weighty = 0.5; gbc.fill = GridBagConstraints.BOTH;
        statusesArea = new JTextArea(5, 30);
        formPanel.add(new JScrollPane(statusesArea), gbc);

        add(formPanel, BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton exportButton = new JButton("Export History");
        exportButton.addActionListener(e -> exportHistory());
        buttonPanel.add(exportButton);

        JButton importButton = new JButton("Import History");
        importButton.addActionListener(e -> importHistory());
        buttonPanel.add(importButton);

        JButton saveButton = new JButton("Save Settings");
        saveButton.addActionListener(e -> saveSettings());
        buttonPanel.add(saveButton);
        
        add(buttonPanel, BorderLayout.SOUTH);

        // Load initial values asynchronously
        loadSettingsAsync();
    }

    private void loadSettingsAsync() {
        // Load config off the EDT to prevent UI blocking during initialization
        backgroundExecutor.execute(() -> {
            ExtensionConfig config = storageManager.loadConfig();
            // Update UI on the EDT
            SwingUtilities.invokeLater(() -> {
                testerNameField.setText(config.getTesterName());
                categoriesArea.setText(String.join("\n", config.getCategories()));
                statusesArea.setText(String.join("\n", config.getStatuses()));
            });
        });
    }

    private void saveSettings() {
        ExtensionConfig config = new ExtensionConfig();
        config.setTesterName(testerNameField.getText().trim());
        
        List<String> categories = Arrays.stream(categoriesArea.getText().split("\n"))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .collect(Collectors.toList());
        config.setCategories(categories);

        List<String> statuses = Arrays.stream(statusesArea.getText().split("\n"))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .collect(Collectors.toList());
        config.setStatuses(statuses);

        // Save config off the EDT
        backgroundExecutor.execute(() -> {
            storageManager.saveConfig(config);
            SwingUtilities.invokeLater(() -> 
                JOptionPane.showMessageDialog(SettingsPanel.this, "Settings Saved!", "Success", JOptionPane.INFORMATION_MESSAGE)
            );
        });
    }

    private void exportHistory() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Attack History");
        int userSelection = fileChooser.showSaveDialog(this);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            java.io.File fileToSave = fileChooser.getSelectedFile();
            if (!fileToSave.getName().toLowerCase().endsWith(".json")) {
                fileToSave = new java.io.File(fileToSave.getAbsolutePath() + ".json");
            }
            final java.io.File finalFileToSave = fileToSave;
            backgroundExecutor.execute(() -> {
                try {
                    storageManager.exportAttacks(finalFileToSave);
                    SwingUtilities.invokeLater(() -> 
                        JOptionPane.showMessageDialog(SettingsPanel.this, "History exported successfully!", "Success", JOptionPane.INFORMATION_MESSAGE)
                    );
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> 
                        JOptionPane.showMessageDialog(SettingsPanel.this, "Error exporting history: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE)
                    );
                }
            });
        }
    }

    private void importHistory() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Import Attack History");
        int userSelection = fileChooser.showOpenDialog(this);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            java.io.File fileToOpen = fileChooser.getSelectedFile();
            backgroundExecutor.execute(() -> {
                try {
                    storageManager.importAttacks(fileToOpen);
                    SwingUtilities.invokeLater(() -> 
                        JOptionPane.showMessageDialog(SettingsPanel.this, "History imported successfully! Please refresh the Attack History tab to see the imported entries.", "Success", JOptionPane.INFORMATION_MESSAGE)
                    );
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> 
                        JOptionPane.showMessageDialog(SettingsPanel.this, "Error importing history: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE)
                    );
                }
            });
        }
    }
}
