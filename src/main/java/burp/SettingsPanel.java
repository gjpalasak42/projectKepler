package burp;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class SettingsPanel extends JPanel {
    private final StorageManager storageManager;
    private final JTextField testerNameField;
    private final JTextArea categoriesArea;
    private final JTextArea statusesArea;

    public SettingsPanel(StorageManager storageManager) {
        this.storageManager = storageManager;
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
        JButton saveButton = new JButton("Save Settings");
        saveButton.addActionListener(e -> saveSettings());
        buttonPanel.add(saveButton);
        add(buttonPanel, BorderLayout.SOUTH);

        // Load initial values
        loadSettings();
    }

    private void loadSettings() {
        ExtensionConfig config = storageManager.loadConfig();
        testerNameField.setText(config.getTesterName());
        categoriesArea.setText(String.join("\n", config.getCategories()));
        statusesArea.setText(String.join("\n", config.getStatuses()));
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

        storageManager.saveConfig(config);
        JOptionPane.showMessageDialog(this, "Settings Saved!", "Success", JOptionPane.INFORMATION_MESSAGE);
    }
}
