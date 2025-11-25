package burp;

import javax.swing.*;
import java.awt.*;

public class SaveAttackDialog extends JDialog {
    private JComboBox<String> categoryComboBox;
    private JComboBox<String> statusComboBox;
    private JTextArea notesArea;
    private boolean saved = false;

    public SaveAttackDialog(Frame owner, ExtensionConfig config) {
        super(owner, "Save Attack to History", true);
        initComponents(config);
        pack();
        setLocationRelativeTo(owner);
    }

    private void initComponents(ExtensionConfig config) {
        setLayout(new BorderLayout(10, 10));
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Category
        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("Category:"), gbc);
        
        gbc.gridx = 1;
        categoryComboBox = new JComboBox<>(config.getCategories().toArray(new String[0]));
        categoryComboBox.setEditable(true); // Allow custom categories
        formPanel.add(categoryComboBox, gbc);

        // Status
        gbc.gridx = 0; gbc.gridy = 1;
        formPanel.add(new JLabel("Status:"), gbc);

        gbc.gridx = 1;
        statusComboBox = new JComboBox<>(config.getStatuses().toArray(new String[0]));
        formPanel.add(statusComboBox, gbc);

        // Notes
        gbc.gridx = 0; gbc.gridy = 2;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        formPanel.add(new JLabel("Notes:"), gbc);

        gbc.gridx = 1;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        notesArea = new JTextArea(5, 30);
        notesArea.setLineWrap(true);
        notesArea.setWrapStyleWord(true);
        formPanel.add(new JScrollPane(notesArea), gbc);

        add(formPanel, BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveButton = new JButton("Save");
        JButton cancelButton = new JButton("Cancel");

        saveButton.addActionListener(e -> {
            saved = true;
            dispose();
        });

        cancelButton.addActionListener(e -> dispose());

        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    public boolean isSaved() { return saved; }
    public String getCategory() { return (String) categoryComboBox.getSelectedItem(); }
    public String getStatus() { return (String) statusComboBox.getSelectedItem(); }
    public String getNotes() { return notesArea.getText(); }
}
