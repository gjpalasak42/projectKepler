package burp;

import javax.swing.*;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class CheckBoxHeader extends JCheckBox implements TableCellRenderer {
    private final JTable table;
    private final int targetColumnIndex;

    public CheckBoxHeader(JTable table, int targetColumnIndex) {
        this.table = table;
        this.targetColumnIndex = targetColumnIndex;
        this.setHorizontalAlignment(JLabel.CENTER);
        this.setOpaque(true); // Make sure background is painted
        
        // Add mouse listener to table header
        JTableHeader header = table.getTableHeader();
        header.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                handleClick(e);
            }
        });
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                   boolean isSelected, boolean hasFocus, int row, int column) {
        // Inherit background/foreground from header
        JTableHeader header = table.getTableHeader();
        if (header != null) {
            setForeground(header.getForeground());
            setBackground(header.getBackground());
            setFont(header.getFont());
        }
        
        // Set state based on whether all items are selected
        if (table.getModel() instanceof AttackTableModel) {
            setSelected(((AttackTableModel) table.getModel()).isAllSelected());
        }
        
        // Add a border to look like a header
        setBorder(UIManager.getBorder("TableHeader.cellBorder"));
        
        return this;
    }

    private void handleClick(MouseEvent e) {
        int columnIndex = table.getColumnModel().getColumnIndexAtX(e.getX());
        if (columnIndex == targetColumnIndex) {
            // Toggle state
            boolean newState = !isSelected();
            setSelected(newState);
            
            // Force repaint of header
            table.getTableHeader().repaint();
            
            // Notify listener (we'll implement this via callback or direct model access)
            // Ideally, we fire an event. For simplicity, let's assume the model handles it.
            // But we need to update the model.
            
            // This is tricky because renderer is just a component.
            // We need to store the "all selected" state somewhere.
            // Let's assume the TableModel has a method for this.
            if (table.getModel() instanceof AttackTableModel) {
                ((AttackTableModel) table.getModel()).setAllSelected(newState);
            }
        }
    }
}
