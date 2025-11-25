package burp;

import javax.swing.table.AbstractTableModel;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class AttackTableModel extends AbstractTableModel {
    private List<AttackEntry> attacks;
    private final String[] columnNames = {"Time", "Category", "Method", "URL", "Status", "Tester"};
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public AttackTableModel() {
        this.attacks = new ArrayList<>();
    }

    public void setAttacks(List<AttackEntry> attacks) {
        this.attacks = attacks;
        fireTableDataChanged();
    }

    public AttackEntry getAttackAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < attacks.size()) {
            return attacks.get(rowIndex);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return attacks.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        AttackEntry attack = attacks.get(rowIndex);
        switch (columnIndex) {
            case 0: return dateFormat.format(new Date(attack.getTimestamp()));
            case 1: return attack.getCategory();
            case 2: return attack.getMethod();
            case 3: return attack.getUrl();
            case 4: return attack.getStatus();
            case 5: return attack.getTesterName();
            default: return "";
        }
    }
}
