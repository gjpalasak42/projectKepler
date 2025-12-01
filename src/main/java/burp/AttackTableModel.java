package burp;

import javax.swing.table.AbstractTableModel;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class AttackTableModel extends AbstractTableModel {
    private List<AttackEntry> allAttacks;
    private List<AttackEntry> displayedAttacks;
    private final String[] columnNames = {"", "Time", "Category", "Method", "URL", "Status", "Tester"}; // Added empty column for checkbox
    private static final DateTimeFormatter DATE_FORMATTER = 
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());
    
    private boolean showDeleted = false;
    private Set<String> selectedIds = new HashSet<>();

    public AttackTableModel() {
        this.allAttacks = new ArrayList<>();
        this.displayedAttacks = new ArrayList<>();
    }

    public void setAttacks(List<AttackEntry> attacks) {
        this.allAttacks = attacks;
        refreshDisplay();
    }

    public void setShowDeleted(boolean showDeleted) {
        this.showDeleted = showDeleted;
        refreshDisplay();
    }
    
    public boolean isShowDeleted() {
        return showDeleted;
    }

    private void refreshDisplay() {
        if (showDeleted) {
            displayedAttacks = allAttacks.stream()
                .filter(AttackEntry::isDeleted)
                .collect(Collectors.toList());
        } else {
            displayedAttacks = allAttacks.stream()
                .filter(a -> !a.isDeleted())
                .collect(Collectors.toList());
        }
        // Clear selection when switching views or refreshing data to avoid confusion
        selectedIds.clear(); 
        fireTableDataChanged();
    }

    public AttackEntry getAttackAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < displayedAttacks.size()) {
            return displayedAttacks.get(rowIndex);
        }
        return null;
    }
    
    public List<AttackEntry> getDisplayedAttacks() {
        return displayedAttacks;
    }
    
    public Set<String> getSelectedIds() {
        return new HashSet<>(selectedIds);
    }
    
    public void setAllSelected(boolean selected) {
        if (selected) {
            for (AttackEntry attack : displayedAttacks) {
                selectedIds.add(attack.getId());
            }
        } else {
            selectedIds.clear();
        }
        fireTableDataChanged();
    }
    
    public boolean isAllSelected() {
        if (displayedAttacks.isEmpty()) return false;
        for (AttackEntry attack : displayedAttacks) {
            if (!selectedIds.contains(attack.getId())) {
                return false;
            }
        }
        return true;
    }

    public void clearSelection() {
        selectedIds.clear();
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return displayedAttacks.size();
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
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) {
            return Boolean.class;
        }
        return String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        AttackEntry attack = displayedAttacks.get(rowIndex);
        switch (columnIndex) {
            case 0: return selectedIds.contains(attack.getId());
            case 1: return DATE_FORMATTER.format(Instant.ofEpochMilli(attack.getTimestamp()));
            case 2: return attack.getCategory();
            case 3: return attack.getMethod();
            case 4: return attack.getUrl();
            case 5: return attack.getStatus();
            case 6: return attack.getTesterName();
            default: return "";
        }
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 0 && aValue instanceof Boolean) {
            AttackEntry attack = displayedAttacks.get(rowIndex);
            if ((Boolean) aValue) {
                selectedIds.add(attack.getId());
            } else {
                selectedIds.remove(attack.getId());
            }
            fireTableCellUpdated(rowIndex, columnIndex);
        }
    }
}
