package burp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.*;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class StorageManager {
    private final File storageFile;
    private final File configFile;
    private final Gson gson;
    private final PrintWriter stderr;

    public StorageManager(String storagePath, String configPath, PrintWriter stderr) {
        this.storageFile = new File(storagePath);
        this.configFile = new File(configPath);
        this.stderr = stderr;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
    }

    public synchronized void saveAttack(AttackEntry entry) {
        List<AttackEntry> attacks = loadAttacks();
        attacks.add(entry);
        saveAll(attacks);
        cachedAttacks = attacks;
        lastLoadedTime = storageFile.lastModified();
    }

    private long lastLoadedTime = 0;
    private List<AttackEntry> cachedAttacks = null;

    public synchronized List<AttackEntry> loadAttacks() {
        if (!storageFile.exists()) {
            cachedAttacks = new ArrayList<>();
            return cachedAttacks;
        }

        long lastModified = storageFile.lastModified();
        if (cachedAttacks != null && lastModified <= lastLoadedTime) {
            return new ArrayList<>(cachedAttacks); // Return copy to prevent external modification affecting cache
        }

        try (Reader reader = new FileReader(storageFile)) {
            Type listType = new TypeToken<ArrayList<AttackEntry>>(){}.getType();
            List<AttackEntry> attacks = gson.fromJson(reader, listType);
            if (attacks != null) {
                boolean modified = false;
                for (AttackEntry attack : attacks) {
                    if (attack.getId() == null || attack.getId().isEmpty()) {
                        attack.ensureId();
                        modified = true;
                    }
                }
                if (modified) {
                    saveAll(attacks);
                    // saveAll updates the file, so lastModified will change.
                    // We should update lastLoadedTime to the new lastModified.
                    lastModified = storageFile.lastModified();
                }
                
                cachedAttacks = attacks;
                lastLoadedTime = lastModified;
                return new ArrayList<>(cachedAttacks);
            }
            cachedAttacks = new ArrayList<>();
            return cachedAttacks;
        } catch (IOException e) {
            stderr.println("Error loading attacks: " + e.getMessage());
            e.printStackTrace(stderr);
            return new ArrayList<>();
        }
    }

    public synchronized void overwriteAttacks(List<AttackEntry> attacks) {
        saveAll(attacks);
        cachedAttacks = new ArrayList<>(attacks);
        lastLoadedTime = storageFile.lastModified();
    }

    public synchronized List<AttackEntry> deleteAttacks(Set<String> ids, boolean permanent) {
        List<AttackEntry> allAttacks = loadAttacks();
        boolean changed = false;

        if (permanent) {
            int initialSize = allAttacks.size();
            allAttacks.removeIf(a -> ids.contains(a.getId()));
            if (allAttacks.size() < initialSize) changed = true;
        } else {
            for (AttackEntry attack : allAttacks) {
                if (ids.contains(attack.getId())) {
                    attack.setDeleted(true);
                    changed = true;
                }
            }
        }

        if (changed) {
            saveAll(allAttacks);
        }
        return allAttacks;
    }

    public synchronized List<AttackEntry> restoreAttacks(Set<String> ids) {
        List<AttackEntry> allAttacks = loadAttacks();
        boolean changed = false;

        for (AttackEntry attack : allAttacks) {
            if (ids.contains(attack.getId())) {
                attack.setDeleted(false);
                changed = true;
            }
        }

        if (changed) {
            saveAll(allAttacks);
        }
        return allAttacks;
    }

    public synchronized List<AttackEntry> emptyTrash() {
        List<AttackEntry> allAttacks = loadAttacks();
        int initialSize = allAttacks.size();
        allAttacks.removeIf(AttackEntry::isDeleted);
        
        if (allAttacks.size() < initialSize) {
            saveAll(allAttacks);
        }
        return allAttacks;
    }

    private void saveAll(List<AttackEntry> attacks) {
        try (Writer writer = new FileWriter(storageFile)) {
            gson.toJson(attacks, writer);
            lastLoadedTime = storageFile.lastModified();
            cachedAttacks = new ArrayList<>(attacks); // Update cache
        } catch (IOException e) {
            // stderr.println("Error saving attacks: " + e.getMessage());
            // e.printStackTrace(stderr);
        }
    }

    public synchronized void saveConfig(ExtensionConfig config) {
        try (Writer writer = new FileWriter(configFile)) {
            gson.toJson(config, writer);
        } catch (IOException e) {
            stderr.println("Error saving config: " + e.getMessage());
            e.printStackTrace(stderr);
        }
    }

    public synchronized ExtensionConfig loadConfig() {
        if (!configFile.exists()) {
            return new ExtensionConfig(); // Return defaults
        }

        try (Reader reader = new FileReader(configFile)) {
            ExtensionConfig config = gson.fromJson(reader, ExtensionConfig.class);
            return config != null ? config : new ExtensionConfig();
        } catch (IOException e) {
            stderr.println("Error loading config: " + e.getMessage());
            e.printStackTrace(stderr);
            return new ExtensionConfig();
        }
    }
    public synchronized void exportAttacks(File destination) throws IOException {
        List<AttackEntry> attacks = loadAttacks();
        try (Writer writer = new FileWriter(destination)) {
            gson.toJson(attacks, writer);
        }
    }

    public synchronized void importAttacks(File source) throws IOException {
        if (!source.exists()) {
            throw new FileNotFoundException("Import file not found: " + source.getAbsolutePath());
        }

        try (Reader reader = new FileReader(source)) {
            Type listType = new TypeToken<ArrayList<AttackEntry>>(){}.getType();
            List<AttackEntry> importedAttacks = gson.fromJson(reader, listType);
            
            if (importedAttacks != null && !importedAttacks.isEmpty()) {
                List<AttackEntry> currentAttacks = loadAttacks();
                
                // Collect existing IDs to prevent duplicates
                java.util.Set<String> existingIds = new java.util.HashSet<>();
                for (AttackEntry entry : currentAttacks) {
                    if (entry.getId() != null) {
                        existingIds.add(entry.getId());
                    }
                }
                
                // Filter and add only unique imported entries
                List<AttackEntry> uniqueNewAttacks = new java.util.ArrayList<>();
                for (AttackEntry imported : importedAttacks) {
                    // Ensure the entry has an ID
                    if (imported.getId() == null || imported.getId().isEmpty()) {
                        imported.ensureId();
                    }
                    // Only add if ID doesn't already exist
                    if (!existingIds.contains(imported.getId())) {
                        uniqueNewAttacks.add(imported);
                        existingIds.add(imported.getId()); // Track to prevent duplicates within import file
                    }
                }
                
                if (!uniqueNewAttacks.isEmpty()) {
                    currentAttacks.addAll(uniqueNewAttacks);
                    saveAll(currentAttacks);
                }
            }
        }
    }
}
