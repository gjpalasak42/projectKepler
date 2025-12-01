package burp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.*;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

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
    }

    private void saveAll(List<AttackEntry> attacks) {
        try (Writer writer = new FileWriter(storageFile)) {
            gson.toJson(attacks, writer);
        } catch (IOException e) {
            stderr.println("Error saving attacks: " + e.getMessage());
            e.printStackTrace(stderr);
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
                currentAttacks.addAll(importedAttacks);
                saveAll(currentAttacks);
            }
        }
    }
}
