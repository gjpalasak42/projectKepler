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

    public synchronized List<AttackEntry> loadAttacks() {
        if (!storageFile.exists()) {
            return new ArrayList<>();
        }

        try (Reader reader = new FileReader(storageFile)) {
            Type listType = new TypeToken<ArrayList<AttackEntry>>(){}.getType();
            List<AttackEntry> attacks = gson.fromJson(reader, listType);
            return attacks != null ? attacks : new ArrayList<>();
        } catch (IOException e) {
            stderr.println("Error loading attacks: " + e.getMessage());
            e.printStackTrace(stderr);
            return new ArrayList<>();
        }
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
}
