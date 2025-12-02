package burp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class StorageManagerTest {

    private StorageManager storageManager;
    private File tempFile;
    private PrintWriter mockStderr;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        tempFile = tempDir.resolve("test_attacks.json").toFile();
        File configFile = tempDir.resolve("test_config.json").toFile();
        mockStderr = new PrintWriter(System.err); // Use real PrintWriter to avoid Mockito issues
        storageManager = new StorageManager(tempFile.getAbsolutePath(), configFile.getAbsolutePath(), mockStderr);
    }

    @Test
    void testSaveAndLoadAttack() {
        // Create a dummy attack entry (mocking dependencies not needed for simple POJO storage test if we use nulls or basic values)
        // However, AttackEntry constructor requires IHttpRequestResponse. We'll need to mock that or use a helper to create a "clean" entry.
        // For this test, we can just manually create an AttackEntry if we add a protected constructor or just mock the dependencies.
        // Let's mock the dependencies for the constructor.
        
        IExtensionHelpers mockHelpers = mock(IExtensionHelpers.class);
        IHttpRequestResponse mockMessage = mock(IHttpRequestResponse.class);
        
        // We need to ensure the constructor doesn't crash on nulls if we don't stub everything.
        // The current AttackEntry constructor checks for nulls.
        
        AttackEntry entry = new AttackEntry(mockMessage, mockHelpers, "Tester1", "SQLi", "Vulnerable", "My Notes");
        
        // Save
        storageManager.saveAttack(entry);
        
        // Load
        List<AttackEntry> loaded = storageManager.loadAttacks();
        
        assertEquals(1, loaded.size());
        assertEquals("Tester1", loaded.get(0).getTesterName());
        assertEquals("SQLi", loaded.get(0).getCategory());
        assertEquals("Vulnerable", loaded.get(0).getStatus());
        assertEquals("My Notes", loaded.get(0).getNotes());
    }

    @Test
    void testLoadEmptyFile() {
        List<AttackEntry> loaded = storageManager.loadAttacks();
        assertTrue(loaded.isEmpty());
    }

    @Test
    void testExportAttacks() throws Exception {
        // Setup mock data
        IExtensionHelpers mockHelpers = mock(IExtensionHelpers.class);
        IHttpRequestResponse mockMessage = mock(IHttpRequestResponse.class);
        AttackEntry entry = new AttackEntry(mockMessage, mockHelpers, "Tester1", "SQLi", "Vulnerable", "My Notes");
        storageManager.saveAttack(entry);

        // Export
        File exportFile = new File(tempFile.getParent(), "export.json");
        storageManager.exportAttacks(exportFile);

        // Verify file exists and has content
        assertTrue(exportFile.exists());
        assertTrue(exportFile.length() > 0);
    }

    @Test
    void testImportAttacks() throws Exception {
        // Create a file to import
        File importFile = new File(tempFile.getParent(), "import.json");
        try (PrintWriter writer = new PrintWriter(importFile)) {
            writer.println("[{\"host\":\"example.com\",\"port\":80,\"protocol\":\"http\",\"method\":\"GET\",\"url\":\"http://example.com/\",\"timestamp\":1234567890,\"testerName\":\"Importer\",\"category\":\"XSS\",\"status\":\"Fixed\",\"notes\":\"Imported note\"}]");
        }

        // Import
        storageManager.importAttacks(importFile);

        // Verify loaded
        List<AttackEntry> loaded = storageManager.loadAttacks();
        assertEquals(1, loaded.size());
        assertEquals("Importer", loaded.get(0).getTesterName());
        assertEquals("Imported note", loaded.get(0).getNotes());
    }

    @Test
    void testImportInvalidFile() {
        File invalidFile = new File(tempFile.getParent(), "nonexistent.json");
        assertThrows(java.io.FileNotFoundException.class, () -> storageManager.importAttacks(invalidFile));
    }


    @Test
    void testIdPersistence() throws Exception {
        // Create a file with an entry missing an ID
        try (PrintWriter writer = new PrintWriter(tempFile)) {
            writer.println("[{\"host\":\"example.com\",\"testerName\":\"Legacy\",\"category\":\"XSS\",\"status\":\"Fixed\",\"notes\":\"Legacy note\"}]");
        }

        // Load - should generate ID and save it
        List<AttackEntry> loaded = storageManager.loadAttacks();
        assertEquals(1, loaded.size());
        String id = loaded.get(0).getId();
        assertNotNull(id);
        assertFalse(id.isEmpty());

        // Reload - should have same ID
        List<AttackEntry> reloaded = storageManager.loadAttacks();
        assertEquals(1, reloaded.size());
        assertEquals(id, reloaded.get(0).getId());
    }

    @Test
    void testImportPreventsDuplicates() throws Exception {
        // First import a file with a specific ID
        File importFile = new File(tempFile.getParent(), "import.json");
        String testId = "test-id-12345";
        try (PrintWriter writer = new PrintWriter(importFile)) {
            writer.println("[{\"id\":\"" + testId + "\",\"host\":\"example.com\",\"port\":80,\"protocol\":\"http\",\"method\":\"GET\",\"url\":\"http://example.com/\",\"timestamp\":1234567890,\"testerName\":\"Importer1\",\"category\":\"XSS\",\"status\":\"Fixed\",\"notes\":\"First import\"}]");
        }
        
        storageManager.importAttacks(importFile);
        
        // Verify first import succeeded
        List<AttackEntry> afterFirstImport = storageManager.loadAttacks();
        assertEquals(1, afterFirstImport.size());
        assertEquals("Importer1", afterFirstImport.get(0).getTesterName());
        
        // Import the same file again (duplicate ID)
        try (PrintWriter writer = new PrintWriter(importFile)) {
            writer.println("[{\"id\":\"" + testId + "\",\"host\":\"example.com\",\"port\":80,\"protocol\":\"http\",\"method\":\"GET\",\"url\":\"http://example.com/\",\"timestamp\":1234567890,\"testerName\":\"Importer2\",\"category\":\"XSS\",\"status\":\"Fixed\",\"notes\":\"Second import - should be skipped\"}]");
        }
        
        storageManager.importAttacks(importFile);
        
        // Verify duplicate was not added
        List<AttackEntry> afterSecondImport = storageManager.loadAttacks();
        assertEquals(1, afterSecondImport.size());
        assertEquals("Importer1", afterSecondImport.get(0).getTesterName()); // Should still be the first import
    }
}
