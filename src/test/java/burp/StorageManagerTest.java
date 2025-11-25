package burp;

import org.junit.jupiter.api.AfterEach;
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
        mockStderr = mock(PrintWriter.class);
        storageManager = new StorageManager(tempFile.getAbsolutePath(), mockStderr);
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
}
