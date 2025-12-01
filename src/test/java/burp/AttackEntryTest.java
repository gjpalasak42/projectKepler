package burp;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AttackEntryTest {

    @Test
    void testAttackEntryExtraction() throws Exception {
        // Mocks
        IHttpRequestResponse messageInfo = mock(IHttpRequestResponse.class);
        IExtensionHelpers helpers = mock(IExtensionHelpers.class);
        IHttpService httpService = mock(IHttpService.class);
        IRequestInfo requestInfo = mock(IRequestInfo.class);

        // Stubbing
        when(messageInfo.getHttpService()).thenReturn(httpService);
        when(httpService.getHost()).thenReturn("example.com");
        when(httpService.getPort()).thenReturn(443);
        when(httpService.getProtocol()).thenReturn("https");

        byte[] requestBytes = "GET /login HTTP/1.1".getBytes();
        byte[] responseBytes = "HTTP/1.1 200 OK".getBytes();
        
        when(messageInfo.getRequest()).thenReturn(requestBytes);
        when(messageInfo.getResponse()).thenReturn(responseBytes);
        
        when(helpers.analyzeRequest(messageInfo)).thenReturn(requestInfo);
        when(requestInfo.getMethod()).thenReturn("GET");
        when(requestInfo.getUrl()).thenReturn(java.net.URI.create("https://example.com/login").toURL());

        // Execute
        AttackEntry entry = new AttackEntry(messageInfo, helpers, "Tester1", "XSS", "Safe", "Notes");

        // Verify
        assertEquals("example.com", entry.getHost());
        assertEquals(443, entry.getPort());
        assertEquals("https", entry.getProtocol());
        assertEquals("GET", entry.getMethod());
        assertEquals("https://example.com/login", entry.getUrl());
        assertEquals("Tester1", entry.getTesterName());
        assertEquals("XSS", entry.getCategory());
        
        assertArrayEquals(requestBytes, entry.getRequest());
        assertArrayEquals(responseBytes, entry.getResponse());
    }


    @Test
    void testIdAndDeletion() {
        // Mocks (minimal needed for constructor)
        IHttpRequestResponse messageInfo = mock(IHttpRequestResponse.class);
        IExtensionHelpers helpers = mock(IExtensionHelpers.class);
        
        // Execute
        AttackEntry entry = new AttackEntry(messageInfo, helpers, "Tester1", "XSS", "Safe", "Notes");

        // Verify ID generation
        assertNotNull(entry.getId());
        assertFalse(entry.getId().isEmpty());
        
        // Verify Deletion Default
        assertFalse(entry.isDeleted());
        
        // Verify Deletion Toggle
        entry.setDeleted(true);
        assertTrue(entry.isDeleted());
    }
}
