package burp;

import java.util.Base64;

public class AttackEntry {
    // Core Request Data
    private String host;
    private int port;
    private String protocol;
    private String method;
    private String url;
    private String requestBase64; // Stored as Base64 to handle binary data safely in JSON
    private String responseBase64;

    // Metadata
    private long timestamp;
    private String testerName;

    // User Documentation
    private String category; // e.g., "SQLi", "XSS"
    private String status;   // e.g., "Vulnerable", "Safe"
    private String notes;

    public AttackEntry(IHttpRequestResponse messageInfo, IExtensionHelpers helpers, String testerName, String category, String status, String notes) {
        this.id = java.util.UUID.randomUUID().toString();
        this.deleted = false;
        this.timestamp = System.currentTimeMillis();
        this.testerName = testerName;
        this.category = category;
        this.status = status;
        this.notes = notes;

        if (messageInfo.getHttpService() != null) {
            this.host = messageInfo.getHttpService().getHost();
            this.port = messageInfo.getHttpService().getPort();
            this.protocol = messageInfo.getHttpService().getProtocol();
        }

        if (messageInfo.getRequest() != null) {
            this.requestBase64 = Base64.getEncoder().encodeToString(messageInfo.getRequest());
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            this.method = requestInfo.getMethod();
            this.url = requestInfo.getUrl().toString();
        }

        if (messageInfo.getResponse() != null) {
            this.responseBase64 = Base64.getEncoder().encodeToString(messageInfo.getResponse());
        }
    }

    // Getters
    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getProtocol() { return protocol; }
    public String getMethod() { return method; }
    public String getUrl() { return url; }
    public String getCategory() { return category; }
    public String getStatus() { return status; }
    public String getNotes() { return notes; }
    public String getTesterName() { return testerName; }
    public long getTimestamp() { return timestamp; }

    public byte[] getRequest() {
        return requestBase64 != null ? Base64.getDecoder().decode(requestBase64) : null;
    }

    public byte[] getResponse() {
        return responseBase64 != null ? Base64.getDecoder().decode(responseBase64) : null;
    }
    
    // Setters for editing
    public void setCategory(String category) { this.category = category; }
    public void setStatus(String status) { this.status = status; }
    public void setNotes(String notes) { this.notes = notes; }

    // Deletion Logic
    private String id;
    private boolean deleted;

    public String getId() { return id; }
    public boolean isDeleted() { return deleted; }
    public void setDeleted(boolean deleted) { this.deleted = deleted; }

    // Ensure ID is initialized if not present (for backward compatibility or new entries)
    public void ensureId() {
        if (this.id == null || this.id.isEmpty()) {
            this.id = java.util.UUID.randomUUID().toString();
        }
    }
}
