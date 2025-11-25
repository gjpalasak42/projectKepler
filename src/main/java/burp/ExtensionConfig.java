package burp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ExtensionConfig {
    private String testerName;
    private List<String> categories;
    private List<String> statuses;

    public ExtensionConfig() {
        // Defaults
        this.testerName = "Tester";
        this.categories = new ArrayList<>(Arrays.asList(
            "SQL Injection", "XSS", "CSRF", "IDOR", "Auth Bypass", "RCE", "Information Disclosure", "Other"
        ));
        this.statuses = new ArrayList<>(Arrays.asList(
            "Vulnerable", "Safe", "Needs Investigation"
        ));
    }

    public String getTesterName() { return testerName; }
    public void setTesterName(String testerName) { this.testerName = testerName; }

    public List<String> getCategories() { return categories; }
    public void setCategories(List<String> categories) { this.categories = categories; }

    public List<String> getStatuses() { return statuses; }
    public void setStatuses(List<String> statuses) { this.statuses = statuses; }
}
