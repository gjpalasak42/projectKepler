# Project Kepler (Attack History Recorder)

> [!IMPORTANT]
> **Disclosure**: This project is AI-driven and the full codebase has not been fully vetted for production deployment.

## Overview
**Project Kepler** is a Burp Suite extension designed to help penetration testers catalog their attacks and document manual testing efforts. It allows you to "record" specific requests, categorize them (e.g., SQLi, XSS), assign a status (Vulnerable, Safe), and add notes. This prevents redundant testing and facilitates knowledge sharing within teams.

## Compatibility

| Component | Version |
|-----------|---------|
| Burp Suite | Professional or Community Edition (2020.1+) |
| Java | JDK 17 or higher |
| Operating System | Windows, macOS, Linux |

> **Note**: This extension uses the legacy Burp Extender API (v2.3). It is compatible with current Burp Suite versions but may require updates if PortSwigger deprecates this API.

## Features
*   **Context Menu Integration**: Right-click any request in Proxy, Repeater, or Target to "Save to Attack History".
*   **Customizable Details**: Assign categories, status, and detailed notes to each saved request.
*   **History Tab**: A dedicated tab in Burp Suite to view all recorded attacks in a sortable table.
*   **Request/Response Viewer**: Inspect the full HTTP traffic for any saved entry.
*   **Persistence**: Automatically saves your history to a local JSON file (`~/.burp_attack_history.json`), ensuring data is safe across restarts.

## Installation

### Option 1: Download Pre-built JAR (Recommended)
1. Go to the [Releases](../../releases) page
2. Download the latest `projectKepler-X.X.X.jar` file
3. Verify the download using the SHA256 checksum:
   ```bash
   sha256sum -c projectKepler-X.X.X.jar.sha256
   ```

### Option 2: Build from Source

#### Prerequisites
*   Java Development Kit (JDK) 17 or higher
*   Git

#### Build Steps
1.  Clone the repository:
    ```bash
    git clone https://github.com/gjpalasak42/projectKepler.git
    cd projectKepler
    ```
2.  Build the project using the Gradle wrapper:
    ```bash
    ./gradlew build
    ```
3.  The extension JAR file will be generated at:
    `build/libs/projectKepler-1.2.0.jar`

### Loading into Burp Suite
1.  Open Burp Suite
2.  Navigate to **Extensions** → **Installed**
3.  Click **Add**
4.  Select **Extension type**: **Java**
5.  Click **Select file...** and choose the JAR file
6.  Click **Next**. You should see "Attack History Recorder Loaded." in the output window
7.  A new **Attack History** tab will appear in the main Burp menu

## Usage

### Recording an Attack
1.  Identify a request you have tested (e.g., in **Proxy → HTTP History**)
2.  Right-click the request and select **Save to Attack History**
3.  In the popup dialog:
    *   **Category**: Select a standard category (e.g., "SQL Injection") or type a new one
    *   **Status**: Mark as "Vulnerable", "Safe", or "Needs Investigation"
    *   **Notes**: Add any observations or proof of concept details
4.  Click **Save**

### Configuration
1.  Go to the **Attack History** tab, then select the **Settings** sub-tab
2.  **Tester Name**: Set your name (default: "Tester"). This will be saved with every attack you record
3.  **Categories**: Edit the list of available categories (one per line)
4.  **Statuses**: Edit the list of available statuses (one per line)
5.  Click **Save Settings** to apply changes

### Viewing and Managing History
1.  Go to the **Attack History** tab in the main Burp menu
2.  Use the table to browse your recorded attacks. Click column headers to sort
3.  Select a row to view the **Request**, **Response**, and **Details** (Notes) in the bottom pane
4.  Use the **Show Trash** toggle to view/restore deleted entries

## Data Storage

Attack history is stored in:
- **History file**: `~/.burp_attack_history.json`
- **Config file**: `~/.burp_attack_history_config.json`

## Security Considerations

*   **Local Storage**: Attack history is stored in a local JSON file in your user's home directory. Ensure appropriate file permissions on shared systems.
*   **Sensitive Data**: The extension stores full HTTP requests and responses, which may contain credentials, tokens, or other sensitive information. Handle the history file with care.
*   **Scope**: This extension is designed for authorized penetration testing activities only. Always obtain proper authorization before testing.

## Troubleshooting

### Extension fails to load
- **Check Java version**: Ensure you're running JDK 17 or higher (`java -version`)
- **Verify JAR integrity**: Re-download and verify the SHA256 checksum
- **Check Burp logs**: Look for error messages in the Extensions → Installed → Errors tab

### "Attack History" tab not appearing
- **Reload extension**: Unload and reload the extension from Extensions → Installed
- **Restart Burp**: Close and reopen Burp Suite completely

### History not persisting
- **Check file permissions**: Ensure write access to your home directory
- **Verify path**: Check that `~/.burp_attack_history.json` exists after saving an entry
- **Disk space**: Ensure sufficient disk space is available

### Context menu "Save to Attack History" not appearing
- **Ensure extension is loaded**: Check Extensions → Installed shows the extension as loaded
- **Right context**: The option appears when right-clicking on HTTP requests/responses

### Performance issues
- **Large history files**: If the history file becomes very large, consider exporting and archiving old entries
- **Background operations**: File I/O operations run in background threads to prevent UI blocking

## Future Improvements (Roadmap)
*   **Export/Import**: Share attack histories with team members via JSON/XML export
*   **Advanced Filtering**: Filter the history table by specific categories or date ranges
*   **Replay**: "Send to Repeater" directly from the history tab
*   **Reporting**: Generate a summary report (HTML/Markdown) of all "Vulnerable" items
*   **Project Integration**: Option to save data within the Burp project file instead of a global JSON file

## Contributing
Contributions are welcome! Please ensure:
1. Code follows existing style conventions
2. All tests pass (`./gradlew test`)
3. New features include appropriate tests

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
