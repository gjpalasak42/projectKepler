# Project Kepler (Attack History Recorder)

> [!IMPORTANT]
> **Disclosure**: This project is a modernized security tool refactored to Kotlin using the modern Burp Suite Montoya API.

## Overview
**Project Kepler** is a Burp Suite extension designed to help penetration testers catalog their attacks and document manual testing efforts. It allows you to "record" specific requests, categorize them (e.g., SQLi, XSS), assign a status (Vulnerable, Safe), and add notes. 

This version has been fully refactored from Java to **idiomatic Kotlin** and transitioned to the **Burp Montoya API**, offering better performance, improved null-safety, and a more responsive UI.

## Compatibility

| Component | Version |
|-----------|---------|
| Burp Suite | Professional or Community Edition (2023.12+) |
| Java | JDK 17 or higher |
| Kotlin | 1.9.24 |
| API | Montoya API |
| Operating System | Windows, macOS, Linux |

## Features
*   **Modern Montoya API**: Built on the latest Burp Suite extension framework.
*   **Kotlin Null-Safety**: Robust handling of traffic data to prevent common extension crashes.
*   **Context Menu Integration**: Right-click any request in Proxy, Repeater, or Target to "Save to Attack History".
*   **Customizable Details**: Assign categories, status, and detailed notes (with XSS protection in UI).
*   **History Tab**: A dedicated tab in Burp Suite to view all recorded attacks in a sortable, filtered table.
*   **Request/Response Viewer**: Full syntax-highlighted HTTP traffic inspection for any saved entry.
*   **Threaded I/O**: Background execution for saving/loading to ensure the Burp UI never freezes.
*   **Persistence**: Automatically saves history to local JSON files (`~/.burp_attack_history.json`).

## Installation

### Build from Source

#### Prerequisites
*   Java Development Kit (JDK) 17 or higher
*   Internet connection for Gradle dependencies

#### Build Steps
1.  Clone the repository:
    ```bash
    git clone <repository-url>
    cd projectKepler
    ```
2.  Build the "Fat JAR" using the Shadow plugin:
    ```bash
    ./gradlew shadowJar
    ```
3.  The extension JAR file will be generated at:
    `build/libs/projectKepler-1.2.1.jar`

### Loading into Burp Suite
1.  Open Burp Suite.
2.  Navigate to **Extensions** → **Installed**.
3.  Click **Add**.
4.  Select **Extension type**: **Java**.
5.  Click **Select file...** and choose the `projectKepler-1.2.1.jar`.
6.  Click **Next**. You should see "ProjectKepler: Attack History Recorder Loaded." in the output window.

## Usage

### Recording an Attack
1.  Right-click any request in **Proxy**, **Repeater**, or **Logger**.
2.  Select **Save to Attack History**.
3.  Fill in the metadata (Category, Status, Notes).
4.  Click **Save**.

### Managing Data
1.  Go to the **Attack History** tab.
2.  Use **Show Trash** to toggle between active records and deleted items.
3.  Use the **Settings** sub-tab to configure your tester name and default dropdown values.
4.  Use **Export/Import** in Settings to share datasets with team members.

## Security Considerations

*   **UI Safety**: The extension sanitizes notes before rendering to prevent XSS within the Burp Suite UI.
*   **Local Storage**: Data is stored as Base64-encoded strings within JSON files in your home directory. 
*   **Sensitive Information**: Because the extension records full HTTP requests/responses (including headers/cookies), treat the `.json` storage files as sensitive data.

## Contributing
The project follows a **Controller/Service** architecture pattern. When contributing:
1. Ensure all logic is written in Kotlin.
2. Use `data classes` for traffic models.
3. Strictly adhere to the Montoya API (no legacy `IBurpExtender` references).
4. Run `./gradlew build` to ensure all diagnostics pass.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.