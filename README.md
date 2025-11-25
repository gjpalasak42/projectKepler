# Project Kepler (Attack History Recorder)

> [!IMPORTANT]
> **Disclosure**: This project is AI Driven and has the full codebase not been fully vetted for production deployment.

## Overview
**Project Kepler** is a Burp Suite extension designed to help penetration testers catalog their attacks and document manual testing efforts. It allows you to "record" specific requests, categorize them (e.g., SQLi, XSS), assign a status (Vulnerable, Safe), and add notes. This prevents redundant testing and facilitates knowledge sharing within teams.

## Features
*   **Context Menu Integration**: Right-click any request in Proxy, Repeater, or Target to "Save to Attack History".
*   **Customizable Details**: Assign categories, status, and detailed notes to each saved request.
*   **History Tab**: A dedicated tab in Burp Suite to view all recorded attacks in a sortable table.
*   **Request/Response Viewer**: Inspect the full HTTP traffic for any saved entry.
*   **Persistence**: Automatically saves your history to a local JSON file (`~/.burp_attack_history.json`), ensuring data is safe across restarts.

## Installation & Building

### Prerequisites
*   Java Development Kit (JDK) 17 or higher.
*   Gradle (optional, wrapper provided).

### Build Steps
1.  Clone the repository:
    ```bash
    git clone <repository-url>
    cd projectKepler
    ```
2.  Build the project using the Gradle wrapper:
    ```bash
    ./gradlew build
    ```
3.  The extension JAR file will be generated at:
    `build/libs/projectKepler-1.0-SNAPSHOT.jar`

### Loading into Burp Suite
1.  Open Burp Suite.
2.  Navigate to **Extensions** > **Installed**.
3.  Click **Add**.
4.  Select **Extension type**: **Java**.
5.  Click **Select file ...** and choose the JAR file generated in step 3.
6.  Click **Next**. You should see a success message in the output window.

## Usage

### Recording an Attack
1.  Identify a request you have tested (e.g., in **Proxy > HTTP History**).
2.  Right-click the request and select **Save to Attack History**.
3.  In the popup dialog:
    *   **Category**: Select a standard category (e.g., "SQL Injection") or type a new one.
    *   **Status**: Mark as "Vulnerable", "Safe", or "Needs Investigation".
    *   **Notes**: Add any observations or proof of concept details.
4.  Click **Save**.

### Configuration
1.  Go to the **Settings** tab.
2.  **Tester Name**: Set your name (default: "Tester"). This will be saved with every attack you record.
3.  **Categories**: Edit the list of available categories (one per line).
4.  **Statuses**: Edit the list of available statuses (one per line).
5.  Click **Save Settings** to apply changes.

### Viewing and Managing History
1.  Go to the **Attack History** tab in the main Burp menu.
2.  Use the table to browse your recorded attacks. Click column headers to sort.
3.  Select a row to view the **Request**, **Response**, and **Details** (Notes) in the bottom pane.

## Future Improvements (Roadmap)
*   **Export/Import**: Share attack histories with team members via JSON/XML export.
*   **Advanced Filtering**: Filter the history table by specific categories or date ranges.
*   **Replay**: "Send to Repeater" directly from the history tab.
*   **Reporting**: Generate a summary report (HTML/Markdown) of all "Vulnerable" items.
*   **Project Integration**: Option to save data within the Burp project file instead of a global JSON file.

## License
[License Name]
