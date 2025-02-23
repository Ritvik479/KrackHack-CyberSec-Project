# Solution to PS 1 KrackHack

This project is a web-based malware scanner that utilizes YARA rules and file hash checks to identify potentially malicious files. It features a cyberpunk-themed dark mode and a user-friendly interface for uploading and scanning files.

## Features

-   **File Scanning:** Upload and scan files for malware using YARA rules and hash checks.
-   **YARA Rule Integration:** Uses YARA rules to detect malware signatures.
-   **File Hash Checks:** Compares file hashes against known malware databases.
-   **Cyberpunk Dark Mode:** A stylish dark mode with neon accents.
-   **Progress Bar:** Visual feedback during the scanning process.
-   **Clear Scan Results:** Displays scan results with clear indicators for safe and malicious files.
-   **Allowed File Types:** Supports scanning of `.exe`, `.pdf`, and `.docx` files.
-   **Bootstrap Integration:** Responsive design with Bootstrap 5.

## Technologies Used

-   **Python:** Flask web framework.
-   **JavaScript:** Client-side scripting for UI interactions.
-   **HTML/CSS:** Front-end structure and styling.
-   **YARA:** Malware identification and classification.
-   **Hashing Algorithms (SHA256):** For file integrity and malware database comparisons.
-   **Bootstrap:** UI framework.

### Prerequisites

-   Python 3.6+
-   pip (Python package installer)
-   YARA (install via pip: `pip install yara-python`)

### Installation

1.  **Clone the repository:**

    ```bash
    git clone [repository_url]
    cd [repository_name]
    ```

2.  **Create a virtual environment (recommended):**

    ```bash
    python -m venv venv
    ```

    -   On Windows:

        ```bash
        venv\Scripts\activate
        ```

    -   On macOS and Linux:

        ```bash
        source venv/bin/activate
        ```

3.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the Flask application:**

    ```bash
    python app.py
    ```

5.  **Open your browser and navigate to `http://127.0.0.1:5000/`.**

## Usage

1.  Open the web application in your browser.
2.  Toggle dark mode using the button.
3.  Click "Choose File" and select a file to scan.
4.  Click "Scan File."
5.  View the scan results displayed below the form.


## Meet the team
- Ritvik Garg
- Saurabh Gopal
- Himanl Arora
- Jashnoor Singh