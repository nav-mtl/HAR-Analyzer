# HAR Analyzer Tool

This is a web-based tool for analyzing HTTP Archive (HAR) files. It allows users to upload or paste HAR content for analysis and provides detailed metrics, security issue detection, and timing plots.

## Features

- **HAR File Analysis**: Upload or paste HAR content to analyze HTTP requests and responses.
- **Metrics Generation**: Provides total number of entries, total time, average time, and status code distribution.
- **Security Issue Detection**: Identifies potential security issues in request and response headers, bodies, cookies, and URLs.
- **Timing Plots**: Visualizes request timing data using interactive plots.
- **Comparison of HAR Files**: Compares two HAR files and highlights differences in metrics and security issues.

## Security Issue Detection

The tool scans the HAR content for the following sensitive information:

- **Authorization Headers**: Detects authorization tokens such as Bearer tokens.
- **API Keys**: Identifies API keys in headers, bodies, and URLs.
- **Cookies**: Checks for sensitive information in cookies.
- **User Credentials**: Detects usernames and passwords in request and response bodies.
- **Session IDs**: Identifies session IDs in cookies and bodies.

## Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/yourusername/har_analyzer.git
    cd har_analyzer
    ```

2. **Install the required packages**:
    ```sh
    pip install -r requirements.txt
    ```

3. **Run the application**:
    ```sh
    python har_analyzer.py
    ```

4. **Open your browser and navigate to**:
    ```
    http://127.0.0.1:5000/
    ```

## Usage

### Analyze a HAR File

1. Open the web interface.
2. Upload a HAR file or paste HAR content into the provided textarea.
3. Click the "Analyze" button to view the analysis results.

### Compare Two HAR Files

1. Open the web interface.
2. Navigate to the "Compare" page.
3. Upload two HAR files or paste two sets of HAR content into the provided textareas.
4. Click the "Compare" button to view the comparison results.

## Security Detection Details

### Authorization Headers

The tool scans for authorization headers that might contain sensitive tokens, such as:

```Authorization Tokens
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

```API Keys
x-api-key: abcdef123456

```Cookies
Set-Cookie: session_id=3e35a8

```Credentials
username: "user1"
password: "Passw0rd!"

```Session Ids
session_id: "3e35a8"

## Author

<p>Navjot Singh</p>
<p><a href="https://www.linkedin.com/in/njot/">LinkedIn</a></p>

## License

<p>This project is licensed under the MIT License.</p>