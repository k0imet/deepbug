Deepug
Deepug is a Streamlit-based web application designed for security researchers and penetration testers to perform reconnaissance and vulnerability scanning on target domains. It provides a user-friendly interface to run various scans, including subdomain enumeration, port scanning, JavaScript analysis, technology detection, and vulnerability detection, with results organized by project and visualized in an interactive dashboard.
Features

Subdomain & Takeover Scan: Discover subdomains using tools like Subfinder and Amass, resolve DNS records, probe HTTP services, and check for subdomain takeovers.
Port Scanning: Identify open ports on targets using Nmap or Masscan.
JavaScript Analysis: Extract JavaScript files, discover endpoints, and identify sensitive data using Fakjs.
Technology Detection: Detect web technologies with Webanalyze, including an option to update definitions.
Vulnerability Detection: Scan for vulnerabilities using Paramspider and GF patterns (e.g., SQLi, XSS, LFI).
Project Management: Organize scan results by project and target, stored as JSON files for persistence.
Interactive Dashboard: Visualize scan results with metrics, bar charts, and pie charts for vulnerability severity distribution.

Prerequisites

Python: 3.10 or higher
Operating System: Linux or macOS (some tools like Subfinder may require specific dependencies)
Dependencies: Listed in requirements.txt
External Tools: Subfinder, Amass, DNSx, HTTPx, Nmap, Masscan, Fakjs, Webanalyze, Paramspider, GF (ensure these are installed and accessible in your PATH)

Installation

Clone the Repository:
git clone https://github.com/<your-username>/deepug.git
cd deepug




Run the Application:
streamlit run app.py



Usage

Access the Web Interface:

Open your browser and navigate to http://localhost:8501 (default Streamlit port).
The app opens on the Projects page (0_Projects.py).


Create or Select a Project:

On the Projects page, create a new project or select an existing one.
Projects are stored in the projects/ directory, with results organized by target (e.g., projects/MTN/mtn_com/).


Run Reconnaissance Scans:

Navigate to the Reconnaissance Tools page (1_Reconnaissance.py).
Select or enter a target domain (e.g., mtn.com).
Use the tabs to run:
Subdomain & Takeover Scan: Discover subdomains and check for takeovers.
Port Scanning: Scan for open ports using Nmap or Masscan.
JavaScript Analysis: Extract JS files and endpoints.
Technology Detection: Identify web technologies with Webanalyze.
Vulnerability Detection: Scan for vulnerabilities using Paramspider and GF.


Scans run synchronously, displaying progress and results in real-time.


View Results in the Dashboard:

Go to the Dashboard page (2_Dashboard.py) to view:
Key Metrics: Counts of subdomains, open ports, JS files, vulnerabilities, and takeovers.
Visualizations: Bar chart for scan result distribution and pie chart for vulnerability severity.
Target Overview: Summary of results per target.
Detailed Results: Expandable sections for each scan type and target.


Click Refresh Dashboard to update results after new scans.


Run Vulnerability Scans:

Use the Vulnerability Scanner page (3_Scanner.py) for additional vulnerability scans (if implemented with backgrounding, results may appear in the dashboard).



Example Workflow

Create a project named MTN on the Projects page.
On the Reconnaissance Tools page, enter mtn.com as the target.
Run a Subdomain & Takeover Scan to discover subdomains and live hosts.
Run a JavaScript Analysis to extract JS files and endpoints.
Navigate to the Dashboard to view metrics and visualizations for mtn.com.
Check JSON files in projects/MTN/mtn_com/ for saved results (e.g., js_files_results.json).

Troubleshooting

Duplicated Results:

If results (e.g., js_files, js_discovered_endpoints) appear duplicated, ensure 1_Reconnaissance.py prevents re-running scans for the same target using session state checks.
Check project_manager.py to confirm save_scan_results overwrites existing JSON files.


UnhashableParamError:

If you see streamlit.runtime.caching.cache_errors.UnhashableParamError, avoid using @st.cache_data with unhashable arguments (e.g., dictionaries with DataFrames). The provided 2_Dashboard.py avoids this by removing caching.


Missing Tools:

Ensure all external tools (Subfinder, Amass, etc.) are installed and in your PATH.
Verify config.yaml points to the correct tool paths.


No Results Displayed:

Confirm results are saved in the projects/ directory.
Check logs in the terminal for errors during scan execution or result saving.



Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a feature branch (git checkout -b feature/your-feature).
Commit changes (git commit -m "Add your feature").
Push to the branch (git push origin feature/your-feature).
Open a pull request.

Please include tests and update documentation for new features.
License
This project is licensed under the MIT License. See the LICENSE file for details.
Contact
For issues or feature requests, open an issue on the GitHub repository or contact the maintainers
