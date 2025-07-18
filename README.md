# Deepug

DeepBug is an automated reconnaissance and bug bounty hunting platform designed to streamline your workflow. It integrates various open-source tools to perform subdomain enumeration, port scanning, JavaScript analysis, vulnerability scanning, and more, all managed within a user-friendly interface.
## Get Started:

    📂 Projects: Start by creating a new project or loading an existing one. All your scan results and findings will be saved under the active project.
    🔍 Reconnaissance: Dive into discovery! Run subdomain scans, active host verification, port scans, and JavaScript analysis.
    🛡️ Vulnerability Scan: Once you have your targets, launch vulnerability scans using integrated tools like Nuclei.
    📊 Dashboard & 📄 Reporting: Review your findings, track progress, and generate comprehensive reports.


## Prerequisites

- **Python**: 3.10 or higher
- **Operating System**: Linux or macOS (some tools like Subfinder may require specific dependencies)
- **Dependencies**: Listed in `requirements.txt`
- **External Tools**: Subfinder, Amass, DNSx, HTTPx, Nmap, Masscan, Fakjs, Webanalyze, Paramspider, GF (ensure these are installed and accessible in your PATH)

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/<your-username>/deepug.git
   cd deepug
   ```
2. **Install requirements.txt**

   Ensure `requirements.txt` includes:
   ```text
   streamlit
   pandas
   plotly
   pyyaml
   ```

4. **Install External Tools**:
   Install the required reconnaissance tools. For example:
  ```bash
bash install.sh
   ```

   Ensure go tools are in your PATH:
   ```bash
   export PATH=$PATH:$HOME/go/bin
   ```

5. **Configure the Application**:
   Create or edit `config.yaml` in the root directory with necessary settings (e.g., paths to tools, project directory):
   ```yaml
  {
    "logging": {
        "level": "INFO",
        "file": "bugbountybot.log"
    },
    "project_settings": {
        "base_projects_dir": "./projects"
    },
    "recon_output_dir": "./recon_tmp_output",
    "tools": {
        "paths": {
            "subfinder": "/home/username/go/bin/subfinder",
            "dnsx": "/home/username/go/bin/dnsx",
            "nuclei": "/home/username/go/bin/nuclei",
            "nuclei_templates": "/home/username/nuclei-templates",
            "nmap": "/usr/bin/nmap",
            "masscan": "/usr/bin/masscan",
            "subjs": "/home/username/go/bin/subjs",
            "webanalyze": "/usr/bin/webanalyze",
            "httpx": "/usr/bin/httpx",
            "getjs": "/usr/bin/getJS",
            "gf": "/home/username/go/bin/gf",
            "linkfinder": "/usr/bin/linkfinder",
            "fakjs":"/usr/bin/fakjs",
            "subdover": "/usr/bin/subdover",
            "paramspider": "/home/username/.local/bin/paramspider",
            "amass": "/home/username/go/bin/amass"
        },
        "rate_limits": {
            "masscan": 1000
        },
        "sqltimer": {
            "sleep_time": 5,
            "threads": 10,
            "timeout_multiplier": 6,
            "timeout_buffer": 10
        }
    },
    "output_formats": {
        "default": "csv"
    }
}
   ```

6. **Run the Application**:
   ```bash
   streamlit run app.py
   ```

## Usage

1. **Access the Web Interface**:
   - Open your browser and navigate to `http://localhost:8501` (default Streamlit port).
   - The app opens on the **Projects** page (`0_Projects.py`).

2. **Create or Select a Project**:
   - On the **Projects** page, create a new project or select an existing one.
   - Projects are stored in the `projects/` directory, with results organized by target (e.g., `projects/example/example_com/`).

3. **Run Reconnaissance Scans**:
   - Navigate to the **Reconnaissance Tools** page (`1_Reconnaissance.py`).
   - Select or enter a target domain (e.g., `example.com`).
   - Use the tabs to run:
     - **Subdomain & Takeover Scan**: Discover subdomains and check for takeovers.
     - **Port Scanning**: Scan for open ports using Nmap or Masscan.
     - **JavaScript Analysis**: Extract JS files and endpoints.
     - **Technology Detection**: Identify web technologies with Webanalyze.
     - **Vulnerability Detection**: Scan for vulnerabilities using Paramspider and GF.
   - Scans run synchronously, displaying progress and results in real-time.

4. **View Results in the Dashboard**:
   - Go to the **Dashboard** page (`2_Dashboard.py`) to view:
     - **Key Metrics**: Counts of subdomains, open ports, JS files, vulnerabilities, and takeovers.
     - **Visualizations**: Bar chart for scan result distribution and pie chart for vulnerability severity.
     - **Target Overview**: Summary of results per target.
     - **Detailed Results**: Expandable sections for each scan type and target.
   - Click **Refresh Dashboard** to update results after new scans.

5. **Run Vulnerability Scans**:
   - Use the **Vulnerability Scanner** page (`3_Scanner.py`) for additional vulnerability scans (if implemented with backgrounding, results may appear in the dashboard).

## Example Workflow

1. Create a project named `example.com` on the **Projects** page.
2. On the **Recon** page, enter `example.com` as the target.
3. Run a **Subdomain & Takeover Scan** to discover subdomains and live hosts.
4. Run a **JavaScript Analysis** to extract JS files and endpoints.
5. Run a ***
6. Navigate to the **Dashboard** to view metrics and visualizations for `example.com`.



## Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

Please include tests and update documentation for new features.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
