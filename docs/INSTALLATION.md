# Installing DeepBug

## Prerequisites

- **Python 3.13+**
- **Streamlit** (installed via `requirements.txt`)
- **Go tools are optional but recommended** — most Recon tabs call external
  binaries (subfinder, nuclei, httpx, katana, …). Without them, scans report
  the missing tool instead of producing results. `bash app/install.sh` installs
  them all (see below).

## Steps

```bash
# 1. Clone or copy the repository
git clone <repo-url> deepbug   # or copy the deepbug/ folder
cd deepbug

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. (Optional but recommended) Install recon tools
bash app/install.sh

# 5. Run the app
streamlit run deepbug_app.py
```

> ⚠️ Always launch with `streamlit run deepbug_app.py` **from the repository
> root**. Running a page file directly breaks imports (see TROUBLESHOOTING.md).

## What `app/install.sh` installs

The script needs **Go already installed** (it exits with an error otherwise).
It then:

1. Updates system packages and installs base deps (`git make gcc libpcap-dev`
   / `libpcap-devel`, `python3 python3-pip`, `curl wget`). Debian/Ubuntu uses
   `apt`; Fedora/RHEL uses `dnf`.
2. Installs Go tools into `$GOBIN` (`$HOME/go/bin` by default):

   `subfinder`, `dnsx`, `nuclei`, `subjs`, `webanalyze`, `httpx`, `getjs`,
   `gf`, `amass`, `fakjs`, `ffuf`

3. Clones or updates the **nuclei-templates** repo to `~/nuclei-templates`.
4. Installs **nmap** and **masscan** via the distro package manager.
5. Installs Python tools: **paramspider** (`/opt/paramspider`), **LinkFinder**
   (`/opt/LinkFinder`), **cloud_enum** (`/opt/cloud_enum`, linked to
   `/usr/local/bin/cloud_enum`).

It finishes with a verification summary and suggests PATH exports:

```bash
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:/usr/local/bin"
export NUCLEI_TEMPLATES_PATH=$HOME/nuclei-templates
```

Tools the installer does *not* cover (install manually when needed): `kxss`,
`katana`, `gau`, `x8`, `arjun`, `waybackurls`, `playwright` (browser-based
validators: DOM XSS, prototype pollution, open redirect).

## Configuration note

- **Theme**: Streamlit theme lives in `.streamlit/config.toml` (dark base,
  teal primary color).
- **Projects directory**: defaults to `/home/user/deepbug/projects` — change
  `project_settings.base_projects_dir` in `app/modules/config.json` (see
  CONFIGURATION.md).

## Verify the install

After starting the app, confirm:

- The sidebar shows the brand, the ordered navigation (Projects → …
  → AI Assistant), and a project badge.
- Create a project on the Projects page — the Projects directory and
  `.current_project_name.txt` appear on disk.

If the browser shows the sidebar navigation and the project badge, the install
is good; missing tool warnings appear inside individual tabs as you use them.
