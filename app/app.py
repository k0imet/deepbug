# app.py

import streamlit as st
import sys
from pathlib import Path

# Add the 'modules' directory to the Python path
# This allows importing modules like 'utils', 'project_manager', 'recon' directly
sys.path.insert(0, str(Path(__file__).resolve().parent / 'modules'))

from utils import load_config, setup_logging

# Load configuration and setup logging as early as possible
CONFIG = load_config()
setup_logging(CONFIG)

st.set_page_config(
    page_title="DeepBug - Automated Recon & Bug Hunting Platform",
    page_icon="🐛",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.sidebar.title("DeepBug 🐛")
st.sidebar.markdown("Automated Recon & Bug Hunting Platform")

# Ensure project_manager_instance is initialized early for all pages
# (It's also done in 0_Projects.py, but doing it here ensures it's always ready)
from project_manager import ProjectManager
if 'project_manager_instance' not in st.session_state:
    st.session_state.project_manager_instance = ProjectManager(CONFIG)
# Get the current project name from the ProjectManager (which loads from file)
if 'current_project_name' not in st.session_state:
    st.session_state.current_project_name = st.session_state.project_manager_instance.get_current_project_name()

# Display current active project in sidebar
current_project = st.session_state.get('current_project_name')
if current_project:
    st.sidebar.success(f"Active Project: **{current_project}**")
else:
    st.sidebar.warning("No project selected.")

st.sidebar.markdown("---")
st.sidebar.header("Navigation")
st.sidebar.page_link("pages/0_Projects.py", label="📂 Projects", icon="📂")
st.sidebar.page_link("pages/1_Dashboard.py", label="📊 Dashboard", icon="📊")
st.sidebar.page_link("pages/2_Recon.py", label="🔍 Reconnaissance", icon="🔍")
st.sidebar.page_link("pages/3_Scanner.py", label="🛡️ Vulnerability Scan", icon="🛡️")
st.sidebar.page_link("pages/4_Reporting.py", label="📄 Reporting", icon="📄")

# Main content for the home page (app.py) if no specific page is selected
st.markdown("""
# Welcome to DeepBug 🐛

DeepBug is an automated reconnaissance and bug bounty hunting platform designed to streamline your workflow.
It integrates various open-source tools to perform subdomain enumeration, port scanning, JavaScript analysis,
vulnerability scanning, and more, all managed within a user-friendly interface.

## Get Started:

1.  **📂 Projects:** Start by creating a new project or loading an existing one. All your scan results and findings will be saved under the active project.
2.  **🔍 Reconnaissance:** Dive into discovery! Run subdomain scans, active host verification, port scans, and JavaScript analysis.
3.  **🛡️ Vulnerability Scan:** Once you have your targets, launch vulnerability scans using integrated tools like Nuclei.
4.  **📊 Dashboard & 📄 Reporting:** Review your findings, track progress, and generate comprehensive reports.

Happy Hunting!
""")

st.info("💡 Tip: Use the sidebar to navigate between different sections of the application.")