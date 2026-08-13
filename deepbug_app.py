# deepbug_app.py
# DeepBug entrypoint: path setup, config, theme, sidebar brand/badge + ordered navigation.
# Run: streamlit run deepbug_app.py  (from the deepbug repository root)

import sys
from pathlib import Path

import streamlit as st

# --------------------------------------------------------------
# 1. Python path – project root + modules dir (kept for page compat)
# --------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent                  # deepbug/
MODULES_DIR = PROJECT_ROOT / 'app' / 'modules'

sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(MODULES_DIR))
sys.path.insert(0, str(PROJECT_ROOT / 'app'))

# --------------------------------------------------------------
# 2. Config + shared services (cached in session_state)
# --------------------------------------------------------------
from app.modules.utils import load_config
from app.modules.project_manager import ProjectManager
from app.utils.theme import (inject_theme, sidebar_brand, sidebar_project_badge,
                             theme_toggle, current_theme)

CONFIG = load_config()

if 'db_config' not in st.session_state:
    st.session_state.db_config = CONFIG
if 'project_manager_instance' not in st.session_state:
    st.session_state.project_manager_instance = ProjectManager(CONFIG)
if 'db_theme' not in st.session_state:
    st.session_state.db_theme = 'dark'

project_manager = st.session_state.project_manager_instance

# --------------------------------------------------------------
# 3. Page config (single source of truth for the whole app)
# --------------------------------------------------------------
st.set_page_config(
    page_title="DeepBug - Automated Recon & Bug Hunting",
    page_icon="🐛",
    layout="wide",
    initial_sidebar_state="expanded",
)
inject_theme()

# --------------------------------------------------------------
# 4. Sidebar shell (brand + active project chip + theme toggle)
# --------------------------------------------------------------
sidebar_brand()
sidebar_project_badge(project_manager)
theme_toggle()

# --------------------------------------------------------------
# 5. Navigation – canonical workflow order:
#    Projects → Reconnaissance → Vulnerability Scanner → Dashboard → Reporting → AI Assistant → Integrations
# --------------------------------------------------------------
PAGES_DIR = PROJECT_ROOT / 'app' / 'pages'

nav = st.navigation([
    st.Page(str(PAGES_DIR / '0_Projects.py'), title='Projects', icon='📂', url_path='projects'),
    st.Page(str(PAGES_DIR / '1_Recon.py'), title='Reconnaissance', icon='🔍', url_path='recon'),
    st.Page(str(PAGES_DIR / '2_Scanner.py'), title='Vulnerability Scanner', icon='🛡️', url_path='scanner'),
    st.Page(str(PAGES_DIR / '3_Dashboard.py'), title='Dashboard', icon='📊', url_path='dashboard'),
    st.Page(str(PAGES_DIR / '4_Reporting.py'), title='Reporting', icon='📄', url_path='reporting'),
    st.Page(str(PAGES_DIR / '5_AI.py'), title='AI Assistant', icon='🤖', url_path='ai'),
    st.Page(str(PAGES_DIR / '6_Integrations.py'), title='Integrations', icon='🔌', url_path='integrations'),
], position='sidebar')

nav.run()