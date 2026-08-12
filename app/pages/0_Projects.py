import sys
import json
from datetime import datetime
from pathlib import Path

import streamlit as st
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from app.modules.utils import load_config
from app.modules.project_manager import ProjectManager
from app.utils.theme import inject_theme, app_header

CONFIG = load_config()

inject_theme()
app_header("📂", "Projects", "Create, load, and manage your reconnaissance projects.")

# Initialize ProjectManager
if 'project_manager_instance' not in st.session_state:
    st.session_state.project_manager_instance = ProjectManager(CONFIG)
project_manager = st.session_state.project_manager_instance

# Sync project
if 'current_project_name' not in st.session_state:
    st.session_state.current_project_name = project_manager.get_current_project_name()
elif st.session_state.current_project_name != project_manager.get_current_project_name():
    st.session_state.current_project_name = project_manager.get_current_project_name()


def scan_overview():
    project_path = project_manager.get_current_project_path()
    if not project_path or not project_path.is_dir():
        return []
    rows = []
    for target_dir in project_path.iterdir():
        if not target_dir.is_dir() or target_dir.name.startswith('.'):
            continue
        target_name = target_dir.name.replace('_', '.')
        for scan_file in target_dir.glob('*_results.json'):
            try:
                ts = scan_file.stat().st_mtime
                with open(scan_file, 'r') as f:
                    data = json.load(f)
            except (OSError, ValueError):
                continue
            modified = datetime.fromtimestamp(ts)
            scan_type = scan_file.name.replace('_results.json', '').replace('_', ' ').title()
            if isinstance(data, list):
                rows.append({'Scan Type': scan_type, 'Target': target_name, 'Records': len(data), 'Last Modified': modified})
            elif isinstance(data, dict):
                for sub_type, v in data.items():
                    records = len(v) if isinstance(v, list) else 0
                    rows.append({'Scan Type': f"{scan_type} ({sub_type.replace('_', ' ').title()})", 'Target': target_name, 'Records': records, 'Last Modified': modified})
    rows.sort(key=lambda r: r['Last Modified'], reverse=True)
    return rows


# Sidebar actions
with st.sidebar:
    st.header("Project Actions")
    with st.expander("Create New Project", expanded=True):
        new_project_name = st.text_input("New Project Name", key="new_project_input")
        if st.button("Create Project", key="create_project_button"):
            if new_project_name:
                if project_manager.create_project(new_project_name):
                    st.session_state.current_project_name = new_project_name
                    st.sidebar.success(f"Project '{new_project_name}' created!")
                    st.rerun()
                else:
                    st.sidebar.error("Failed to create project.")
            else:
                st.sidebar.warning("Enter a name.")

    all_projects = project_manager.get_all_projects()
    with st.expander("Load Existing Project", expanded=len(all_projects) > 0):
        if all_projects:
            current = project_manager.get_current_project_name()
            default_idx = all_projects.index(current) + 1 if current in all_projects else 0
            selected = st.selectbox("Select Project:", options=[''] + all_projects, index=default_idx, key="select_project")
            if st.button("Load Project", key="load_project_button"):
                if selected and project_manager.set_current_project(selected):
                    st.session_state.current_project_name = selected
                    st.sidebar.success(f"Loaded '{selected}'")
                    st.rerun()
                else:
                    st.sidebar.error("Failed to load.")
        else:
            st.sidebar.info("No projects found.")

    with st.expander("Delete Project", expanded=False):
        if all_projects:
            delete_project = st.selectbox("Select Project to Delete:", options=[''] + all_projects, index=0, key="delete_project")
            if delete_project:
                if st.button("Confirm Delete", key="confirm_delete_button"):
                    if project_manager.delete_project(delete_project):
                        if delete_project == project_manager.get_current_project_name():
                            st.session_state.current_project_name = None
                        st.sidebar.success(f"Deleted '{delete_project}'")
                        st.rerun()
                    else:
                        st.sidebar.error("Deletion failed.")
        else:
            st.sidebar.info("No projects to delete.")

# Main page – project overview
current_project = project_manager.get_current_project_name()
if current_project:
    st.success(f"**Active Project:** `{current_project}`")
    st.write(f"Results stored in: `{project_manager.get_current_project_path()}`")

    if st.button("🔄 Refresh"):
        st.rerun()

    st.subheader("📊 Project Overview")
    overview = scan_overview()
    if overview:
        st.dataframe(pd.DataFrame(overview), width='stretch')
    else:
        st.info("No scan data found.")
else:
    st.warning("No project loaded. Use the sidebar to create or load one.")