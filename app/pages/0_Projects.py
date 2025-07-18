# pages/0_Projects.py

import streamlit as st
import sys
from pathlib import Path
import pandas as pd

# Add the modules directory to the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'modules'))

from project_manager import ProjectManager
from utils import load_config, setup_logging  # Import setup_logging from utils

# Load configuration and setup logging
CONFIG = load_config()
setup_logging(CONFIG)  # Call setup_logging here too

st.set_page_config(layout="wide", page_title="Project Management")

# Initialize ProjectManager - Ensure it's done only once and persisted
if 'project_manager_instance' not in st.session_state:
    st.session_state.project_manager_instance = ProjectManager(CONFIG)
project_manager: ProjectManager = st.session_state.project_manager_instance

# Sync Streamlit session state with ProjectManager's active project
if 'current_project_name' not in st.session_state:
    st.session_state.current_project_name = project_manager.get_current_project_name()
elif st.session_state.current_project_name != project_manager.get_current_project_name():
    # If session state project diverges from persisted project, update session state
    st.session_state.current_project_name = project_manager.get_current_project_name()

st.title("📂 Project Management")
st.markdown("Create, load, and manage your reconnaissance projects.")

st.sidebar.header("Project Actions")

# --- Create New Project ---
with st.sidebar.expander("Create New Project", expanded=True):
    new_project_name = st.text_input("New Project Name", key="new_project_input")
    if st.button("Create Project", key="create_project_button"):
        if new_project_name:
            if project_manager.create_project(new_project_name):
                st.session_state.current_project_name = new_project_name  # Update session state
                st.sidebar.success(f"Project '{new_project_name}' created and set as active!")
                st.rerun()  # Rerun to update the project selection dropdown and other pages
            else:
                st.sidebar.error(f"Failed to create project '{new_project_name}'. It might already exist or name is invalid.")
        else:
            st.sidebar.warning("Please enter a project name.")

# --- Load Existing Project ---
all_projects = project_manager.get_all_projects()
with st.sidebar.expander("Load Existing Project", expanded=len(all_projects) > 0):
    if all_projects:
        current_selection_pm = project_manager.get_current_project_name()  # Get from ProjectManager
        
        # Determine default index for the selectbox
        default_index = 0
        if current_selection_pm and current_selection_pm in all_projects:
            default_index = all_projects.index(current_selection_pm) + 1  # +1 for the "" option

        selected_project = st.selectbox(
            "Select Project:",
            options=[''] + all_projects,  # Add an empty option at the start
            index=default_index,
            key="select_project"
        )
        if st.button("Load Project", key="load_project_button"):
            if selected_project:
                if project_manager.set_current_project(selected_project):
                    st.session_state.current_project_name = selected_project  # Update session state
                    st.sidebar.success(f"Project '{selected_project}' loaded successfully!")
                    st.rerun()  # Rerun to update active project display on other pages
                else:
                    st.sidebar.error(f"Failed to load project '{selected_project}'. It may not exist.")
            else:
                st.sidebar.warning("Please select a project to load.")
    else:
        st.sidebar.info("No projects found. Create a new one!")

# --- Delete Project ---
with st.sidebar.expander("Delete Project", expanded=False):
    if all_projects:
        delete_project = st.selectbox(
            "Select Project to Delete:",
            options=[''] + all_projects,  # Add an empty option at the start
            index=0,
            key="delete_project"
        )
        if delete_project:
            if st.button("Confirm Delete", key="confirm_delete_button"):
                # Add a confirmation dialog
                if st.session_state.get("confirm_delete", False):
                    if project_manager.delete_project(delete_project):
                        if delete_project == project_manager.get_current_project_name():
                            st.session_state.current_project_name = None  # Clear active project if deleted
                        st.session_state.confirm_delete = False  # Reset confirmation state
                        st.sidebar.success(f"Project '{delete_project}' and its files deleted successfully!")
                        st.rerun()  # Rerun to refresh the project list and UI
                    else:
                        st.sidebar.error(f"Failed to delete project '{delete_project}'. Check logs for details.")
                else:
                    st.session_state.confirm_delete = True
                    st.sidebar.warning(f"Are you sure you want to delete '{delete_project}'? This action cannot be undone. Click 'Confirm Delete' again to proceed.")
        else:
            st.sidebar.warning("Please select a project to delete.")
    else:
        st.sidebar.info("No projects available to delete.")

# --- Display Current Project Status on Main Page ---
st.markdown("---")
current_project = project_manager.get_current_project_name()  # Still get from ProjectManager
if current_project:
    st.success(f"Currently Active Project: **{current_project}**")
    st.write(f"Results for this project are stored in: `{project_manager.get_current_project_path()}`")

    # Display a summary of results in the current project
    st.subheader("Project Overview: Scans Completed")
    all_results = project_manager.get_all_results_for_current_project()
    
    if all_results:
        summary_data = []
        for scan_type, targets_data in all_results.items():
            for target_name, result_data in targets_data.items():
                if isinstance(result_data, pd.DataFrame):
                    summary_data.append({
                        "Scan Type": scan_type.replace('_', ' ').title(),
                        "Target": target_name,
                        "Results": f"{len(result_data)} rows"
                    })
                elif isinstance(result_data, dict):  # For nested results like JS analysis
                    nested_summary = []
                    for sub_type, sub_df in result_data.items():
                        if isinstance(sub_df, pd.DataFrame) and not sub_df.empty:
                            nested_summary.append(f"{sub_type.replace('_', ' ').title()} ({len(sub_df)} rows)")
                    summary_data.append({
                        "Scan Type": scan_type.replace('_', ' ').title(),
                        "Target": target_name,
                        "Results": ", ".join(nested_summary) if nested_summary else "No nested results"
                    })
        if summary_data:
            st.dataframe(pd.DataFrame(summary_data), use_container_width=True)
        else:
            st.info("No scan results recorded for this project yet.")
    else:
        st.info("No scan results recorded for this project yet.")

else:
    st.warning("No project is currently loaded. Please create a new project or load an existing one from the sidebar.")