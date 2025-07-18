import os
import json
import shutil
import pandas as pd
import logging
from pathlib import Path
from typing import Dict, Any, Union, Optional, List

logger = logging.getLogger(__name__)

class ProjectManager:
    def __init__(self, config: Dict):
        self.config = config
        # Ensure base_projects_dir is always a Path object and exists
        self.base_projects_dir = Path(self.config['project_settings']['base_projects_dir']).expanduser()
        self.base_projects_dir.mkdir(parents=True, exist_ok=True)
        
        # File to store the currently active project name across sessions
        self.current_project_file = self.base_projects_dir / ".current_project_name.txt"
        self._current_project_name = self._load_current_project_name_from_file()
        
        logger.info(f"ProjectManager initialized. Projects directory: {self.base_projects_dir}")
        if self._current_project_name:
            logger.info(f"Loaded active project: {self._current_project_name}")
        else:
            logger.info("No active project loaded initially.")

    def _load_current_project_name_from_file(self) -> Optional[str]:
        """Loads the last active project name from a file."""
        if self.current_project_file.exists():
            try:
                name = self.current_project_file.read_text().strip()
                # Validate if the project directory actually exists
                if name and (self.base_projects_dir / name).is_dir():
                    return name
                else:
                    self.current_project_file.unlink(missing_ok=True) # Clean up if directory doesn't exist
                    return None
            except Exception as e:
                logger.error(f"Error loading current project name from file: {e}")
                return None
        return None

    def _save_current_project_name_to_file(self, project_name: str):
        """Saves the current active project name to a file."""
        try:
            self.current_project_file.write_text(project_name)
        except Exception as e:
            logger.error(f"Error saving current project name to file: {e}")

    def get_current_project_name(self) -> Optional[str]:
        """Returns the name of the currently active project."""
        return self._current_project_name

    def set_current_project(self, project_name: str) -> bool:
        """Sets the active project if it exists."""
        project_path = self.base_projects_dir / project_name
        if project_path.is_dir():
            self._current_project_name = project_name
            self._save_current_project_name_to_file(project_name)
            logger.info(f"Current project set to: {project_name}")
            return True
        logger.warning(f"Project '{project_name}' not found at {project_path}.")
        return False

    def create_project(self, project_name: str) -> bool:
        """Creates a new project directory and sets it as active."""
        project_path = self.base_projects_dir / project_name
        if project_path.exists():
            logger.warning(f"Project '{project_name}' already exists.")
            return False
        try:
            project_path.mkdir(parents=True, exist_ok=True)
            self._current_project_name = project_name
            self._save_current_project_name_to_file(project_name)
            logger.info(f"Project '{project_name}' created at {project_path} and set as active.")
            return True
        except Exception as e:
            logger.error(f"Failed to create project '{project_name}': {e}")
            return False

    def get_all_projects(self) -> List[str]:
        """Returns a list of all existing project names."""
        # Only list directories that are not the .current_project_name.txt file itself
        return sorted([d.name for d in self.base_projects_dir.iterdir() if d.is_dir() and not d.name.startswith('.')])

    def get_current_project_path(self) -> Optional[Path]:
        """Returns the Path object for the current project directory."""
        if self._current_project_name:
            return self.base_projects_dir / self._current_project_name
        return None

    # REVERTED / CORRECTED METHOD: Returns a dictionary whose keys are the target names
    def get_all_targets_for_current_project(self) -> Dict[str, Any]:
        """
        Retrieves all targets (represented by subdirectories) associated with the current project,
        returning them as keys in a dictionary. The value can be empty or hold metadata if needed later.
        """
        project_path = self.get_current_project_path()
        if not project_path:
            logger.warning("No current project set. Cannot retrieve targets.")
            return {}

        targets_dict = {}
        for item in project_path.iterdir():
            if item.is_dir() and not item.name.startswith('.'): # Exclude hidden directories
                # Reverse sanitization for target name
                # Assuming target names were sanitized with .replace('.', '_').replace('/', '_')
                original_target_name = item.name.replace('_', '.') # Adjust if you have more complex sanitization
                targets_dict[original_target_name] = {} # You can populate this with metadata if needed
        
        return targets_dict

    def add_target_to_current_project(self, target: str) -> bool:
        """
        Ensures a directory exists for the given target within the current project.
        This implicitly "adds" the target as it creates its storage location.
        """
        project_path = self.get_current_project_path()
        if not project_path:
            logger.error("No current project set. Cannot add target.")
            return False
        
        # Sanitize target name for directory creation
        sanitized_target = target.replace('.', '_').replace('/', '_') 
        target_dir = project_path / sanitized_target
        
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Ensured target directory exists for '{target}' in project '{self._current_project_name}'.")
            return True
        except Exception as e:
            logger.error(f"Failed to create directory for target '{target}': {e}")
            return False

    def save_scan_results(self, scan_type: str, target: str, results: Union[pd.DataFrame, Dict[str, pd.DataFrame]]):
        """
        Saves scan results to the current project's directory.
        Args:
            scan_type (str): Type of scan (e.g., 'subdomains', 'ports', 'js_analysis').
            target (str): The target identifier (e.g., domain, IP).
            results (Union[pd.DataFrame, Dict[str, pd.DataFrame]]): The results DataFrame(s).
        """
        project_path = self.get_current_project_path()
        if not project_path:
            logger.error("Cannot save results: No project selected.")
            return

        # Sanitize target name for directory
        sanitized_target = target.replace('.', '_').replace('/', '_') 
        target_dir = project_path / sanitized_target
        target_dir.mkdir(parents=True, exist_ok=True) # Ensure target directory exists

        file_name = f"{scan_type}_results.json"
        file_path = target_dir / file_name

        try:
            if isinstance(results, pd.DataFrame):
                results.to_json(file_path, orient='records', indent=4)
            elif isinstance(results, dict) and all(isinstance(v, pd.DataFrame) for v in results.values()):
                # For JS analysis or similar nested results where the dict keys are sub-types
                nested_data = {k: v.to_dict(orient='records') for k, v in results.items()}
                with open(file_path, 'w') as f:
                    json.dump(nested_data, f, indent=4)
            else:
                logger.error(f"Unsupported results type for saving: {type(results)}")
                return
            logger.info(f"Results for '{scan_type}' of '{target}' saved to {file_path}")
        except Exception as e:
            logger.error(f"Error saving results for '{scan_type}' of '{target}': {e}")

    def load_scan_results(self, scan_type: str, target: str) -> Union[pd.DataFrame, Dict[str, pd.DataFrame], None]:
        """
        Loads scan results from the current project's directory.
        Returns:
            Union[pd.DataFrame, Dict[str, pd.DataFrame], None]: Loaded results or empty DataFrame/Dict if not found/error.
        """
        project_path = self.get_current_project_path()
        if not project_path:
            return pd.DataFrame() # Return empty DataFrame if no project

        # Sanitize target name for directory
        sanitized_target = target.replace('.', '_').replace('/', '_')
        target_dir = project_path / sanitized_target
        file_name = f"{scan_type}_results.json"
        file_path = target_dir / file_name

        if not file_path.exists():
            # Return appropriate empty type based on expected scan_type
            if scan_type in ['js_analysis']: # Assuming JS analysis returns a dict of DFs
                return {}
            return pd.DataFrame() # Most others return a DataFrame

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            if isinstance(data, list): # Standard DataFrame
                return pd.DataFrame(data)
            elif isinstance(data, dict) and all(isinstance(v, list) for v in data.values()): # Nested DataFrames
                return {k: pd.DataFrame(v) for k, v in data.items()}
            else:
                logger.warning(f"Unexpected data format in {file_path}")
                if scan_type in ['js_analysis']:
                    return {}
                return pd.DataFrame()
        except Exception as e:
            logger.error(f"Error loading results for '{scan_type}' of '{target}': {e}")
            if scan_type in ['js_analysis']:
                return {}
            return pd.DataFrame()

    def get_all_results_for_current_project(self) -> Dict[str, Dict[str, Union[pd.DataFrame, Dict[str, pd.DataFrame]]]]:
        """
        Loads all scan results for the currently active project.
        Returns:
            Dict: A nested dictionary of results {scan_type: {target: results_df/dict_of_dfs}}.
        """
        project_path = self.get_current_project_path()
        if not project_path:
            return {}

        all_results = {}
        # Iterate through target directories
        for target_dir in project_path.iterdir():
            if target_dir.is_dir() and not target_dir.name.startswith('.'): # Exclude hidden directories
                # Reverse sanitization for display
                original_target_name = target_dir.name.replace('_', '.') # Adjust if more complex
                
                # Iterate through scan result files within each target directory
                for scan_file in target_dir.iterdir():
                    if scan_file.name.endswith("_results.json"):
                        scan_type = scan_file.name.replace("_results.json", "")
                        results = self.load_scan_results(scan_type, original_target_name)
                        
                        # Check if results are not empty before adding
                        is_empty = False
                        if isinstance(results, pd.DataFrame):
                            is_empty = results.empty
                        elif isinstance(results, dict):
                            is_empty = all(df.empty for df in results.values() if isinstance(df, pd.DataFrame))

                        if not is_empty:
                            if scan_type not in all_results:
                                all_results[scan_type] = {}
                            all_results[scan_type][original_target_name] = results
        return all_results 

    def delete_project(self, project_name: str) -> bool:
        """Delete a project and its directory."""
        if not project_name or not isinstance(project_name, str):
            logger.error(f"Invalid project name: {project_name}")
            return False
        
        project_path = self.base_projects_dir / project_name
        if not project_path.exists():
            logger.warning(f"Project '{project_name}' does not exist at {project_path}.")
            return False

        try:
            # Remove the project directory and all its contents
            shutil.rmtree(project_path)
            logger.info(f"Deleted project '{project_name}' and its files at {project_path}")

            # If the deleted project was the current one, clear the current project
            if self._current_project_name == project_name:
                self._current_project_name = None
                self._save_current_project_name_to_file("")
                logger.info(f"Cleared current project as '{project_name}' was deleted.")

            return True
        except Exception as e:
            logger.error(f"Failed to delete project '{project_name}': {e}")
            return False

# Required import for shutil (added at the top with other imports)
