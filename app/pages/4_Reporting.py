import streamlit as st
import pandas as pd
from datetime import datetime
# import base64 # Removed: Not used in the current logic
import sys
from pathlib import Path
import html # Already correctly imported for escaping HTML

# Add the modules directory to the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'modules'))

# --- Import load_config and setup_logging ---
from utils import load_config, setup_logging

# --- Load configuration and setup logging ---
# This is the crucial fix for the TypeError
CONFIG = load_config()
setup_logging(CONFIG) 

st.set_page_config(layout="wide", page_title="Report Generator")

st.title("📄 Report Generator")
st.markdown("Select scan results from your current session to generate an HTML report.")

# --- Helper function to get all relevant scan keys from session state ---
def get_all_scan_keys_from_session():
    keys = []
    # Iterate through session_state to find dataframes from recon and js_analysis
    for key in st.session_state:
        # Check if the key indicates scan results and its value is a DataFrame or a dictionary
        if ('_results_' in key or 'js_analysis_results_' in key) and isinstance(st.session_state[key], (pd.DataFrame, dict)):
            # If it's a dict (from full_js_analysis), iterate its sub-keys
            if isinstance(st.session_state[key], dict):
                for sub_key in st.session_state[key]:
                    # Only add if the nested item is a DataFrame and not empty
                    if isinstance(st.session_state[key][sub_key], pd.DataFrame) and not st.session_state[key][sub_key].empty:
                        # Append with a descriptive prefix for dicts to differentiate
                        keys.append(f"{key}/{sub_key}")
            # If it's a direct DataFrame and not empty
            elif isinstance(st.session_state[key], pd.DataFrame) and not st.session_state[key].empty:
                keys.append(key)
    return sorted(list(set(keys))) # Use set to deduplicate, then sort for consistent order

available_scan_keys = get_all_scan_keys_from_session()

if not available_scan_keys:
    st.info("No scan results found in the current session to generate a report. Please run some scans first.")
else:
    st.subheader("Select Scan Results to Include")
    selected_keys = st.multiselect(
        "Choose which scan results to include in the report:",
        options=available_scan_keys,
        default=available_scan_keys # Select all by default for convenience
    )

    report_title = st.text_input("Report Title", "Bug Bounty Reconnaissance Report")
    report_author = st.text_input("Report Author", "BugBountyBot User")

    if st.button("Generate HTML Report"):
        if not selected_keys:
            st.warning("Please select at least one scan result to include in the report.")
        else:
            report_sections = []
            for key_to_include in selected_keys:
                df_to_add = None
                # Default display title
                display_title = key_to_include.replace('_', ' ').replace('results', 'Results').title()

                # Handle nested dictionary structure (e.g., from JS analysis)
                if '/' in key_to_include:
                    main_key, sub_key = key_to_include.split('/', 1)
                    if main_key in st.session_state and isinstance(st.session_state[main_key], dict):
                        if sub_key in st.session_state[main_key] and isinstance(st.session_state[main_key][sub_key], pd.DataFrame):
                            df_to_add = st.session_state[main_key][sub_key]
                            # Create a more descriptive title for nested data
                            display_title = f"{main_key.replace('_', ' ').title()} - {sub_key.replace('_', ' ').title()}"
                else:
                    # Handle direct DataFrame in session state
                    if key_to_include in st.session_state and isinstance(st.session_state[key_to_include], pd.DataFrame):
                        df_to_add = st.session_state[key_to_include]
                
                # Add DataFrame to report if available and not empty
                if df_to_add is not None and not df_to_add.empty:
                    report_sections.append(f"<h2>{display_title}</h2>")
                    report_sections.append(df_to_add.to_html(classes="dataframe", escape=False, index=False))
                    report_sections.append("<br><hr><br>") # Separator for readability
                else:
                    # Indicate if no data was found for a selected section
                    report_sections.append(f"<h2>{display_title}</h2>")
                    report_sections.append("<p>No data available for this section.</p>")
                    report_sections.append("<br><hr><br>")

            # Basic HTML Template using .format() as per your original structure
            html_template = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>{report_title_escaped}</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        margin: 20px;
                        background-color: #f4f4f4;
                        color: #333;
                    }}
                    .container {{
                        max-width: 1200px;
                        margin: auto;
                        background: #fff;
                        padding: 30px;
                        border-radius: 8px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    }}
                    h1, h2, h3 {{
                        color: #0056b3;
                    }}
                    table {{
                        width: 100%;
                        border-collapse: collapse;
                        margin-bottom: 20px;
                    }}
                    th, td {{
                        border: 1px solid #ddd;
                        padding: 8px;
                        text-align: left;
                    }}
                    th {{
                        background-color: #e0e0e0;
                        font-weight: bold;
                    }}
                    tr:nth-child(even) {{
                        background-color: #f9f9f9;
                    }}
                    .footer {{
                        margin-top: 40px;
                        padding-top: 20px;
                        border-top: 1px solid #eee;
                        text-align: center;
                        color: #777;
                        font-size: 0.9em;
                    }}
                    .dataframe {{
                        border: 1px solid #ccc;
                        border-collapse: collapse;
                    }}
                    .dataframe th, .dataframe td {{
                        padding: 8px 12px;
                        border: 1px solid #ccc;
                    }}
                    .dataframe th {{
                        background-color: #f2f2f2;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>{report_title_escaped}</h1>
                    <p><strong>Generated By:</strong> {report_author_escaped}</p>
                    <p><strong>Date:</strong> {report_date}</p>
                    <hr>
                    {report_sections_html}
                    <div class="footer">
                        <p>This report was generated by BugBountyBot.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Escape HTML characters in user-provided inputs for security
            report_title_escaped = html.escape(report_title)
            report_author_escaped = html.escape(report_author)

            # Populate the HTML template
            html_content = html_template.format(
                report_title_escaped=report_title_escaped,
                report_author_escaped=report_author_escaped,
                report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                report_sections_html="\n".join(report_sections)
            )
            
            # Provide a download button for the generated HTML report
            st.download_button(
                label="Download HTML Report",
                data=html_content,
                file_name=f"{report_title.replace(' ', '_').lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                mime="text/html"
            )
            st.success("Report generated! Click the 'Download HTML Report' button above.")