import sys
import html
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
app_header("📄", "Reporting", "Generate an HTML report from the saved scan results of the active project.")

if 'project_manager_instance' not in st.session_state:
    st.session_state.project_manager_instance = ProjectManager(CONFIG)
project_manager = st.session_state.project_manager_instance

if not project_manager.get_current_project_name():
    st.warning("No project selected. Go to Projects first.")
    st.stop()


def _nice_label(target: str, scan_type: str, sub: str = '') -> str:
    base = scan_type.replace('_', ' ').title()
    if sub:
        return f"{target} - {base} - {sub.replace('_', ' ').title()}"
    return f"{target} - {base}"


def get_report_sections():
    """(label, df) for every non-empty saved scan result across targets."""
    sections = []
    all_results = project_manager.get_all_results_for_current_project()  # {scan_type: {target: df}}
    for scan_type in sorted(all_results.keys()):
        for target in sorted(all_results[scan_type].keys()):
            data = all_results[scan_type][target]
            if data is None:
                continue
            if isinstance(data, dict):
                for sub_key in sorted(data.keys()):
                    df = data[sub_key]
                    if isinstance(df, pd.DataFrame) and not df.empty:
                        sections.append((_nice_label(target, scan_type, sub_key), df))
            elif isinstance(data, pd.DataFrame) and not data.empty:
                sections.append((_nice_label(target, scan_type), data))
    return sections


sections = get_report_sections()
labels = [label for label, _ in sections]
total_rows = sum(len(df) for _, df in sections)

if not labels:
    st.info("No results saved for the active project yet. Run scans in Reconnaissance, then run a Vulnerability Scan; results appear here.")
else:
    st.caption(f"{len(sections)} section(s), {total_rows} total row(s) loaded from disk.")

    st.subheader("Select Scan Results to Include")
    selected_labels = st.multiselect(
        "Choose which scan results to include in the report:",
        options=labels,
        default=labels  # Select all by default for convenience
    )

    report_title = st.text_input("Report Title", "Bug Bounty Reconnaissance Report")
    report_author = st.text_input("Report Author", "BugBountyBot User")

    if st.button("Generate HTML Report"):
        if not selected_labels:
            st.warning("Please select at least one scan result to include in the report.")
        else:
            label_to_df = dict(sections)
            report_sections = []
            for label in selected_labels:
                df_to_add = label_to_df.get(label)
                display_title = label
                if df_to_add is not None and not df_to_add.empty:
                    report_sections.append(f"<h2>{display_title}</h2>")
                    report_sections.append(df_to_add.to_html(classes="dataframe", escape=False, index=False))
                    report_sections.append("<br><hr><br>")  # Separator for readability
                else:
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