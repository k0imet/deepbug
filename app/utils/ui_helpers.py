# app/utils/ui_helpers.py
# Tiny streamlit UI helpers shared by pages: consistent result sections,
# compact tables with download buttons, status captions and AI output
# rendering. Keeps pages decluttered by pushing bulk content behind
# expanders instead of long vertical dumps.

import pandas as pd
from typing import List, Optional, Any, Dict


def render_df(st, df, columns: Optional[List[str]] = None,
              title: str = "Results", download_name: str = "results.csv",
              expanded: bool = False):
    """Render a dataframe inside an expander with a download button.

    `download_name` must be unique per call site (it doubles as the button key).
    No-op when the data is empty.
    """
    if df is None:
        return
    if isinstance(df, list):
        df = pd.DataFrame(df) if df else pd.DataFrame()
    if not isinstance(df, pd.DataFrame) or df.empty:
        return
    if columns:
        cols = [c for c in columns if c in df.columns]
        df = df[cols]
    with st.expander(f"{title} ({len(df)})", expanded=expanded):
        st.dataframe(df, use_container_width=True)
        st.download_button("📥 Download", df.to_csv(index=False),
                           download_name, "text/csv", key=f"dl_{download_name}")


def section_caption(st, ok: bool, text: str):
    """Single-line ok/warn status caption - cheaper than a st.success + details."""
    st.caption(("OK: " if ok else "WARN: ") + text)


def analysis_result(st, result: Dict[str, Any]):
    """Render AI/heuristic analysis output with a source badge."""
    if not isinstance(result, dict) or not result.get('text'):
        st.info("No analysis output.")
        return
    if result.get('source') == 'ai':
        st.success("AI analysis")
    else:
        st.caption("Local heuristic analysis - set `ai.enable: true` + `ai.api_key` "
                   "in config.json (or OPENAI_API_KEY) for real AI output.")
    st.markdown(result['text'])