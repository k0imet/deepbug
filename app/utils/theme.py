# app/utils/theme.py
# DeepBug design system: dual-palette (dark/light) theme, shared page header,
# sidebar brand + project badge + theme toggle.
#
# Streamlit >= 1.5x themes widgets through emotion inline styles (no CSS vars),
# so the toggle swaps a full CSS overlay for the chosen palette. Both palettes
# cover every surface DeepBug controls; native widget colors are overridden
# with !important per palette.

import streamlit as st

DEFAULT_THEME = "dark"
THEME_KEY = "db_theme"


def _palette(name: str) -> dict:
    return PALETTES.get(name, PALETTES[DEFAULT_THEME])


PALETTES = {
    "dark": {
        "name": "dark",
        "bg": "#0e1117",
        "bg2": "#161b22",
        "text": "#e6edf3",
        "muted": "#9aa7b8",
        "accent": "#0fb3a4",
        "accent_strong": "#0c9488",
        "accent_soft": "rgba(15,179,164,0.16)",
        "border": "rgba(255,255,255,0.10)",
        "sidebar_from": "#0d1420",
        "sidebar_to": "#0a1018",
        "sidebar_text": "#dbe4ee",
        "sidebar_muted": "#8fa3b8",
        "card_bg": "#131820",
        "table_header": "#1c2530",
        "input_bg": "#0d1117",
        "input_border": "rgba(255,255,255,0.18)",
        "popup_bg": "#1a212b",
        "button_text": "#ffffff",
        "plotly_bg": "#0e1117",
        "plotly_text": "#e6edf3",
    },
    "light": {
        "name": "light",
        "bg": "#f7f9fb",
        "bg2": "#ffffff",
        "text": "#1a202c",
        "muted": "#5b6675",
        "accent": "#0e9488",
        "accent_strong": "#0b7f74",
        "accent_soft": "rgba(14,148,136,0.12)",
        "border": "rgba(20,30,45,0.14)",
        "sidebar_from": "#eef2f6",
        "sidebar_to": "#e6ecf2",
        "sidebar_text": "#24303e",
        "sidebar_muted": "#5c6b7d",
        "card_bg": "#ffffff",
        "table_header": "#e4eaf0",
        "input_bg": "#ffffff",
        "input_border": "rgba(20,30,45,0.22)",
        "popup_bg": "#ffffff",
        "button_text": "#ffffff",
        "plotly_bg": "#ffffff",
        "plotly_text": "#1a202c",
    },
}


def _css(p: dict) -> str:
    return f"""
<style>
/* ============================= DeepBug theme ({p['name']}) ============================= */
html, body {{
    color: {p['text']};
}}
[data-testid="stAppViewContainer"] {{
    background-color: {p['bg']} !important;
    color: {p['text']} !important;
}}
[data-testid="stHeader"] {{
    background: transparent !important;
}}
h1, h2, h3, h4, h5, h6 {{
    color: {p['text']} !important;
}}
p, li, span, label, [data-testid="stMarkdownContainer"], [data-testid="stCaptionContainer"] {{
    color: {p['text']};
}}
a {{
    color: {p['accent']} !important;
}}
code, pre {{
    background: {p['bg2']} !important;
    color: {p['text']} !important;
}}

/* ---------- Sidebar ---------- */
section[data-testid="stSidebar"] {{
    background: linear-gradient(180deg, {p['sidebar_from']} 0%, {p['sidebar_to']} 100%) !important;
    border-right: 1px solid {p['border']};
}}
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3,
section[data-testid="stSidebar"] h4,
section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] span[data-testid="stCaptionContainer"],
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] {{
    color: {p['sidebar_text']} !important;
}}
section[data-testid="stSidebar"] hr {{
    border-color: {p['border']};
}}
section[data-testid="stSidebar"] a[data-testid="stPageLink"] {{
    border-radius: 8px;
    padding: 0.35rem 0.6rem;
    transition: background 0.15s ease;
    color: {p['sidebar_text']} !important;
}}
section[data-testid="stSidebar"] a[data-testid="stPageLink"]:hover {{
    background: {p['accent_soft']};
}}
section[data-testid="stSidebar"] [data-testid="stExpander"] {{
    background: {p['accent_soft']};
    border: 1px solid {p['border']};
    border-radius: 10px;
}}
section[data-testid="stSidebar"] [data-testid="stExpander"] summary {{ color: {p['sidebar_text']}; }}

/* ---------- Brand + project badge ---------- */
.db-brand {{
    display: flex; align-items: center; gap: 0.6rem;
    padding: 0.4rem 0.15rem 0.15rem 0.15rem;
}}
.db-brand-bug {{ font-size: 1.6rem; line-height: 1; }}
.db-brand-title {{
    font-size: 1.25rem; font-weight: 700; letter-spacing: 0.2px;
    color: {p['text']}; line-height: 1.1;
}}
.db-brand-sub {{
    font-size: 0.68rem; color: {p['muted']}; letter-spacing: 0.4px;
    text-transform: uppercase; margin-top: 2px;
}}
.db-project-badge {{
    margin: 0.6rem 0 0.2rem 0; padding: 0.55rem 0.7rem; border-radius: 10px;
    background: {p['accent_soft']};
    border: 1px solid {p['accent']}55;
    font-size: 0.82rem; line-height: 1.35;
}}
.db-project-badge .db-pb-label {{
    font-size: 0.62rem; letter-spacing: 0.6px; text-transform: uppercase;
    color: {p['accent']}; font-weight: 600;
}}
.db-project-badge .db-pb-name {{
    color: {p['text']}; font-weight: 600; word-break: break-all;
}}
.db-project-badge .db-pb-none {{ color: #e8a33d; font-weight: 500; }}

/* ---------- Page hero ---------- */
.db-hero {{
    padding: 0.4rem 0 0.9rem 0; border-bottom: 1px solid {p['border']};
    margin-bottom: 1.1rem;
}}
.db-hero-icon {{ font-size: 1.5rem; }}
.db-hero-title {{
    font-size: 1.65rem; font-weight: 750; letter-spacing: -0.2px;
    margin: 0; line-height: 1.15; color: {p['text']} !important;
}}
.db-hero-sub {{ color: {p['muted']}; font-size: 0.9rem; margin-top: 0.15rem; }}

/* ---------- Cards / KPI ---------- */
.db-card {{
    background: {p['card_bg']}; border: 1px solid {p['border']};
    border-radius: 12px; padding: 0.9rem 1rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.15);
}}
.db-card h4 {{ margin: 0 0 0.3rem 0; font-size: 0.85rem; letter-spacing: 0.3px;
    text-transform: uppercase; color: {p['muted']}; }}
.db-card .db-kpi {{ font-size: 1.9rem; font-weight: 750; line-height: 1.1; color: {p['text']}; }}
.db-kpi-accent {{ color: {p['accent']}; }}
div[data-testid="stMetric"] {{
    background: {p['card_bg']};
    border: 1px solid {p['border']};
    border-radius: 12px;
    padding: 0.7rem 0.9rem;
}}
div[data-testid="stMetric"] label {{ color: {p['muted']} !important; }}
div[data-testid="stMetricValue"] {{ color: {p['text']} !important; }}

/* ---------- Buttons ---------- */
.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button {{
    border-radius: 8px; font-weight: 550;
    background: {p['bg2']};
    border: 1px solid {p['input_border']};
    color: {p['text']} !important;
}}
.stButton > button:hover, .stDownloadButton > button:hover, .stFormSubmitButton > button:hover {{
    border-color: {p['accent']};
}}
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] {{
    background: {p['accent']} !important;
    border: 1px solid {p['accent']} !important;
    color: {p['button_text']} !important;
}}
.stButton > button[kind="primary"]:hover, .stFormSubmitButton > button[kind="primary"]:hover {{
    background: {p['accent_strong']} !important;
}}

/* ---------- Inputs ---------- */
[data-testid="stTextInput"] input, [data-testid="stNumberInput"] input,
[data-testid="stTextArea"] textarea, [data-testid="stDateInput"] input,
[data-testid="stTimeInput"] input, [data-testid="stSelectbox"] [data-baseweb="select"],
[data-testid="stMultiSelect"] [data-baseweb="select"] {{
    background-color: {p['input_bg']} !important;
    border-color: {p['input_border']} !important;
    color: {p['text']} !important;
}}
[data-testid="stSelectbox"] [data-baseweb="select"] input,
[data-testid="stMultiSelect"] [data-baseweb="select"] input,
[data-testid="stTextInput"] input, [data-testid="stNumberInput"] input,
[data-testid="stTextArea"] textarea {{
    color: {p['text']} !important;
}}
/* dropdown menus */
[data-baseweb="popover"] [data-baseweb="menu"], [data-baseweb="popover"] ul {{
    background-color: {p['popup_bg']} !important;
}}
[data-baseweb="popover"] [role="option"], [data-baseweb="menu"] li {{
    color: {p['text']} !important;
}}
[data-baseweb="popover"] [role="option"]:hover {{
    background-color: {p['accent_soft']} !important;
}}
/* radio / checkbox */
[data-testid="stRadio"] label, [data-testid="stCheckbox"] label,
[data-testid="stRadio"] span, [data-testid="stCheckbox"] span {{
    color: {p['text']} !important;
}}

/* ---------- Tabs ---------- */
.stTabs [data-baseweb="tab-list"] {{ gap: 6px; }}
.stTabs [data-baseweb="tab"] {{
    border-radius: 8px 8px 0 0; font-weight: 550; padding: 0.45rem 0.9rem;
    color: {p['muted']} !important;
}}
.stTabs [data-baseweb="tab"][aria-selected="true"] {{
    color: {p['text']} !important;
    box-shadow: inset 0 -2px 0 {p['accent']};
}}

/* ---------- Tables / dataframes ---------- */
[data-testid="stDataFrame"] {{
    border: 1px solid {p['border']}; border-radius: 10px; overflow: hidden;
    --gdg-bg-cell: {p['bg']};
    --gdg-bg-header: {p['table_header']};
    --gdg-bg-header-has-focus: {p['table_header']};
    --gdg-text-dark: {p['text']};
    --gdg-text-light: {p['text']};
    --gdg-border-color: {p['border']};
    --gdg-accent-color: {p['accent']};
    --gdg-accent-fg: {p['button_text']};
    --gdg-accent-light: {p['accent_soft']};
    --gdg-bg-bubble: {p['accent_soft']};
}}

/* ---------- Expanders / alerts / progress / chat ---------- */
[data-testid="stExpander"] {{
    border: 1px solid {p['border']}; border-radius: 10px;
    background: {p['bg2']};
}}
.stProgress > div > div > div > div {{ background: {p['accent']}; }}
[data-testid="stChatMessage"] {{ background: {p['bg2']}; border: 1px solid {p['border']}; }}
[data-testid="stSidebar"] [data-testid="stChatMessage"] {{ background: transparent; border: none; }}
</style>
"""


def current_theme() -> str:
    """Active palette name ('dark' | 'light')."""
    return st.session_state.get(THEME_KEY, DEFAULT_THEME)


def get_palette() -> dict:
    """Colors for the active palette (charts, custom components)."""
    return _palette(current_theme())


def inject_theme() -> None:
    """Inject the CSS for the active palette. Call at the top of every page."""
    st.markdown(_css(_palette(current_theme())), unsafe_allow_html=True)


def theme_toggle() -> None:
    """Sidebar Light/Dark toggle. Call once per run (from the entrypoint)."""
    current = current_theme()
    choice = st.sidebar.radio(
        "Theme", ("🌙 Dark", "☀️ Light"),
        index=0 if current == "dark" else 1,
        horizontal=True,
        label_visibility="collapsed",
    )
    new_theme = "dark" if choice.startswith("🌙") else "light"
    if new_theme != current:
        st.session_state[THEME_KEY] = new_theme
        st.rerun()


def app_header(icon: str, title: str, subtitle: str = "") -> None:
    """Consistent page hero. Use as the first content element of every page."""
    sub = f'<div class="db-hero-sub">{subtitle}</div>' if subtitle else ""
    st.markdown(
        f'<div class="db-hero"><span class="db-hero-icon">{icon}</span> '
        f'<span class="db-hero-title">{title}</span>{sub}</div>',
        unsafe_allow_html=True,
    )


def sidebar_project_badge(project_manager, current_project_name: str = None) -> None:
    """Project status chip pinned at the top of the sidebar on every page."""
    name = current_project_name or (project_manager.get_current_project_name() if project_manager else None)
    if name:
        st.sidebar.markdown(
            '<div class="db-project-badge">'
            '<div class="db-pb-label">Active project</div>'
            f'<div class="db-pb-name">📁 {name}</div>'
            "</div>",
            unsafe_allow_html=True,
        )
    else:
        st.sidebar.markdown(
            '<div class="db-project-badge">'
            '<div class="db-pb-label">No project</div>'
            '<div class="db-pb-none">Start in Projects →</div>'
            "</div>",
            unsafe_allow_html=True,
        )


def sidebar_brand() -> None:
    """Brand block at the top of the sidebar."""
    st.sidebar.markdown(
        '<div class="db-brand">'
        '<div class="db-brand-bug">🐛</div>'
        "<div><div class=\"db-brand-title\">DeepBug</div>"
        '<div class="db-brand-sub">Recon &amp; Bug Hunting</div></div>'
        "</div>",
        unsafe_allow_html=True,
    )
