# pages/5_AI.py
# AI Assistant: bring your own AI (any OpenAI-compatible chat completions endpoint).
# Two modes: 1) streaming chat with optional pinned context, 2) analyze saved scan
# results (summary / triage / prioritize / suggest_next) with heuristic fallback.

import sys
import json
from datetime import datetime
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from app.modules.utils import load_config
from app.modules.project_manager import ProjectManager
from app.modules.tools.ai_analyzer import AIAnalyzer, chat_messages, stream_chat_completion
from app.utils.theme import inject_theme, app_header

CONFIG = load_config()
AI_DEFAULTS = CONFIG.get('ai', {})

inject_theme()
app_header("🤖", "AI Assistant",
           "Bring your own AI — point DeepBug at any OpenAI-compatible endpoint "
           "(OpenAI, Groq, OpenRouter, Ollama, LM Studio, ...) for chat and result analysis.")

if 'project_manager_instance' not in st.session_state:
    st.session_state.project_manager_instance = ProjectManager(CONFIG)
project_manager = st.session_state.project_manager_instance


# ---------------------------------------------------------------------
# Connection settings (persist per session; prefill from config/env)
# ---------------------------------------------------------------------
st.subheader("🔌 Connection")

_default_base = AI_DEFAULTS.get('chat_base') or AI_DEFAULTS.get('api_base') or "https://api.openai.com/v1"
_default_model = AI_DEFAULTS.get('chat_model') or AI_DEFAULTS.get('model') or "gpt-4o-mini"
_default_key = AI_DEFAULTS.get('api_key') or ""

with st.expander("AI endpoint & model (OpenAI-compatible)", expanded=True):
    c1, c2 = st.columns([3, 2])
    with c1:
        api_base = st.text_input(
            "API Base URL", value=_default_base,
            placeholder="https://api.openai.com/v1",
            help="Any server implementing POST /chat/completions. "
                 "e.g. https://api.openai.com/v1, https://api.groq.com/openai/v1, "
                 "https://openrouter.ai/api/v1, http://localhost:11434/v1 (Ollama).")
    with c2:
        model = st.text_input("Model", value=_default_model,
                              placeholder="gpt-4o-mini, llama3.3, ...")
    c3, c4 = st.columns([3, 2])
    with c3:
        api_key = st.text_input(
            "API Key", value=_default_key, type="password",
            help="Leave empty to use the OPENAI_API_KEY environment variable "
                 "or ai.api_key in config.json. Not stored to disk.")
    with c4:
        temperature = st.slider("Temperature", 0.0, 1.5, 0.3, 0.05)

    available = bool(api_key or _default_key)
    if not available:
        st.info(
            "No API key configured — chat will show guidance instead of calling "
            "the model. Set one above, or configure `ai.api_key` in "
            "`app/modules/config.json` / the `OPENAI_API_KEY` env var. "
            "See the README → **Bring your own AI** for examples.")
    else:
        st.caption(f"Endpoint: `{api_base}/chat/completions` · Model: `{model}`")

# ---------------------------------------------------------------------
# Chat history (persisted per project so it survives page switches)
# ---------------------------------------------------------------------
current_project = project_manager.get_current_project_name()
_chat_file = None
if current_project:
    _chat_file = Path(project_manager.get_current_project_path()) / ".ai_chat.json"


def _load_chat() -> list:
    if _chat_file and _chat_file.exists():
        try:
            data = json.loads(_chat_file.read_text())
            if isinstance(data, list):
                return data
        except Exception:
            pass
    return []


def _save_chat(msgs: list):
    if _chat_file:
        try:
            _chat_file.write_text(json.dumps(msgs, indent=1))
        except Exception:
            pass


if 'ai_chat_messages' not in st.session_state:
    st.session_state.ai_chat_messages = _load_chat()

# If the project changed, reload the chat from disk
if _chat_file and st.session_state.get('ai_chat_project') != current_project:
    st.session_state.ai_chat_messages = _load_chat()
st.session_state.ai_chat_project = current_project


# ---------------------------------------------------------------------
# Chat UI
# ---------------------------------------------------------------------
st.subheader("💬 Chat")

if current_project:
    pinned_context = st.text_area(
        "Pinned context (attached to every message — paste scan results, JS code, ...)",
        height=90, key="ai_pinned_context",
        placeholder="Optional: paste findings, endpoints, JS snippets...")
else:
    pinned_context = ""

top_c1, top_c2 = st.columns([1, 4])
with top_c1:
    if st.button("🧹 Clear conversation", key="ai_chat_clear"):
        st.session_state.ai_chat_messages = []
        _save_chat([])
        st.rerun()
with top_c2:
    st.caption(f"{len(st.session_state.ai_chat_messages)} message(s) in the conversation")

for m in st.session_state.ai_chat_messages[-40:]:
    with st.chat_message(m['role']):
        st.markdown(m['content'])

if not available:
    st.warning(
        "Add an API key above to start chatting. DeepBug never stores your key — "
        "it's held in the session only. Local models (Ollama / LM Studio) work "
        "with `http://localhost:<port>/v1` and any model name.")
else:
    prompt = st.chat_input("Ask about your findings, endpoints or methodology...")

    if prompt:
        st.session_state.ai_chat_messages.append({'role': 'user', 'content': prompt})
        with st.chat_message('user'):
            st.markdown(prompt)
        try:
            messages = chat_messages(
                CONFIG, st.session_state.ai_chat_messages, pinned_context=pinned_context,
                max_history=int(AI_DEFAULTS.get('chat_max_history', 20)),
                max_chars=int(AI_DEFAULTS.get('chat_max_chars', 6000)))
            with st.chat_message('assistant'):
                reply = st.write_stream(stream_chat_completion(
                    messages, api_base, api_key, model,
                    temperature=temperature,
                    timeout=int(AI_DEFAULTS.get('timeout', 120))))
        except Exception as chat_err:
            reply = f"⚠️ Chat error: {type(chat_err).__name__}: {chat_err}"
            st.error(reply)
        if reply:
            st.session_state.ai_chat_messages.append({'role': 'assistant', 'content': reply})
            _save_chat(st.session_state.ai_chat_messages)

# ---------------------------------------------------------------------
# Analyze saved scan results
# ---------------------------------------------------------------------
st.subheader("📊 Analyze saved results")

all_results = project_manager.get_all_results_for_current_project() if current_project else {}
flat_sections = []
for scan_type, targets_data in all_results.items():
    for target, data in targets_data.items():
        flat_sections.append((f"{scan_type} · {target}", scan_type, target, data))

if not flat_sections:
    st.info("No saved scan results for the active project yet. Run scans in Reconnaissance first — "
            "analysis can also run without a project if you select 'manual' below." if not current_project
            else "No saved scan results for the active project yet. Run scans in Reconnaissance first.")
else:
    a1, a2 = st.columns([2, 1])
    with a1:
        selection = st.selectbox("Result set:", [s[0] for s in flat_sections])
    with a2:
        mode = st.selectbox("Mode:", ["summary", "triage", "prioritize", "suggest_next",
                                      "verify", "exploit_chain"],
                            format_func=lambda m: m.replace('_', ' ').title())

    _sel = next((s for s in flat_sections if s[0] == selection), None)
    if _sel:
        _, scan_type, target, data = _sel
        record_count = len(data) if hasattr(data, '__len__') else 0
        st.caption(f"`{scan_type}` for `{target}` · {record_count} records")

    if st.button("🔬 Run analysis", key="ai_analyze_btn", width='stretch'):
        with st.spinner("Analyzing..."):
            merged = dict(CONFIG)
            merged['ai'] = {**AI_DEFAULTS,
                            'enable': True if available else AI_DEFAULTS.get('enable', False),
                            'api_base': api_base, 'api_key': api_key,
                            'model': model, 'timeout': int(AI_DEFAULTS.get('timeout', 60))}
            analyzer = AIAnalyzer(merged)
            try:
                payload = {scan_type: data} if not hasattr(data, 'to_dict') else {scan_type: data.to_dict(orient='records')}
                result = analyzer.scan_sync(payload, mode=mode, target=target)
            except Exception as e:
                result = {'mode': mode, 'source': 'error', 'text': f"Analysis error: {type(e).__name__}: {e}"}

        with st.expander("Analysis output", expanded=True):
            if result.get('source') == 'ai':
                st.success(f"AI analysis ({mode}) · {api_base}")
            elif result.get('source') == 'error':
                st.error(result['text'])
            else:
                st.caption("Local heuristic analysis — connect an AI endpoint above for LLM-powered output.")
            st.markdown(result.get('text') or "No output.")
        if result.get('text'):
            st.session_state['ai_last_result'] = {
                'text': result['text'], 'name': f"{scan_type}_{target}_{mode}_{datetime.now():%Y%m%d_%H%M}.md"}
    if st.session_state.get('ai_last_result'):
        st.download_button(
            "📥 Download analysis", st.session_state['ai_last_result']['text'],
            st.session_state['ai_last_result']['name'],
            "text/markdown", key="dl_ai_result")

st.markdown("---")
st.caption("DeepBug uses plain HTTP to OpenAI-compatible `/chat/completions` endpoints — "
           "no vendor SDK required. Keys are never persisted by the app.")
