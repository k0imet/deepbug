# Bring Your Own AI — DeepBug AI Guide

DeepBug never bundles an AI vendor. Instead it speaks plain HTTP to **any
OpenAI-compatible `/chat/completions` endpoint** — no SDK required. Point it at
OpenAI, Groq, OpenRouter, a local Ollama, or LM Studio and the AI Assistant
page and result analysis work out of the box.

## How DeepBug calls AI

- **Transport**: plain `POST {api_base}/chat/completions` with a standard
  OpenAI chat payload (`model`, `messages`, `temperature`).
- **Streaming**: the AI Assistant streams deltas over SSE (`"stream": true`)
  and renders them live; the analysis path uses a single non-streaming call.
- **Auth**: `Authorization: Bearer <api_key>` header. No key → local models or
  heuristic fallback.

## Where AI is used

### (a) AI Assistant page (`5_AI.py`) — chat

- Base URL, model, key and temperature are **editable in the UI**; the fields
  prefill from config `ai.chat_base` / `ai.chat_model` / `ai.temperature`-adjacent
  defaults (falls back to `ai.api_base` / `ai.model`, then OpenAI defaults).
- **Pinned context**: paste scan results, JS code, etc. into the "Pinned
  context" box — it is attached to the system prompt of every message
  (capped at `ai.chat_max_chars`).
- History is trimmed to the last `ai.chat_max_history` messages, each message
  truncated to `ai.chat_max_chars` characters.
- The conversation is **persisted per project** in `.ai_chat.json` inside the
  project folder, so it survives page switches and restarts.
- `ai.chat_temperature` is the default; the UI slider overrides per session.

### (b) Result analysis — summary / triage / prioritize / suggest_next

The "Analyze saved results" section of the AI Assistant page runs
`AIAnalyzer` (app/modules/tools/ai_analyzer.py) over any saved result set:

- Uses `ai.enable` + `ai.api_key` + `ai.model` + `ai.api_base`; the UI values
  override config for that session.
- If the AI is unavailable (no key, call fails, timeout) it **falls back to
  deterministic local heuristics** — severity keyword matching, ranking, and
  canned next-step suggestions — so the feature always works, marked as
  "Local heuristic analysis".
- When the page's API key field is set (or a key is otherwise available), the
  `ai.enable` flag is overridden to true for the analysis call.

### (c) Environment fallback

`OPENAI_API_KEY` is used as a fallback for `ai.api_key` when the config key is
empty (`AIAnalyzer` reads `os.environ.get('OPENAI_API_KEY')`).

## Provider examples

Add an `"ai"` block to `app/modules/config.json` (see CONFIGURATION.md for the
full key table) — or just type the values into the AI Assistant page:

| Provider | Base URL | Example model | Notes |
|----------|----------|---------------|-------|
| **OpenAI** | `https://api.openai.com/v1` | `gpt-4o-mini` | Official endpoint; needs an API key |
| **Groq** | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` | Fast, free-tier available; key required |
| **OpenRouter** | `https://openrouter.ai/api/v1` | any model, incl. free ones (e.g. `moonshotai/kimi-k3-free`) | One key, many models |
| **Ollama (local)** | `http://localhost:11434/v1` | `llama3.1` | No key needed — leave empty |
| **LM Studio (local)** | `http://localhost:1234/v1` | any loaded model | No key needed — leave empty |

Config examples:

```json
{ "ai": {
    "enable": true,
    "api_base": "https://api.openai.com/v1", "api_key": "sk-...", "model": "gpt-4o-mini",
    "chat_base": "https://api.openai.com/v1", "chat_model": "gpt-4o-mini" } }
```

```json
{ "ai": {
    "enable": true,
    "api_base": "https://api.groq.com/openai/v1", "api_key": "gsk_...", "model": "llama-3.3-70b-versatile",
    "chat_base": "https://api.groq.com/openai/v1", "chat_model": "llama-3.3-70b-versatile" } }
```

```json
{ "ai": {
    "enable": true,
    "api_base": "https://openrouter.ai/api/v1", "api_key": "sk-or-...", "model": "moonshotai/kimi-k3-free",
    "chat_base": "https://openrouter.ai/api/v1", "chat_model": "moonshotai/kimi-k3-free" } }
```

```json
{ "ai": {
    "enable": true,
    "api_base": "http://localhost:11434/v1", "api_key": "",
    "model": "llama3.1", "chat_base": "http://localhost:11434/v1", "chat_model": "llama3.1" } }
```

```json
{ "ai": {
    "enable": true,
    "api_base": "http://localhost:1234/v1", "api_key": "",
    "model": "your-loaded-model", "chat_base": "http://localhost:1234/v1", "chat_model": "your-loaded-model" } }
```

For local models keep `api_key` **empty** (`""`) — the app then skips the
"no key" warning only if you enter nothing in the UI field too.

## Security notes

- **Keys are never persisted by the app.** They live in the Streamlit session /
  UI input only (a password field), or in your config/env if you choose to put
  them there. The chat history saved to `.ai_chat.json` contains messages, not
  keys.
- Prefer the `OPENAI_API_KEY` env var over hardcoding keys in `config.json`.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| **404 on `/chat/completions`** | The base URL must point at an OpenAI-compatible endpoint. Check it ends in `/v1` (e.g. `https://api.groq.com/openai/v1`, not `https://api.groq.com`). |
| **401 / auth errors** | Wrong or missing key. Set it in the UI, in `ai.api_key`, or export `OPENAI_API_KEY`. |
| **Timeouts / "Chat timed out"** | Endpoint unreachable or slow. Raise `ai.timeout` (default 60s for analysis, 120s chat cap), check firewall/proxy, confirm the local model server is running. |
| **"No API key configured" info** | Expected when key fields are empty — enter a key for hosted providers, or leave empty for local models. |
| **Analysis falls back to heuristics** | `AIAnalyzer` degrades gracefully; an enabled AI with a valid key routes to the LLM instead. |
