# Try it out

Two supported environments: the **SANS SIFT Workstation** (what judges run) and
a **macOS / Linux dev box** (what we built on). The code is identical; only
tool paths and the LLM endpoint differ, both set via environment variables.

## A. On the SIFT Workstation (recommended for judges)

SIFT already ships Volatility 3 and Sleuth Kit, so there is nothing forensic to
install.

```bash
# 1. Get the code
git clone https://github.com/FUYOH666/evidencegene-court.git
cd evidencegene-court

# 2. Install uv (if not present) and sync
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync --extra dev --extra forensics

# 3. Point at an LLM endpoint
cp .env.example .env
# edit .env:
#   - local:  EGC_LLM_BASE_URL=http://<your-lm-studio-host>:1234/v1
#   - cloud:  EGC_LLM_BASE_URL=<openai-compatible-gateway>  + EGC_LLM_API_KEY=...

# 4. Health check
uv run egc-court health

# 5. Fetch the demo case (or point at your own images)
bash scripts/fetch_case001.sh DC01-memory.zip DC01-E01.zip
cd cases/case001 && unzip -o DC01-memory.zip && cd -

# 6. Run the court
uv run egc-court investigate \
  --memory cases/case001/citadeldc01.mem --source memory:dc01

# 7. Verify the audit chain is untampered
uv run egc-court verify
```

Outputs land in `reports/runs/`:
- `artifacts.sqlite3` — every tool execution, full output, content hash
- `audit_chain.jsonl` — SHA-256-chained log of tools, agent messages, verdicts
- `findings.jsonl` — published findings with tiers and source-backed refs

## B. As an MCP server (Claude Code / OpenClaw / Cursor)

```bash
uv run egc-mcp     # stdio transport
```

Register `sift-gene-mcp` in your MCP client. The client's agent then drives the
same 11 read-only tools directly; the FindingSerializer is exposed through the
court orchestrator rather than the raw MCP surface.

## macOS (Apple Silicon) dev setup

```bash
brew install sleuthkit libewf yara
uv sync --extra dev --extra forensics    # volatility3 is pure Python, installs natively
# LLM via LM Studio (load a model, start the server on :1234)
```

## Troubleshooting

- **`tool vol: MISSING`** — Volatility 3 is installed in the uv venv; run via
  `uv run` so the `vol` console script is on PATH.
- **`LLM endpoint UNREACHABLE`** — start LM Studio's server, or set
  `EGC_LLM_BASE_URL` to a reachable OpenAI-compatible endpoint.
- **DFIR Madness download returns a tiny HTML file** — the site is behind
  ModSecurity; `scripts/fetch_case001.sh` sends the required browser headers.
