"""Runtime configuration. All knobs via environment (prefix EGC_) or .env."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="EGC_", env_file=".env", extra="ignore")

    # LLM (OpenAI-compatible; LM Studio default, judges may point to Anthropic/OpenAI gateways)
    llm_base_url: str = "http://localhost:1234/v1"
    llm_model: str = "qwen3.6-35b-a3b-uncensored-hauhaucs-aggressive-text-oq4"
    llm_api_key: str = "not-needed-for-local"
    llm_timeout: float = 300.0
    llm_temperature: float = 0.2

    # Case workspace (outputs only; evidence itself is read-only input)
    work_dir: Path = Path("reports/runs")
    artifact_db: Path = Path("reports/runs/artifacts.sqlite3")
    audit_log: Path = Path("reports/runs/audit_chain.jsonl")
    findings_log: Path = Path("reports/runs/findings.jsonl")

    # Forensic tool binaries (overridden on SIFT via env / tool_paths)
    vol_cmd: str = "vol"
    mmls_cmd: str = "mmls"
    fls_cmd: str = "fls"
    tool_timeout: float = 900.0

    # Court loop
    max_iterations: int = 6

    # Artifact responses: rows above this count are summarized, full data stays in store
    preview_rows: int = 12


settings = Settings()
