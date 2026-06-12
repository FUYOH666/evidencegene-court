"""Minimal OpenAI-compatible chat client (LM Studio, llama.cpp, vLLM, cloud gateways).

JSON-schema constrained output where supported; falls back to JSON extraction.
Token usage is captured for the audit log (a judging deliverable).
"""

import json
import logging
import re
from typing import Any

import httpx

from evidencegene.config import settings

logger = logging.getLogger(__name__)


class LLMError(Exception):
    pass


class ChatClient:
    def __init__(self) -> None:
        self._client = httpx.Client(
            base_url=settings.llm_base_url,
            timeout=settings.llm_timeout,
            headers={"Authorization": f"Bearer {settings.llm_api_key}"},
        )

    def health(self) -> bool:
        try:
            r = self._client.get("/models")
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    def complete_json(
        self,
        system: str,
        user: str,
        schema: dict[str, Any],
        schema_name: str = "response",
    ) -> tuple[dict[str, Any], dict[str, int]]:
        """Returns (parsed_json, token_usage)."""
        body: dict[str, Any] = {
            "model": settings.llm_model,
            "temperature": settings.llm_temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "schema": schema, "strict": True},
            },
        }
        try:
            r = self._client.post("/chat/completions", json=body)
            if r.status_code == 400:
                logger.warning("LLM 400 with json_schema: %s", r.text[:400])
                # endpoint may not support json_schema — retry without constraint
                body.pop("response_format", None)
                r = self._client.post("/chat/completions", json=body)
            if r.status_code >= 400:
                raise LLMError(f"LLM {r.status_code}: {r.text[:400]}")
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMError(f"LLM request failed: {exc}") from exc

        data = r.json()
        message = data["choices"][0]["message"]
        content = message.get("content") or ""
        if not content.strip():
            # some reasoning models emit the answer in reasoning_content
            content = message.get("reasoning_content") or ""
        usage = data.get("usage", {})
        token_usage = {
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
        }
        return self._extract_json(content), token_usage

    @staticmethod
    def _extract_json(content: str) -> dict[str, Any]:
        # strip thinking blocks emitted by reasoning models
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", content, flags=re.DOTALL)
            if not match:
                raise LLMError(f"model returned non-JSON content: {content[:300]}") from None
            return json.loads(match.group(0))
