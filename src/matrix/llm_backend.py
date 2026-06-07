"""
matrix.llm_backend — Unified LLM interface for Ollama (local) and Anthropic (remote).

Single-turn, tool-use-only interactions.  No multi-turn chat.  No streaming.
The LLM receives a system prompt, a single user message (the Semantic Delta),
and a list of tool definitions.  It returns zero or more tool_use blocks.

Zero external dependencies — uses urllib.request only.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "LLMBackend",
    "OllamaBackend",
    "AnthropicBackend",
    "LLMResponse",
    "LLMToolCall",
    "LLMError",
    "ToolDefinition",
    "create_backend",
]


# ── Exceptions ───────────────────────────────────────────────────────────────


class LLMError(Exception):
    """Raised when LLM communication fails."""


# ── Data Structures ──────────────────────────────────────────────────────────


@dataclass(slots=True)
class LLMToolCall:
    """A single tool invocation requested by the LLM."""
    tool_name: str
    arguments: Dict[str, Any]
    call_id: str = ""


@dataclass(slots=True)
class LLMResponse:
    """Parsed LLM response: a list of tool calls plus metadata."""
    tool_calls: List[LLMToolCall] = field(default_factory=list)
    raw_text: str = ""
    model: str = ""
    usage_tokens: int = 0


@dataclass(slots=True)
class ToolDefinition:
    """Schema for a tool the LLM can invoke."""
    name: str
    description: str
    parameters: Dict[str, Any]  # JSON Schema object


# ── Abstract Base ────────────────────────────────────────────────────────────


class LLMBackend:
    """Abstract base for LLM providers."""

    def invoke(
        self,
        system_prompt: str,
        user_message: str,
        tools: List[ToolDefinition],
        timeout: float = 30.0,
    ) -> LLMResponse:
        raise NotImplementedError


# ── Ollama Backend ───────────────────────────────────────────────────────────


class OllamaBackend(LLMBackend):
    """Local LLM via Ollama REST API (POST /api/chat)."""

    def __init__(self, endpoint: str, model: str):
        self._endpoint = endpoint.rstrip("/")
        self._model = model

    def invoke(
        self,
        system_prompt: str,
        user_message: str,
        tools: List[ToolDefinition],
        timeout: float = 30.0,
    ) -> LLMResponse:
        ollama_tools = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in tools
        ]
        body = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "tools": ollama_tools,
            "stream": False,
        }
        url = f"{self._endpoint}/api/chat"
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise LLMError(f"Ollama request failed: {exc}") from exc

        return self._parse(data)

    @staticmethod
    def _parse(data: dict) -> LLMResponse:
        message = data.get("message", {})
        tool_calls: List[LLMToolCall] = []
        for tc in message.get("tool_calls", []):
            func = tc.get("function", {})
            tool_calls.append(LLMToolCall(
                tool_name=func.get("name", ""),
                arguments=func.get("arguments", {}),
            ))
        return LLMResponse(
            tool_calls=tool_calls,
            raw_text=message.get("content", ""),
            model=data.get("model", ""),
        )


# ── Anthropic Backend ────────────────────────────────────────────────────────


class AnthropicBackend(LLMBackend):
    """Remote LLM via Anthropic Messages API (POST /v1/messages)."""

    API_URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: str, model: str):
        self._api_key = api_key
        self._model = model

    def invoke(
        self,
        system_prompt: str,
        user_message: str,
        tools: List[ToolDefinition],
        timeout: float = 30.0,
    ) -> LLMResponse:
        anthropic_tools = [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.parameters,
            }
            for t in tools
        ]
        body = {
            "model": self._model,
            "max_tokens": 1024,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}],
            "tools": anthropic_tools,
        }
        req = urllib.request.Request(
            self.API_URL,
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise LLMError(f"Anthropic request failed: {exc}") from exc

        return self._parse(data)

    @staticmethod
    def _parse(data: dict) -> LLMResponse:
        tool_calls: List[LLMToolCall] = []
        raw_text = ""
        for block in data.get("content", []):
            if block.get("type") == "tool_use":
                tool_calls.append(LLMToolCall(
                    tool_name=block["name"],
                    arguments=block.get("input", {}),
                    call_id=block.get("id", ""),
                ))
            elif block.get("type") == "text":
                raw_text += block.get("text", "")
        usage = data.get("usage", {})
        return LLMResponse(
            tool_calls=tool_calls,
            raw_text=raw_text,
            model=data.get("model", ""),
            usage_tokens=usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
        )


# ── Factory ──────────────────────────────────────────────────────────────────


def create_backend(cfg=None) -> LLMBackend:
    """Create an LLM backend from configuration."""
    if cfg is None:
        from matrix.config import config as cfg
    if not cfg.llm_model:
        raise LLMError("MATRIX_LLM_MODEL must be set")
    if cfg.llm_backend == "anthropic":
        if not cfg.llm_api_key:
            raise LLMError("MATRIX_LLM_API_KEY required for Anthropic backend")
        return AnthropicBackend(cfg.llm_api_key, cfg.llm_model)
    return OllamaBackend(cfg.llm_endpoint, cfg.llm_model)
