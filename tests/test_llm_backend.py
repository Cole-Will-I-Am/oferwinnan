"""Tests for llm_backend.py — LLM provider abstraction."""

import json
import unittest
from unittest.mock import patch, MagicMock

from matrix.llm_backend import (
    LLMBackend,
    LLMError,
    LLMResponse,
    LLMToolCall,
    OllamaBackend,
    AnthropicBackend,
    ToolDefinition,
    create_backend,
)


# ── OllamaBackend Parsing ───────────────────────────────────────────────────


class TestOllamaBackendParsing(unittest.TestCase):
    """Test Ollama response parsing without network calls."""

    def test_parse_tool_calls(self):
        data = {
            "model": "llama3.1:8b",
            "message": {
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "set_routing_weights",
                            "arguments": {"weights": {"tcp": 0.8}},
                        }
                    },
                    {
                        "function": {
                            "name": "trigger_discovery",
                            "arguments": {"timeout": 5},
                        }
                    },
                ],
            },
        }
        resp = OllamaBackend._parse(data)
        self.assertEqual(len(resp.tool_calls), 2)
        self.assertEqual(resp.tool_calls[0].tool_name, "set_routing_weights")
        self.assertEqual(resp.tool_calls[0].arguments, {"weights": {"tcp": 0.8}})
        self.assertEqual(resp.tool_calls[1].tool_name, "trigger_discovery")
        self.assertEqual(resp.model, "llama3.1:8b")

    def test_parse_no_tool_calls(self):
        data = {
            "model": "llama3.1:8b",
            "message": {"content": "No action needed.", "tool_calls": []},
        }
        resp = OllamaBackend._parse(data)
        self.assertEqual(len(resp.tool_calls), 0)
        self.assertEqual(resp.raw_text, "No action needed.")

    def test_parse_empty_message(self):
        data = {"model": "test", "message": {}}
        resp = OllamaBackend._parse(data)
        self.assertEqual(len(resp.tool_calls), 0)
        self.assertEqual(resp.raw_text, "")

    def test_parse_missing_function_fields(self):
        data = {
            "model": "test",
            "message": {"tool_calls": [{"function": {}}]},
        }
        resp = OllamaBackend._parse(data)
        self.assertEqual(len(resp.tool_calls), 1)
        self.assertEqual(resp.tool_calls[0].tool_name, "")
        self.assertEqual(resp.tool_calls[0].arguments, {})


# ── AnthropicBackend Parsing ─────────────────────────────────────────────────


class TestAnthropicBackendParsing(unittest.TestCase):
    """Test Anthropic response parsing without network calls."""

    def test_parse_tool_use(self):
        data = {
            "model": "claude-sonnet-4-20250514",
            "content": [
                {"type": "text", "text": "Adjusting weights."},
                {
                    "type": "tool_use",
                    "id": "toolu_123",
                    "name": "set_routing_weights",
                    "input": {"weights": {"ws": 0.5}},
                },
            ],
            "usage": {"input_tokens": 100, "output_tokens": 50},
        }
        resp = AnthropicBackend._parse(data)
        self.assertEqual(len(resp.tool_calls), 1)
        self.assertEqual(resp.tool_calls[0].tool_name, "set_routing_weights")
        self.assertEqual(resp.tool_calls[0].call_id, "toolu_123")
        self.assertEqual(resp.tool_calls[0].arguments, {"weights": {"ws": 0.5}})
        self.assertIn("Adjusting weights", resp.raw_text)
        self.assertEqual(resp.usage_tokens, 150)
        self.assertEqual(resp.model, "claude-sonnet-4-20250514")

    def test_parse_no_tool_use(self):
        data = {
            "model": "test",
            "content": [{"type": "text", "text": "Nothing to do."}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
        resp = AnthropicBackend._parse(data)
        self.assertEqual(len(resp.tool_calls), 0)
        self.assertEqual(resp.raw_text, "Nothing to do.")

    def test_parse_multiple_tool_calls(self):
        data = {
            "model": "test",
            "content": [
                {
                    "type": "tool_use",
                    "id": "a",
                    "name": "trigger_discovery",
                    "input": {},
                },
                {
                    "type": "tool_use",
                    "id": "b",
                    "name": "adjust_rate_limit",
                    "input": {"bytes_per_second": 4096},
                },
            ],
        }
        resp = AnthropicBackend._parse(data)
        self.assertEqual(len(resp.tool_calls), 2)
        self.assertEqual(resp.tool_calls[0].tool_name, "trigger_discovery")
        self.assertEqual(resp.tool_calls[1].tool_name, "adjust_rate_limit")

    def test_parse_empty_content(self):
        data = {"model": "test", "content": []}
        resp = AnthropicBackend._parse(data)
        self.assertEqual(len(resp.tool_calls), 0)


# ── Data Structures ──────────────────────────────────────────────────────────


class TestDataStructures(unittest.TestCase):
    def test_tool_call_defaults(self):
        tc = LLMToolCall(tool_name="foo", arguments={"a": 1})
        self.assertEqual(tc.call_id, "")

    def test_response_defaults(self):
        resp = LLMResponse()
        self.assertEqual(resp.tool_calls, [])
        self.assertEqual(resp.raw_text, "")
        self.assertEqual(resp.usage_tokens, 0)

    def test_tool_definition(self):
        td = ToolDefinition(
            name="test",
            description="A test tool",
            parameters={"type": "object"},
        )
        self.assertEqual(td.name, "test")


# ── Factory ──────────────────────────────────────────────────────────────────


class TestCreateBackend(unittest.TestCase):
    def test_default_ollama(self):
        cfg = MagicMock()
        cfg.llm_backend = "ollama"
        cfg.llm_endpoint = "http://localhost:11434"
        cfg.llm_model = "llama3.1:8b"
        backend = create_backend(cfg)
        self.assertIsInstance(backend, OllamaBackend)

    def test_anthropic_with_key(self):
        cfg = MagicMock()
        cfg.llm_backend = "anthropic"
        cfg.llm_api_key = "sk-test"
        cfg.llm_model = "claude-sonnet-4-20250514"
        backend = create_backend(cfg)
        self.assertIsInstance(backend, AnthropicBackend)

    def test_anthropic_without_key(self):
        cfg = MagicMock()
        cfg.llm_backend = "anthropic"
        cfg.llm_api_key = None
        cfg.llm_model = "some-model"
        with self.assertRaises(LLMError):
            create_backend(cfg)

    def test_missing_model(self):
        cfg = MagicMock()
        cfg.llm_backend = "ollama"
        cfg.llm_model = ""
        with self.assertRaises(LLMError):
            create_backend(cfg)


# ── Network Error Handling ───────────────────────────────────────────────────


class TestOllamaNetworkErrors(unittest.TestCase):
    def test_connection_refused(self):
        backend = OllamaBackend("http://127.0.0.1:1", "test")
        with self.assertRaises(LLMError):
            backend.invoke("sys", "msg", [], timeout=2.0)


class TestAnthropicNetworkErrors(unittest.TestCase):
    def test_bad_api_key(self):
        backend = AnthropicBackend("invalid-key", "test")
        with self.assertRaises(LLMError):
            backend.invoke("sys", "msg", [], timeout=5.0)


if __name__ == "__main__":
    unittest.main()
