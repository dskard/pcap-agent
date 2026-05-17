"""Tests for agent creation and system prompt construction."""

import pytest
from chatlas import ToolRejectError
from chatlas._content import ContentToolRequest

from pcap_agent.agent import create_agent


class TestCreateAgent:
    def test_system_prompt_contains_pcap_path_when_provided(self):
        chat = create_agent(
            api_key="test-key",
            model="claude-sonnet-4-6",
            pcap_file="/data/evidence01.pcap",
        )
        assert "/data/evidence01.pcap" in chat.system_prompt

    def test_system_prompt_no_file_context_when_not_provided(self):
        chat = create_agent(api_key="test-key", model="claude-sonnet-4-6")
        assert "already ingested" not in chat.system_prompt

    def test_system_prompt_includes_schema_when_provided(self):
        schema = "Database schema:\n  packets: frame_id BIGINT"
        chat = create_agent(
            api_key="test-key",
            model="claude-sonnet-4-6",
            pcap_file="/data/test.pcap",
            schema=schema,
        )
        assert schema in chat.system_prompt

    def test_system_prompt_no_schema_block_when_not_provided(self):
        chat = create_agent(
            api_key="test-key",
            model="claude-sonnet-4-6",
            pcap_file="/data/test.pcap",
        )
        assert "Database schema:" not in chat.system_prompt

    def test_system_prompt_contains_decode_payload_hint(self):
        chat = create_agent(api_key="test-key", model="claude-sonnet-4-6")
        assert (
            "When a payload is returned as hex-encoded bytes, call decode_payload"
            " to decompress or unpack it before presenting results to the user."
            in chat.system_prompt
        )

    def test_decode_payload_registered_as_tool(self):
        chat = create_agent(api_key="test-key", model="claude-sonnet-4-6")
        tool_names = [t.name for t in chat.get_tools()]
        assert "decode_payload" in tool_names


class TestOnToolRequestCallback:
    def test_raises_tool_reject_error_for_null_arguments(self):
        chat = create_agent(api_key="test-key", model="claude-sonnet-4-6")
        request = ContentToolRequest(id="req-1", name="query", arguments=None)
        with pytest.raises(ToolRejectError):
            chat._on_tool_request_callbacks.invoke(request)

    def test_raises_tool_reject_error_for_string_arguments(self):
        chat = create_agent(api_key="test-key", model="claude-sonnet-4-6")
        request = ContentToolRequest(id="req-2", name="query", arguments="bad input")
        with pytest.raises(ToolRejectError):
            chat._on_tool_request_callbacks.invoke(request)

    def test_does_not_raise_for_dict_arguments(self):
        chat = create_agent(api_key="test-key", model="claude-sonnet-4-6")
        request = ContentToolRequest(
            id="req-3", name="query", arguments={"sql": "SELECT 1"}
        )
        chat._on_tool_request_callbacks.invoke(request)
