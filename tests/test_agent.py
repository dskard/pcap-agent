"""Tests for agent creation and system prompt construction."""

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
