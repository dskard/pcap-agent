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
