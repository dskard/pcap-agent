"""Tests for the CLI entry point."""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from constants import TOTAL_FRAMES, UDP_TOP_TALKER_IP

from pcap_agent.cli import main


@pytest.fixture()
def cli_runner():
    return CliRunner()


@pytest.fixture()
def mock_chat():
    chat = MagicMock()
    chat.console.return_value = None
    return chat


class TestCliSynopsis:
    """CLI prints a synopsis after loading a PCAP, new or cached."""

    def _invoke(self, cli_runner, mock_chat, pcap_path, db_dir):
        with patch("pcap_agent.agent.create_agent", return_value=mock_chat):
            return cli_runner.invoke(
                main,
                [
                    str(pcap_path),
                    "--api-key",
                    "test-key",
                    "--db-dir",
                    db_dir,
                    "--ui",
                    "console",
                ],
                catch_exceptions=False,
            )

    def test_new_file_synopsis_shows_packet_count(
        self, cli_runner, mock_chat, synthetic_pcap, tmp_path
    ):
        result = self._invoke(cli_runner, mock_chat, synthetic_pcap, str(tmp_path))
        assert result.exit_code == 0, result.output
        assert str(TOTAL_FRAMES) in result.output

    def test_new_file_synopsis_shows_protocol(
        self, cli_runner, mock_chat, synthetic_pcap, tmp_path
    ):
        result = self._invoke(cli_runner, mock_chat, synthetic_pcap, str(tmp_path))
        assert result.exit_code == 0, result.output
        assert "UDP" in result.output or "TCP" in result.output

    def test_new_file_synopsis_shows_top_talker(
        self, cli_runner, mock_chat, synthetic_pcap, tmp_path
    ):
        result = self._invoke(cli_runner, mock_chat, synthetic_pcap, str(tmp_path))
        assert result.exit_code == 0, result.output
        assert UDP_TOP_TALKER_IP in result.output

    def test_cached_file_synopsis_shows_packet_count(
        self, cli_runner, mock_chat, synthetic_pcap, tmp_path
    ):
        # First invocation — ingests the file
        self._invoke(cli_runner, mock_chat, synthetic_pcap, str(tmp_path))
        # Second invocation — cache hit; synopsis must still appear
        result = self._invoke(cli_runner, mock_chat, synthetic_pcap, str(tmp_path))
        assert result.exit_code == 0, result.output
        assert str(TOTAL_FRAMES) in result.output

    def test_cached_file_synopsis_shows_protocol(
        self, cli_runner, mock_chat, synthetic_pcap, tmp_path
    ):
        self._invoke(cli_runner, mock_chat, synthetic_pcap, str(tmp_path))
        result = self._invoke(cli_runner, mock_chat, synthetic_pcap, str(tmp_path))
        assert result.exit_code == 0, result.output
        assert "UDP" in result.output or "TCP" in result.output

    def test_cached_file_synopsis_shows_top_talker(
        self, cli_runner, mock_chat, synthetic_pcap, tmp_path
    ):
        self._invoke(cli_runner, mock_chat, synthetic_pcap, str(tmp_path))
        result = self._invoke(cli_runner, mock_chat, synthetic_pcap, str(tmp_path))
        assert result.exit_code == 0, result.output
        assert UDP_TOP_TALKER_IP in result.output
