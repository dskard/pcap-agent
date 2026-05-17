"""Tests for the CLI entry point."""

import logging
import os
from unittest.mock import MagicMock, patch

import anthropic
import duckdb
import httpx
import pytest
from click.testing import CliRunner
from constants import TOTAL_FRAMES, UDP_TOP_TALKER_IP

import pcap_agent.telemetry as telemetry
from pcap_agent.cli import main
from pcap_agent.tools import _state


@pytest.fixture()
def cli_runner():
    return CliRunner()


@pytest.fixture()
def mock_chat():
    chat = MagicMock()
    chat.console.return_value = None
    return chat


@pytest.fixture(autouse=True)
def _restore_state():
    """Save and restore _state around each test.

    CLI tests call ingest_pcap in-process, which closes the prior connection
    and points _state._conn at a tmp_path DB that is deleted after the test.
    Re-opening the saved path prevents state pollution for session fixtures.
    """
    saved_path = _state.get_db_path()
    yield
    current = _state.get_connection()
    if current is not None:
        try:
            current.close()
        except Exception:
            pass
    if saved_path is not None:
        _state.set_connection(duckdb.connect(saved_path), saved_path)
    else:
        _state.reset()


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


class TestCliLogFile:
    """CLI --log-file option routes logs to a file."""

    @pytest.fixture(autouse=True)
    def _reset_telemetry(self):
        telemetry._reset()
        root = logging.getLogger()
        orig_level = root.level
        orig_handlers = root.handlers[:]
        yield
        telemetry._reset()
        root.handlers[:] = orig_handlers
        root.setLevel(orig_level)

    def test_log_file_produces_nonempty_file(
        self, synthetic_pcap, tmp_path
    ):
        log_path = tmp_path / "agent.log"
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        mock_chat = MagicMock()
        mock_chat.console.return_value = None
        runner = CliRunner()
        with patch("pcap_agent.agent.create_agent", return_value=mock_chat):
            result = runner.invoke(
                main,
                [
                    str(synthetic_pcap),
                    "--api-key", "test-key",
                    "--db-dir", str(db_dir),
                    "--log-level", "DEBUG",
                    "--log-file", str(log_path),
                ],
                catch_exceptions=False,
            )
        assert result.exit_code == 0, result.output
        assert log_path.exists()
        assert log_path.stat().st_size > 0

    def test_bad_log_file_path_exits_with_error(self, tmp_path):
        bad_path = str(tmp_path / "no_such_dir" / "agent.log")
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--api-key", "test-key",
                "--log-file", bad_path,
            ],
        )
        assert result.exit_code != 0
        assert "Error" in result.output or "Error" in (result.output or "")


def _make_bad_request_error(
    msg: str = "messages.0.content.0.tool_use.input: Input should be an object",
) -> anthropic.BadRequestError:
    response = httpx.Response(
        400, request=httpx.Request("POST", "https://api.anthropic.com")
    )
    return anthropic.BadRequestError(msg, response=response, body=None)


class TestCliBadRequestRecovery:
    """CLI recovers from BadRequestError by popping the malformed turn."""

    @pytest.fixture(autouse=True)
    def _clean_env(self):
        saved = {k: os.environ.pop(k, None) for k in ("PCAP_AGENT_LOG_FILE",)}
        yield
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)

    def test_bad_request_error_pops_last_turn_and_continues(self, cli_runner):
        turns = [MagicMock(), MagicMock()]
        mock_chat = MagicMock()
        mock_chat.get_turns.return_value = turns
        mock_chat.console.side_effect = [_make_bad_request_error(), None]

        with patch("pcap_agent.agent.create_agent", return_value=mock_chat):
            result = cli_runner.invoke(
                main,
                ["--api-key", "test-key"],
                catch_exceptions=False,
            )

        assert result.exit_code == 0
        mock_chat.set_turns.assert_called_once_with(turns[:-1])
        assert "[error]" in result.output

    def test_bad_request_error_prints_recoverable_message(self, cli_runner):
        mock_chat = MagicMock()
        mock_chat.get_turns.return_value = [MagicMock()]
        mock_chat.console.side_effect = [_make_bad_request_error(), None]

        with patch("pcap_agent.agent.create_agent", return_value=mock_chat):
            result = cli_runner.invoke(
                main,
                ["--api-key", "test-key"],
                catch_exceptions=False,
            )

        assert "invalid tool call" in result.output.lower()
        assert "continue" in result.output.lower()


class TestCliForceReingest:
    """CLI --force-reingest flag sets the env var and updates the synopsis."""

    @pytest.fixture(autouse=True)
    def _clean_env(self):
        saved = {
            k: os.environ.pop(k, None)
            for k in ("PCAP_AGENT_FORCE_REINGEST", "PCAP_AGENT_LOG_FILE")
        }
        yield
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)

    def _invoke(self, cli_runner, mock_chat, pcap_path, db_dir, extra_args=None):
        args = [
            str(pcap_path),
            "--api-key", "test-key",
            "--db-dir", str(db_dir),
            "--ui", "console",
        ]
        if extra_args:
            args += extra_args
        with patch("pcap_agent.agent.create_agent", return_value=mock_chat):
            return cli_runner.invoke(main, args, catch_exceptions=False)

    def test_force_reingest_synopsis_shows_forced_label(
        self, cli_runner, mock_chat, synthetic_pcap, tmp_path
    ):
        self._invoke(cli_runner, mock_chat, synthetic_pcap, tmp_path)
        result = self._invoke(
            cli_runner, mock_chat, synthetic_pcap, tmp_path,
            extra_args=["--force-reingest"],
        )
        assert result.exit_code == 0, result.output
        assert "(forced re-ingest)" in result.output

    def test_no_force_reingest_flag_does_not_set_env_var(
        self, cli_runner, mock_chat, synthetic_pcap, tmp_path
    ):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PCAP_AGENT_FORCE_REINGEST", None)
            self._invoke(cli_runner, mock_chat, synthetic_pcap, tmp_path)
            assert os.environ.get("PCAP_AGENT_FORCE_REINGEST") is None
