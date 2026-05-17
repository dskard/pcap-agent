"""Integration tests for tools.ingest.ingest_pcap."""

import duckdb
import pytest
from constants import (
    ICMP_PACKET_COUNT,
    TCP_TOTAL,
    TOTAL_IP,
    UDP_TOTAL,
)
from scapy.all import (  # type: ignore[import-untyped]
    IP,
    TCP,
    Dot11,
    RadioTap,
    wrpcap,
)

from pcap_agent.tools import _state
from pcap_agent.tools.ingest import ingest_pcap

_RT_FRAMES_DATA = [
    {"signal_dbm": -65, "freq": 2437, "rate_raw": 108, "channel": 6, "rate_mbps": 54.0},
    {"signal_dbm": -72, "freq": 5180, "rate_raw": 24, "channel": 36, "rate_mbps": 12.0},
    {"signal_dbm": -80, "freq": 2462, "rate_raw": 4, "channel": 11, "rate_mbps": 2.0},
]


@pytest.fixture
def _restore_state():
    """Restore _state after a test that temporarily changes the connection.

    ingest_pcap closes the previous connection when switching databases, so we
    cannot restore the saved connection object — it will already be closed.
    Instead we re-open the saved db_path after the test.
    """
    saved_path = _state.get_db_path()
    yield
    new_conn = _state.get_connection()
    if new_conn is not None:
        new_conn.close()
    if saved_path is not None:
        restored = duckdb.connect(saved_path)
        _state.set_connection(restored, saved_path)
    else:
        _state.reset()


class TestIngestPcap:
    def test_packets_table_populated(self, ingested_conn):
        count = ingested_conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        assert count == TOTAL_IP

    def test_tcp_segments_table_populated(self, ingested_conn):
        count = ingested_conn.execute("SELECT COUNT(*) FROM tcp_segments").fetchone()[0]
        assert count == TCP_TOTAL

    def test_udp_datagrams_table_populated(self, ingested_conn):
        count = ingested_conn.execute(
            "SELECT COUNT(*) FROM udp_datagrams"
        ).fetchone()[0]
        assert count == UDP_TOTAL

    def test_icmp_messages_table_populated(self, ingested_conn):
        count = ingested_conn.execute(
            "SELECT COUNT(*) FROM icmp_messages"
        ).fetchone()[0]
        assert count == ICMP_PACKET_COUNT

    def test_summary_n_packets(self, ingested_db):
        assert ingested_db["n_packets"] == TOTAL_IP

    def test_summary_has_protocol_counts(self, ingested_db):
        assert isinstance(ingested_db["protocol_counts"], list)
        assert len(ingested_db["protocol_counts"]) > 0

    def test_summary_has_top_talkers(self, ingested_db):
        assert isinstance(ingested_db["top_talkers"], list)
        assert len(ingested_db["top_talkers"]) > 0

    def test_summary_has_time_bounds(self, ingested_db):
        assert ingested_db["time_start"] is not None
        assert ingested_db["time_end"] is not None
        assert ingested_db["time_end"] >= ingested_db["time_start"]

    def test_first_ingest_not_cached(self, ingested_db):
        assert ingested_db["cached"] is False

    def test_capture_info_populated(self, ingested_conn, ingested_db):
        row = ingested_conn.execute(
            "SELECT link_type, has_radiotap FROM capture_info WHERE sha256 = ?",
            [ingested_db["sha256"]],
        ).fetchone()
        assert row is not None
        assert isinstance(row[0], int)
        assert row[1] is False

    def test_radiotap_frames_empty_for_non_radiotap_pcap(self, ingested_conn):
        count = ingested_conn.execute(
            "SELECT COUNT(*) FROM radiotap_frames"
        ).fetchone()[0]
        assert count == 0

    def test_summary_has_schema_key(self, ingested_db):
        assert "schema" in ingested_db
        assert isinstance(ingested_db["schema"], str)
        assert len(ingested_db["schema"]) > 0


class TestIngestCaching:
    def test_second_ingest_returns_cached(
        self, synthetic_pcap, tmp_path, _restore_state
    ):
        db_dir = str(tmp_path)
        result1 = ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        result2 = ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        assert result1["cached"] is False
        assert result2["cached"] is True

    def test_cached_result_has_correct_packet_count(
        self, synthetic_pcap, tmp_path, _restore_state
    ):
        db_dir = str(tmp_path)
        ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        result2 = ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        assert result2["n_packets"] == TOTAL_IP

    def test_cached_result_has_protocol_counts(
        self, synthetic_pcap, tmp_path, _restore_state
    ):
        db_dir = str(tmp_path)
        ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        result2 = ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        assert isinstance(result2["protocol_counts"], list)
        assert len(result2["protocol_counts"]) > 0

    def test_cached_result_has_top_talkers(
        self, synthetic_pcap, tmp_path, _restore_state
    ):
        db_dir = str(tmp_path)
        ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        result2 = ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        assert isinstance(result2["top_talkers"], list)
        assert len(result2["top_talkers"]) > 0

    def test_cached_result_has_schema_key(
        self, synthetic_pcap, tmp_path, _restore_state
    ):
        db_dir = str(tmp_path)
        ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        result2 = ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        assert "schema" in result2
        assert isinstance(result2["schema"], str)
        assert len(result2["schema"]) > 0

    @pytest.mark.parametrize(
        "missing_table",
        ["ethernet_frames", "arp_packets", "capture_info"],
    )
    def test_stale_cache_triggers_reingest(
        self, synthetic_pcap, tmp_path, _restore_state, missing_table
    ):
        db_dir = str(tmp_path)
        result1 = ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        db_path = result1["db_path"]

        # Simulate an upgrade: release the connection, drop a new table via a
        # separate handle (as if the DB was created by an older pcap-agent that
        # lacked these tables), then let ingest_pcap re-open it.
        _state.get_connection().close()
        _state.reset()
        stale_conn = duckdb.connect(db_path)
        stale_conn.execute(f'DROP TABLE "{missing_table}"')
        stale_conn.close()

        result2 = ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        assert result2["cached"] is False
        assert result2["n_packets"] == TOTAL_IP


class TestIngestForceReingest:
    def test_force_reingest_bypasses_cache(
        self, synthetic_pcap, tmp_path, _restore_state
    ):
        db_dir = str(tmp_path)
        ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        import os

        os.environ["PCAP_AGENT_FORCE_REINGEST"] = "true"
        try:
            result = ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        finally:
            os.environ.pop("PCAP_AGENT_FORCE_REINGEST", None)
        assert result["cached"] is False
        assert result["forced"] is True
        assert result["n_packets"] == TOTAL_IP

    @pytest.mark.parametrize("env_val", ["true", "True", "TRUE", "1"])
    def test_force_reingest_env_values(
        self, synthetic_pcap, tmp_path, _restore_state, env_val
    ):
        import os

        db_dir = str(tmp_path)
        ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        os.environ["PCAP_AGENT_FORCE_REINGEST"] = env_val
        try:
            result = ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        finally:
            os.environ.pop("PCAP_AGENT_FORCE_REINGEST", None)
        assert result["forced"] is True

    def test_no_force_reingest_returns_cached(
        self, synthetic_pcap, tmp_path, _restore_state
    ):
        db_dir = str(tmp_path)
        ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        result = ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        assert result["cached"] is True
        assert result["forced"] is False

    def test_fresh_ingest_forced_false(self, synthetic_pcap, tmp_path, _restore_state):
        db_dir = str(tmp_path)
        result = ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        assert result["forced"] is False

    def test_force_reingest_on_first_ingest_returns_forced_false(
        self, synthetic_pcap, tmp_path, _restore_state
    ):
        import os

        db_dir = str(tmp_path)
        os.environ["PCAP_AGENT_FORCE_REINGEST"] = "true"
        try:
            result = ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        finally:
            os.environ.pop("PCAP_AGENT_FORCE_REINGEST", None)
        assert result["cached"] is False
        assert result["forced"] is False

    def test_force_reingest_env_unset_after_test(
        self, synthetic_pcap, tmp_path, _restore_state
    ):
        import os

        db_dir = str(tmp_path)
        ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        os.environ["PCAP_AGENT_FORCE_REINGEST"] = "1"
        try:
            ingest_pcap(str(synthetic_pcap), db_dir=db_dir)
        finally:
            os.environ.pop("PCAP_AGENT_FORCE_REINGEST", None)
        assert "PCAP_AGENT_FORCE_REINGEST" not in os.environ


class TestIngestRadiotap:
    @pytest.fixture()
    def radiotap_pcap(self, tmp_path):
        pkts = [
            RadioTap(
                present="Rate+Channel+dBm_AntSignal",
                Rate=f["rate_raw"],
                ChannelFrequency=f["freq"],
                dBm_AntSignal=f["signal_dbm"],
            )
            / Dot11()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=1234, dport=80, flags="S")
            for f in _RT_FRAMES_DATA
        ]
        pcap_path = tmp_path / "radiotap.pcap"
        wrpcap(str(pcap_path), pkts)
        return pcap_path

    @pytest.fixture()
    def radiotap_ingest_result(self, radiotap_pcap, tmp_path, _restore_state):
        db_dir = str(tmp_path / "rtdb")
        return ingest_pcap(str(radiotap_pcap), db_dir=db_dir)

    @pytest.fixture()
    def radiotap_conn(self, radiotap_ingest_result):  # noqa: ARG002
        return _state.require_connection()

    def test_radiotap_frames_row_count(self, radiotap_conn):
        count = radiotap_conn.execute(
            "SELECT COUNT(*) FROM radiotap_frames"
        ).fetchone()[0]
        assert count == len(_RT_FRAMES_DATA)

    def test_radiotap_signal_dbm(self, radiotap_conn):
        rows = radiotap_conn.execute(
            "SELECT signal_dbm FROM radiotap_frames ORDER BY frame_id"
        ).fetchall()
        expected = [float(f["signal_dbm"]) for f in _RT_FRAMES_DATA]
        assert [r[0] for r in rows] == expected

    def test_radiotap_channel(self, radiotap_conn):
        rows = radiotap_conn.execute(
            "SELECT channel FROM radiotap_frames ORDER BY frame_id"
        ).fetchall()
        expected = [f["channel"] for f in _RT_FRAMES_DATA]
        assert [r[0] for r in rows] == expected

    def test_radiotap_data_rate_mbps(self, radiotap_conn):
        rows = radiotap_conn.execute(
            "SELECT data_rate_mbps FROM radiotap_frames ORDER BY frame_id"
        ).fetchall()
        expected = [f["rate_mbps"] for f in _RT_FRAMES_DATA]
        assert [r[0] for r in rows] == expected

    def test_capture_info_has_radiotap_true(
        self, radiotap_conn, radiotap_ingest_result
    ):
        row = radiotap_conn.execute(
            "SELECT has_radiotap FROM capture_info WHERE sha256 = ?",
            [radiotap_ingest_result["sha256"]],
        ).fetchone()
        assert row is not None
        assert row[0] is True
