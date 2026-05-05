"""Integration tests for tools.ingest.ingest_pcap."""

import duckdb
import pytest
from constants import (
    ICMP_PACKET_COUNT,
    TCP_TOTAL,
    TOTAL_IP,
    UDP_TOTAL,
)

from pcap_agent.tools import _state
from pcap_agent.tools.ingest import ingest_pcap


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
