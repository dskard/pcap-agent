"""Unit tests for pcap_agent.db."""

import duckdb
import pytest
from constants import (
    ICMP_PACKET_COUNT,
    TCP_TOTAL,
    TOTAL_IP,
    UDP_TOTAL,
)

from pcap_agent import db

_EXPECTED_TABLES = {
    "packets",
    "tcp_segments",
    "udp_datagrams",
    "icmp_messages",
    "pcap_meta",
}


class TestCreateSchema:
    def test_all_tables_exist(self, duckdb_conn):
        rows = duckdb_conn.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'main'"
        ).fetchall()
        tables = {r[0] for r in rows}
        assert _EXPECTED_TABLES <= tables

    def test_idempotent(self, duckdb_conn):
        db.create_schema(duckdb_conn)
        rows = duckdb_conn.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'main'"
        ).fetchall()
        tables = {r[0] for r in rows}
        assert _EXPECTED_TABLES <= tables


class TestIngest:
    def test_packets_row_count(self, duckdb_conn, parsed_pcap):
        db.ingest(duckdb_conn, parsed_pcap)
        count = duckdb_conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        assert count == TOTAL_IP

    def test_tcp_segments_row_count(self, duckdb_conn, parsed_pcap):
        db.ingest(duckdb_conn, parsed_pcap)
        count = duckdb_conn.execute(
            "SELECT COUNT(*) FROM tcp_segments"
        ).fetchone()[0]
        assert count == TCP_TOTAL

    def test_udp_datagrams_row_count(self, duckdb_conn, parsed_pcap):
        db.ingest(duckdb_conn, parsed_pcap)
        count = duckdb_conn.execute(
            "SELECT COUNT(*) FROM udp_datagrams"
        ).fetchone()[0]
        assert count == UDP_TOTAL

    def test_icmp_messages_row_count(self, duckdb_conn, parsed_pcap):
        db.ingest(duckdb_conn, parsed_pcap)
        count = duckdb_conn.execute(
            "SELECT COUNT(*) FROM icmp_messages"
        ).fetchone()[0]
        assert count == ICMP_PACKET_COUNT


class TestIngestRollback:
    """Verify ingest() rolls back on mid-ingest failure."""

    def test_rollback_on_failure(self, duckdb_conn, parsed_pcap):
        # Pre-insert packet_id=0 to trigger a PRIMARY KEY violation on the
        # second ingest() call, forcing a failure after _load_df("packets").
        duckdb_conn.execute(
            "INSERT INTO packets"
            " (packet_id, timestamp, src_ip, dst_ip, protocol, length, ttl)"
            " VALUES (0, 0.0, '0.0.0.0', '0.0.0.0', 0, 0, 0)"
        )
        with pytest.raises(duckdb.ConstraintException):
            db.ingest(duckdb_conn, parsed_pcap)
        # packets must still contain only the one pre-inserted row.
        count = duckdb_conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        assert count == 1


class TestIngestCallerTransaction:
    """Tests for ingest() when the caller owns the active transaction."""

    def test_participates_in_caller_transaction(self, duckdb_conn, parsed_pcap):
        duckdb_conn.begin()
        db.ingest(duckdb_conn, parsed_pcap, begin_transaction=False)
        count = duckdb_conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        assert count == TOTAL_IP
        duckdb_conn.commit()
        count = duckdb_conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        assert count == TOTAL_IP

    def test_does_not_commit_caller_transaction(self, duckdb_conn, parsed_pcap):
        duckdb_conn.begin()
        db.ingest(duckdb_conn, parsed_pcap, begin_transaction=False)
        duckdb_conn.rollback()
        count = duckdb_conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        assert count == 0


class TestSetCached:
    _SHA256 = "c" * 64
    _PATH = "/tmp/set_test.pcap"

    def test_inserts_row(self, duckdb_conn):
        db.set_cached(duckdb_conn, self._SHA256, self._PATH)
        result = db.get_cached(duckdb_conn, self._SHA256)
        assert result is not None
        assert result["sha256"] == self._SHA256
        assert result["pcap_path"] == self._PATH

    def test_idempotent(self, duckdb_conn):
        db.set_cached(duckdb_conn, self._SHA256, self._PATH)
        db.set_cached(duckdb_conn, self._SHA256, self._PATH)
        count = duckdb_conn.execute(
            "SELECT COUNT(*) FROM pcap_meta WHERE sha256 = ?", [self._SHA256]
        ).fetchone()[0]
        assert count == 1


class TestGetCached:
    _SHA256 = "a" * 64
    _PATH = "/tmp/test.pcap"

    def _insert(self, conn):
        db.set_cached(conn, self._SHA256, self._PATH)

    def test_cache_hit(self, duckdb_conn):
        self._insert(duckdb_conn)
        result = db.get_cached(duckdb_conn, self._SHA256)
        assert result is not None
        assert result["sha256"] == self._SHA256
        assert result["pcap_path"] == self._PATH
        assert result["ingested_at"] is not None

    def test_cache_miss(self, duckdb_conn):
        result = db.get_cached(duckdb_conn, "b" * 64)
        assert result is None

    def test_cache_miss_after_other_entry(self, duckdb_conn):
        self._insert(duckdb_conn)
        result = db.get_cached(duckdb_conn, "b" * 64)
        assert result is None
