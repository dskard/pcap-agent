"""Unit tests for pcap_agent.db."""

from constants import (
    ANOMALY_PACKET_COUNT,
    SCAN_PORT_COUNT,
    TCP_PACKET_COUNT,
    UDP_PACKET_COUNT,
)

from pcap_agent import db

_TCP_TOTAL = TCP_PACKET_COUNT + SCAN_PORT_COUNT
_UDP_TOTAL = UDP_PACKET_COUNT + ANOMALY_PACKET_COUNT
_TOTAL_IP = _TCP_TOTAL + _UDP_TOTAL

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
        assert count == _TOTAL_IP

    def test_tcp_segments_row_count(self, duckdb_conn, parsed_pcap):
        db.ingest(duckdb_conn, parsed_pcap)
        count = duckdb_conn.execute(
            "SELECT COUNT(*) FROM tcp_segments"
        ).fetchone()[0]
        assert count == _TCP_TOTAL

    def test_udp_datagrams_row_count(self, duckdb_conn, parsed_pcap):
        db.ingest(duckdb_conn, parsed_pcap)
        count = duckdb_conn.execute(
            "SELECT COUNT(*) FROM udp_datagrams"
        ).fetchone()[0]
        assert count == _UDP_TOTAL

    def test_icmp_messages_row_count(self, duckdb_conn, parsed_pcap):
        db.ingest(duckdb_conn, parsed_pcap)
        count = duckdb_conn.execute(
            "SELECT COUNT(*) FROM icmp_messages"
        ).fetchone()[0]
        assert count == 0


class TestGetCached:
    _SHA256 = "a" * 64
    _PATH = "/tmp/test.pcap"

    def _insert(self, conn):
        conn.execute(
            "INSERT INTO pcap_meta (sha256, pcap_path) VALUES (?, ?)",
            [self._SHA256, self._PATH],
        )

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
