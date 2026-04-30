"""Integration tests for the stream reassembly tool."""

import pytest
from constants import (
    TCP_DPORT,
    TCP_DST_IP,
    TCP_PACKET_COUNT,
    TCP_SPORT,
    TCP_SRC_IP,
    UDP_DPORT,
    UDP_PACKET_COUNT,
    UDP_SPORT,
    UDP_TARGET_IP,
    UDP_TOP_TALKER_IP,
)

from pcap_agent.tools import _state
from pcap_agent.tools.reassembly import reassemble_stream

_TCP_PAYLOAD_CHUNK = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
_UDP_PAYLOAD_CHUNK = b"U" * 1400
_MAX_BYTES = 64 * 1024


class TestTCPReassembly:
    def test_tcp_returns_all_chunks_in_seq_order(self, ingested_db):  # noqa: ARG002
        result = reassemble_stream(TCP_SRC_IP, TCP_DST_IP, TCP_SPORT, TCP_DPORT, "TCP")

        assert "error" not in result
        assert result["protocol"] == "TCP"
        assert result["truncated"] is False

        expected = (_TCP_PAYLOAD_CHUNK * TCP_PACKET_COUNT).decode("utf-8")
        assert result["payload"] == expected

    def test_tcp_payload_decoded_as_utf8(self, ingested_db):  # noqa: ARG002
        result = reassemble_stream(TCP_SRC_IP, TCP_DST_IP, TCP_SPORT, TCP_DPORT, "TCP")

        assert result["encoding"] == "utf-8"
        assert isinstance(result["payload"], str)
        assert "GET / HTTP/1.1" in result["payload"]

    def test_tcp_seq_order_matches_payload_prefix(self, ingested_db):  # noqa: ARG002
        """First bytes of the reassembled stream must match the first chunk."""
        result = reassemble_stream(TCP_SRC_IP, TCP_DST_IP, TCP_SPORT, TCP_DPORT, "TCP")
        assert result["payload"].startswith(_TCP_PAYLOAD_CHUNK.decode("utf-8"))


class TestUDPReassembly:
    def test_udp_truncated_at_64kb(self, ingested_db):  # noqa: ARG002
        total_udp_bytes = UDP_PACKET_COUNT * len(_UDP_PAYLOAD_CHUNK)
        assert total_udp_bytes > _MAX_BYTES, "fixture must exceed 64 KB for this test"

        result = reassemble_stream(
            UDP_TOP_TALKER_IP, UDP_TARGET_IP, UDP_SPORT, UDP_DPORT, "UDP"
        )

        assert "error" not in result
        assert result["truncated"] is True
        assert len(result["payload"].encode()) <= _MAX_BYTES

    def test_udp_truncation_flag_present(self, ingested_db):  # noqa: ARG002
        result = reassemble_stream(
            UDP_TOP_TALKER_IP, UDP_TARGET_IP, UDP_SPORT, UDP_DPORT, "UDP"
        )
        assert "truncated" in result

    def test_udp_timestamp_order_preserved(self, ingested_db):  # noqa: ARG002
        """UDP chunks are `b'U' * 1400` — any ordering gives the same bytes,
        but we confirm the tool runs without error and returns a non-empty payload."""
        result = reassemble_stream(
            UDP_TOP_TALKER_IP, UDP_TARGET_IP, UDP_SPORT, UDP_DPORT, "UDP"
        )
        assert "error" not in result
        assert len(result["payload"]) > 0


class TestBinaryEncoding:
    """Test hex-dump fallback for non-UTF-8 payloads using an isolated DB."""

    @pytest.fixture()
    def binary_conn(self, duckdb_conn):
        """Insert a UDP flow with a binary (non-UTF-8) payload into a fresh DB."""
        binary_payload = bytes(range(256))  # contains non-UTF-8 bytes
        duckdb_conn.execute(
            "INSERT INTO packets "
            "VALUES (1, 1700000000.0, '1.2.3.4', '5.6.7.8', 17, 256, 64)"
        )
        duckdb_conn.execute(
            "INSERT INTO udp_datagrams VALUES (1, 9000, 9001, ?)",
            [binary_payload],
        )
        old = _state.get_connection()
        old_path = _state.get_db_path()
        _state.set_connection(duckdb_conn, ":memory:")
        yield duckdb_conn, binary_payload
        _state.set_connection(old, old_path) if old else _state.reset()

    def test_binary_payload_returned_as_hex(self, binary_conn):
        _, binary_payload = binary_conn
        result = reassemble_stream("1.2.3.4", "5.6.7.8", 9000, 9001, "UDP")

        assert "error" not in result
        assert result["encoding"] == "hex"
        assert result["payload"] == binary_payload.hex()


class TestEdgeCases:
    def test_unknown_5tuple_returns_error(self, ingested_db):  # noqa: ARG002
        result = reassemble_stream("0.0.0.0", "0.0.0.0", 1, 2, "TCP")
        assert "error" in result

    def test_unsupported_protocol_returns_error(self, ingested_db):  # noqa: ARG002
        result = reassemble_stream(TCP_SRC_IP, TCP_DST_IP, TCP_SPORT, TCP_DPORT, "ICMP")
        assert "error" in result
        assert "hint" in result

    def test_protocol_case_insensitive(self, ingested_db):  # noqa: ARG002
        result = reassemble_stream(TCP_SRC_IP, TCP_DST_IP, TCP_SPORT, TCP_DPORT, "tcp")
        assert "error" not in result
        assert result["protocol"] == "TCP"


class TestTruncationAt64KB:
    """Verify truncation mechanics with an isolated DB and a single large payload."""

    @pytest.fixture()
    def oversized_conn(self, duckdb_conn):
        large_payload = b"A" * (65 * 1024)  # 65 KB, just over the cap
        duckdb_conn.execute(
            "INSERT INTO packets "
            "VALUES (1, 1700000000.0, '1.1.1.1', '2.2.2.2', 6, 66560, 64)"
        )
        duckdb_conn.execute(
            "INSERT INTO tcp_segments VALUES (1, 5000, 80, 'PA', 1000, 0, ?)",
            [large_payload],
        )
        old = _state.get_connection()
        old_path = _state.get_db_path()
        _state.set_connection(duckdb_conn, ":memory:")
        yield duckdb_conn
        _state.set_connection(old, old_path) if old else _state.reset()

    @pytest.fixture()
    def exact_fill_conn(self, duckdb_conn):
        exact_payload = b"A" * _MAX_BYTES  # exactly 64 KB, no overflow
        duckdb_conn.execute(
            "INSERT INTO packets "
            "VALUES (1, 1700000000.0, '1.1.1.1', '2.2.2.2', 6, 65536, 64)"
        )
        duckdb_conn.execute(
            "INSERT INTO tcp_segments VALUES (1, 5000, 80, 'PA', 1000, 0, ?)",
            [exact_payload],
        )
        old = _state.get_connection()
        old_path = _state.get_db_path()
        _state.set_connection(duckdb_conn, ":memory:")
        yield duckdb_conn
        _state.set_connection(old, old_path) if old else _state.reset()

    def test_single_oversized_chunk_truncated(self, oversized_conn):  # noqa: ARG002
        result = reassemble_stream("1.1.1.1", "2.2.2.2", 5000, 80, "TCP")

        assert result["truncated"] is True
        assert len(result["payload"].encode()) == _MAX_BYTES

    def test_exact_fill_chunk_not_truncated(self, exact_fill_conn):  # noqa: ARG002
        """A chunk that exactly fills 64 KB must not set truncated=True."""
        result = reassemble_stream("1.1.1.1", "2.2.2.2", 5000, 80, "TCP")

        assert result["truncated"] is False
        assert len(result["payload"].encode()) == _MAX_BYTES


class TestTCPRetransmission:
    """Retransmitted segments (duplicate seq numbers) must not double-count payload."""

    @pytest.fixture()
    def retransmit_conn(self, duckdb_conn):
        payload = b"hello"
        duckdb_conn.execute(
            "INSERT INTO packets VALUES (1, 1700000000.0, '1.1.1.1', '2.2.2.2', 6, 50, 64)"
        )
        duckdb_conn.execute(
            "INSERT INTO packets VALUES (2, 1700000001.0, '1.1.1.1', '2.2.2.2', 6, 50, 64)"
        )
        duckdb_conn.execute(
            "INSERT INTO tcp_segments VALUES (1, 5000, 80, 'PA', 1000, 0, ?)", [payload]
        )
        duckdb_conn.execute(
            "INSERT INTO tcp_segments VALUES (2, 5000, 80, 'PA', 1000, 0, ?)", [payload]
        )
        old = _state.get_connection()
        old_path = _state.get_db_path()
        _state.set_connection(duckdb_conn, ":memory:")
        yield duckdb_conn
        _state.set_connection(old, old_path) if old else _state.reset()

    def test_retransmitted_segments_not_duplicated(self, retransmit_conn):  # noqa: ARG002
        result = reassemble_stream("1.1.1.1", "2.2.2.2", 5000, 80, "TCP")

        assert "error" not in result
        assert result["payload"] == "hello"
