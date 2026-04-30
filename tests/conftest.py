"""Shared pytest fixtures, including the synthetic PCAP test fixture."""

import os

import duckdb
import pytest
from constants import (
    ANOMALY_DPORT,
    ANOMALY_DST_IP,
    ANOMALY_PACKET_COUNT,
    ANOMALY_SPORT,
    ANOMALY_SRC_IP,
    SCAN_PORT_COUNT,
    SCAN_TARGET_IP,
    SCANNER_IP,
    SCANNER_SPORT,
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
from scapy.all import IP, TCP, UDP, Raw, wrpcap  # type: ignore[import-untyped]

from pcap_agent import db, parser


def pytest_configure(config):  # noqa: ARG001
    """Ensure ANTHROPIC_API_KEY is set so config.py can be imported in tests."""
    os.environ.setdefault("ANTHROPIC_API_KEY", "test-dummy-key")


@pytest.fixture(scope="session")
def synthetic_pcap(tmp_path_factory):
    """Generate a synthetic PCAP file with known traffic patterns.

    Contents:
    - 50 TCP packets (HTTP-like stream, reassemblable in seq order)
    - 200 large UDP packets from a single top-talker IP
    - 20 TCP SYN packets from one IP to 20 distinct ports (port scanner)
    - 5 oversized UDP packets at very short inter-arrival time (anomalies)
    """
    tmp_path = tmp_path_factory.mktemp("pcap")
    pcap_path = tmp_path / "synthetic.pcap"

    packets = []
    base_time = 1_700_000_000.0

    # 50 TCP packets: HTTP-like payload, sequential seq numbers for reassembly
    payload_chunk = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    seq = 1000
    for i in range(TCP_PACKET_COUNT):
        pkt = (
            IP(src=TCP_SRC_IP, dst=TCP_DST_IP)
            / TCP(sport=TCP_SPORT, dport=TCP_DPORT, seq=seq, flags="PA")
            / Raw(load=payload_chunk)
        )
        pkt.time = base_time + i * 0.01  # type: ignore[attr-defined]
        packets.append(pkt)
        seq += len(payload_chunk)

    # 200 large UDP packets from one IP (top talker)
    udp_payload = b"U" * 1400
    for i in range(UDP_PACKET_COUNT):
        pkt = (
            IP(src=UDP_TOP_TALKER_IP, dst=UDP_TARGET_IP)
            / UDP(sport=UDP_SPORT, dport=UDP_DPORT)
            / Raw(load=udp_payload)
        )
        pkt.time = base_time + 1000 + i * 0.1  # type: ignore[attr-defined]
        packets.append(pkt)

    # 20 TCP SYN packets to distinct ports (port scanner)
    for i, port in enumerate(range(1, SCAN_PORT_COUNT + 1)):
        pkt = IP(src=SCANNER_IP, dst=SCAN_TARGET_IP) / TCP(
            sport=SCANNER_SPORT, dport=port, flags="S"
        )
        pkt.time = base_time + 2000 + i * 0.001  # type: ignore[attr-defined]
        packets.append(pkt)

    # 5 oversized UDP packets with very short inter-arrival time (anomalies)
    anomaly_payload = b"A" * 9000
    for i in range(ANOMALY_PACKET_COUNT):
        pkt = (
            IP(src=ANOMALY_SRC_IP, dst=ANOMALY_DST_IP)
            / UDP(sport=ANOMALY_SPORT, dport=ANOMALY_DPORT)
            / Raw(load=anomaly_payload)
        )
        pkt.time = base_time + 3000 + i * 0.00001  # type: ignore[attr-defined]
        packets.append(pkt)

    wrpcap(str(pcap_path), packets)
    return pcap_path


@pytest.fixture(scope="session")
def parsed_pcap(synthetic_pcap):
    """Parse the synthetic PCAP once per test session."""
    return parser.parse(synthetic_pcap)


@pytest.fixture
def duckdb_conn():
    """Provide a fresh in-memory DuckDB connection per test."""
    conn = duckdb.connect(":memory:")
    db.create_schema(conn)
    yield conn
    conn.close()
