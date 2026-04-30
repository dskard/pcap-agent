"""Shared pytest fixtures, including the synthetic PCAP test fixture."""

import pytest
from scapy.all import IP, TCP, UDP, Raw, wrpcap  # type: ignore[import-untyped]

TCP_SRC_IP = "10.0.0.1"
TCP_DST_IP = "10.0.0.2"
UDP_TOP_TALKER_IP = "192.168.1.100"
UDP_TARGET_IP = "192.168.1.1"
SCANNER_IP = "10.0.2.1"
SCAN_TARGET_IP = "10.0.2.100"
ANOMALY_SRC_IP = "10.0.4.1"
ANOMALY_DST_IP = "10.0.4.2"

TCP_SPORT = 54321
TCP_DPORT = 80
UDP_SPORT = 12345
UDP_DPORT = 53
SCANNER_SPORT = 55000
SCAN_PORT_COUNT = 20
ANOMALY_SPORT = 9999
ANOMALY_DPORT = 9998

TCP_PACKET_COUNT = 50
UDP_PACKET_COUNT = 200
ANOMALY_PACKET_COUNT = 5


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
