"""Smoke tests verifying the synthetic PCAP fixture is well-formed."""

from pathlib import Path

from constants import (
    ANOMALY_PACKET_COUNT,
    ANOMALY_SRC_IP,
    ICMP_PACKET_COUNT,
    ICMP_SRC_IP,
    ICMP_TYPE,
    SCAN_PORT_COUNT,
    SCAN_TARGET_IP,
    SCANNER_IP,
    TCP_DST_IP,
    TCP_PACKET_COUNT,
    TCP_SRC_IP,
    TOTAL_FRAMES,
    UDP_PACKET_COUNT,
    UDP_TOP_TALKER_IP,
)
from scapy.all import rdpcap  # type: ignore[import-untyped]


def test_synthetic_pcap_exists(synthetic_pcap):
    assert isinstance(synthetic_pcap, Path)
    assert synthetic_pcap.exists()
    assert synthetic_pcap.stat().st_size > 0


def test_synthetic_pcap_packet_counts(synthetic_pcap):
    pkts = rdpcap(str(synthetic_pcap))
    assert len(pkts) == TOTAL_FRAMES


def test_synthetic_pcap_tcp_stream(synthetic_pcap):
    pkts = rdpcap(str(synthetic_pcap))
    tcp_pkts = [p for p in pkts if p.haslayer("TCP") and p["IP"].src == TCP_SRC_IP]
    assert len(tcp_pkts) == TCP_PACKET_COUNT
    assert all(p["IP"].dst == TCP_DST_IP for p in tcp_pkts)


def test_synthetic_pcap_top_talker(synthetic_pcap):
    pkts = rdpcap(str(synthetic_pcap))
    udp_pkts = [
        p for p in pkts if p.haslayer("UDP") and p["IP"].src == UDP_TOP_TALKER_IP
    ]
    assert len(udp_pkts) == UDP_PACKET_COUNT


def test_synthetic_pcap_port_scanner(synthetic_pcap):
    pkts = rdpcap(str(synthetic_pcap))
    scan_pkts = [p for p in pkts if p.haslayer("TCP") and p["IP"].src == SCANNER_IP]
    dst_ports = {p["TCP"].dport for p in scan_pkts}
    assert len(scan_pkts) == SCAN_PORT_COUNT
    assert all(p["IP"].dst == SCAN_TARGET_IP for p in scan_pkts)
    assert len(dst_ports) == SCAN_PORT_COUNT


def test_synthetic_pcap_anomalies(synthetic_pcap):
    pkts = rdpcap(str(synthetic_pcap))
    anomaly_pkts = [
        p for p in pkts if p.haslayer("UDP") and p["IP"].src == ANOMALY_SRC_IP
    ]
    assert len(anomaly_pkts) == ANOMALY_PACKET_COUNT
    assert all(len(p) > 8000 for p in anomaly_pkts)


def test_synthetic_pcap_icmp(synthetic_pcap):
    pkts = rdpcap(str(synthetic_pcap))
    icmp_pkts = [
        p for p in pkts if p.haslayer("ICMP") and p["IP"].src == ICMP_SRC_IP
    ]
    assert len(icmp_pkts) == ICMP_PACKET_COUNT
    assert all(p["ICMP"].type == ICMP_TYPE for p in icmp_pkts)
