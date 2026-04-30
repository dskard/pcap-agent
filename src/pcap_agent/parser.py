"""Parse a PCAP file into normalized polars DataFrames using scapy."""

from dataclasses import dataclass
from pathlib import Path

import polars as pl
from scapy.all import ICMP, IP, TCP, UDP, rdpcap  # type: ignore[import-untyped]

_PACKETS_SCHEMA = {
    "packet_id": pl.Int64,
    "timestamp": pl.Float64,
    "src_ip": pl.String,
    "dst_ip": pl.String,
    "protocol": pl.Int32,
    "length": pl.Int32,
    "ttl": pl.Int32,
}

_TCP_SCHEMA = {
    "packet_id": pl.Int64,
    "sport": pl.Int32,
    "dport": pl.Int32,
    "flags": pl.String,
    "seq": pl.Int64,
    "ack": pl.Int64,
    "payload": pl.Binary,
}

_UDP_SCHEMA = {
    "packet_id": pl.Int64,
    "sport": pl.Int32,
    "dport": pl.Int32,
    "payload": pl.Binary,
}

_ICMP_SCHEMA = {
    "packet_id": pl.Int64,
    "type": pl.Int32,
    "code": pl.Int32,
    "payload": pl.Binary,
}


@dataclass(frozen=True)
class ParsedPcap:
    packets: pl.DataFrame
    tcp_segments: pl.DataFrame
    udp_datagrams: pl.DataFrame
    icmp_messages: pl.DataFrame


def parse(pcap_path: Path | str) -> ParsedPcap:
    """Parse a PCAP file and return four normalized DataFrames."""
    raw_packets = rdpcap(str(pcap_path))

    packets_rows: list[dict] = []
    tcp_rows: list[dict] = []
    udp_rows: list[dict] = []
    icmp_rows: list[dict] = []
    packet_id = 0

    for pkt in raw_packets:
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        packets_rows.append(
            {
                "packet_id": packet_id,
                "timestamp": float(pkt.time),
                "src_ip": str(ip.src),
                "dst_ip": str(ip.dst),
                "protocol": int(ip.proto),
                "length": len(pkt),
                "ttl": int(ip.ttl),
            }
        )

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            tcp_rows.append(
                {
                    "packet_id": packet_id,
                    "sport": int(tcp.sport),
                    "dport": int(tcp.dport),
                    "flags": str(tcp.flags),
                    "seq": int(tcp.seq),
                    "ack": int(tcp.ack),
                    "payload": bytes(tcp.payload) if tcp.payload else b"",
                }
            )
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            udp_rows.append(
                {
                    "packet_id": packet_id,
                    "sport": int(udp.sport),
                    "dport": int(udp.dport),
                    "payload": bytes(udp.payload) if udp.payload else b"",
                }
            )
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            icmp_rows.append(
                {
                    "packet_id": packet_id,
                    "type": int(icmp.type),
                    "code": int(icmp.code),
                    "payload": bytes(icmp.payload) if icmp.payload else b"",
                }
            )

        packet_id += 1

    return ParsedPcap(
        packets=pl.DataFrame(packets_rows, schema=_PACKETS_SCHEMA)
        if packets_rows
        else pl.DataFrame(schema=_PACKETS_SCHEMA),
        tcp_segments=pl.DataFrame(tcp_rows, schema=_TCP_SCHEMA)
        if tcp_rows
        else pl.DataFrame(schema=_TCP_SCHEMA),
        udp_datagrams=pl.DataFrame(udp_rows, schema=_UDP_SCHEMA)
        if udp_rows
        else pl.DataFrame(schema=_UDP_SCHEMA),
        icmp_messages=pl.DataFrame(icmp_rows, schema=_ICMP_SCHEMA)
        if icmp_rows
        else pl.DataFrame(schema=_ICMP_SCHEMA),
    )
