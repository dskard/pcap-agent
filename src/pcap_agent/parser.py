"""Parse a PCAP file into normalized polars DataFrames using scapy."""

import logging
from dataclasses import dataclass
from pathlib import Path

import polars as pl
from scapy.all import (  # type: ignore[import-untyped]
    ARP,
    ICMP,
    IP,
    TCP,
    UDP,
    Dot1Q,
    Ether,
    IPv6,
    RadioTap,
)
from scapy.utils import PcapReader  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

_PROTO_TCP = 6
_PROTO_UDP = 17
_PROTO_ICMP = 1
_PROTO_ICMPV6 = 58

_PACKETS_SCHEMA = {
    "frame_id": pl.Int64,
    "timestamp": pl.Float64,
    "src_ip": pl.String,
    "dst_ip": pl.String,
    "protocol": pl.Int32,
    "length": pl.Int32,
    "ttl": pl.Int32,
}

_TCP_SCHEMA = {
    "frame_id": pl.Int64,
    "sport": pl.Int32,
    "dport": pl.Int32,
    "flags": pl.String,
    "seq": pl.Int64,
    "ack": pl.Int64,
    "payload": pl.Binary,
}

_UDP_SCHEMA = {
    "frame_id": pl.Int64,
    "sport": pl.Int32,
    "dport": pl.Int32,
    "payload": pl.Binary,
}

_ICMP_SCHEMA = {
    "frame_id": pl.Int64,
    "type": pl.Int32,
    "code": pl.Int32,
    "payload": pl.Binary,
}

_ETHERNET_FRAMES_SCHEMA = {
    "frame_id": pl.Int64,
    "src_mac": pl.String,
    "dst_mac": pl.String,
    "ethertype": pl.Int32,
    "vlan_id": pl.Int32,
}

_ARP_PACKETS_SCHEMA = {
    "frame_id": pl.Int64,
    "hw_type": pl.Int32,
    "proto_type": pl.Int32,
    "operation": pl.Int32,
    "sender_mac": pl.String,
    "sender_ip": pl.String,
    "target_mac": pl.String,
    "target_ip": pl.String,
}

_RADIOTAP_FRAMES_SCHEMA = {
    "frame_id": pl.Int64,
    "signal_dbm": pl.Float64,
    "channel": pl.Int32,
    "data_rate_mbps": pl.Float64,
}


@dataclass(frozen=True)
class ParsedPcap:
    packets: pl.DataFrame
    tcp_segments: pl.DataFrame
    udp_datagrams: pl.DataFrame
    icmp_messages: pl.DataFrame
    ethernet_frames: pl.DataFrame
    arp_packets: pl.DataFrame
    radiotap_frames: pl.DataFrame
    link_type: int
    has_radiotap: bool


def _freq_to_channel(freq_mhz: int) -> int | None:
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2412) // 5 + 1
    if freq_mhz == 2484:
        return 14
    if 5180 <= freq_mhz <= 5885:
        return (freq_mhz - 5000) // 5
    return None


def parse(pcap_path: Path | str) -> ParsedPcap:
    """Parse a PCAP file and return normalized DataFrames plus capture metadata."""
    logger.info("Parsing PCAP file: %s", pcap_path)
    with PcapReader(str(pcap_path)) as reader:
        link_type: int = reader.linktype
        raw_packets = reader.read_all()

    has_radiotap = False
    packets_rows: list[dict] = []
    tcp_rows: list[dict] = []
    udp_rows: list[dict] = []
    icmp_rows: list[dict] = []
    ethernet_rows: list[dict] = []
    arp_rows: list[dict] = []
    radiotap_rows: list[dict] = []

    for frame_id, pkt in enumerate(raw_packets):
        if pkt.haslayer(RadioTap):
            has_radiotap = True
            rt = pkt[RadioTap]
            sig = getattr(rt, "dBm_AntSignal", None)
            freq = getattr(rt, "ChannelFrequency", None)
            rate = getattr(rt, "Rate", None)
            radiotap_rows.append(
                {
                    "frame_id": frame_id,
                    "signal_dbm": float(sig) if sig is not None else None,
                    "channel": _freq_to_channel(freq) if freq is not None else None,
                    "data_rate_mbps": float(rate) / 2.0 if rate is not None else None,
                }
            )

        if pkt.haslayer(Ether):
            ether = pkt[Ether]
            if pkt.haslayer(Dot1Q):
                dot1q = pkt[Dot1Q]
                vlan_id: int | None = int(dot1q.vlan)
                ethertype = int(dot1q.type)
            else:
                vlan_id = None
                ethertype = int(ether.type)
            ethernet_rows.append(
                {
                    "frame_id": frame_id,
                    "src_mac": str(ether.src),
                    "dst_mac": str(ether.dst),
                    "ethertype": ethertype,
                    "vlan_id": vlan_id,
                }
            )
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                arp_rows.append(
                    {
                        "frame_id": frame_id,
                        "hw_type": int(arp.hwtype),
                        "proto_type": int(arp.ptype),
                        "operation": int(arp.op),
                        "sender_mac": str(arp.hwsrc),
                        "sender_ip": str(arp.psrc),
                        "target_mac": str(arp.hwdst),
                        "target_ip": str(arp.pdst),
                    }
                )

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            proto = int(ip_layer.proto)
            ttl = int(ip_layer.ttl)
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]
            ttl = int(ip_layer.hlim)
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            # Use haslayer() to find the transport protocol past any extension
            # headers; nh only reflects the first next-header value, which may
            # be an extension-header type (e.g. 43=routing, 44=fragment) rather
            # than the actual transport protocol.
            if pkt.haslayer(TCP):
                proto = _PROTO_TCP
            elif pkt.haslayer(UDP):
                proto = _PROTO_UDP
            else:
                proto = int(ip_layer.nh)
        else:
            continue

        packets_rows.append(
            {
                "frame_id": frame_id,
                "timestamp": float(pkt.time),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "length": len(pkt),
                "ttl": ttl,
            }
        )

        # proto classifies by outer protocol so ICMP error packets that
        # encapsulate an inner IP/TCP or IP/UDP header are not misrouted.
        # haslayer() remains as a guard: malformed/truncated captures can have
        # proto == 6 but no TCP layer, causing pkt[TCP] to raise an error.
        if proto == _PROTO_TCP and pkt.haslayer(TCP):
            tcp = pkt[TCP]
            tcp_rows.append(
                {
                    "frame_id": frame_id,
                    "sport": int(tcp.sport),
                    "dport": int(tcp.dport),
                    "flags": str(tcp.flags),
                    "seq": int(tcp.seq),
                    "ack": int(tcp.ack),
                    "payload": bytes(tcp.payload) if tcp.payload else b"",
                }
            )
        elif proto == _PROTO_UDP and pkt.haslayer(UDP):
            udp = pkt[UDP]
            udp_rows.append(
                {
                    "frame_id": frame_id,
                    "sport": int(udp.sport),
                    "dport": int(udp.dport),
                    "payload": bytes(udp.payload) if udp.payload else b"",
                }
            )
        elif proto == _PROTO_ICMP and pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            icmp_rows.append(
                {
                    "frame_id": frame_id,
                    "type": int(icmp.type),
                    "code": int(icmp.code),
                    "payload": bytes(icmp.payload) if icmp.payload else b"",
                }
            )
        elif proto == _PROTO_ICMPV6:
            icmpv6 = ip_layer.payload
            if icmpv6 and hasattr(icmpv6, "type"):
                icmp_rows.append(
                    {
                        "frame_id": frame_id,
                        "type": int(icmpv6.type),
                        "code": int(icmpv6.code) if hasattr(icmpv6, "code") else 0,
                        "payload": bytes(icmpv6.payload) if icmpv6.payload else b"",
                    }
                )

    logger.info("Parsed %d IP/IPv6 packets from %s", len(packets_rows), pcap_path)
    logger.debug(
        "Protocol breakdown — TCP: %d, UDP: %d, ICMP: %d, Ethernet: %d, ARP: %d",
        len(tcp_rows),
        len(udp_rows),
        len(icmp_rows),
        len(ethernet_rows),
        len(arp_rows),
    )

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
        ethernet_frames=pl.DataFrame(ethernet_rows, schema=_ETHERNET_FRAMES_SCHEMA)
        if ethernet_rows
        else pl.DataFrame(schema=_ETHERNET_FRAMES_SCHEMA),
        arp_packets=pl.DataFrame(arp_rows, schema=_ARP_PACKETS_SCHEMA)
        if arp_rows
        else pl.DataFrame(schema=_ARP_PACKETS_SCHEMA),
        radiotap_frames=pl.DataFrame(radiotap_rows, schema=_RADIOTAP_FRAMES_SCHEMA)
        if radiotap_rows
        else pl.DataFrame(schema=_RADIOTAP_FRAMES_SCHEMA),
        link_type=link_type,
        has_radiotap=has_radiotap,
    )
