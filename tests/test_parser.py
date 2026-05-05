"""Unit tests for pcap_agent.parser."""

import polars as pl
import pytest
from constants import (
    ANOMALY_DPORT,
    ANOMALY_PACKET_COUNT,
    ANOMALY_SPORT,
    ANOMALY_SRC_IP,
    ICMP_CODE,
    ICMP_DST_IP,
    ICMP_PACKET_COUNT,
    ICMP_SRC_IP,
    ICMP_TYPE,
    TCP_DPORT,
    TCP_PACKET_COUNT,
    TCP_SPORT,
    TCP_SRC_IP,
    TCP_TOTAL,
    TOTAL_IP,
    UDP_DPORT,
    UDP_PACKET_COUNT,
    UDP_SPORT,
    UDP_TOP_TALKER_IP,
    UDP_TOTAL,
)
from scapy.all import (  # type: ignore[import-untyped]
    TCP,
    UDP,
    ICMPv6EchoRequest,
    IPv6,
    Raw,
    wrpcap,
)


class TestParsedPcapTypes:
    def test_returns_four_dataframes(self, parsed_pcap):
        assert isinstance(parsed_pcap.packets, pl.DataFrame)
        assert isinstance(parsed_pcap.tcp_segments, pl.DataFrame)
        assert isinstance(parsed_pcap.udp_datagrams, pl.DataFrame)
        assert isinstance(parsed_pcap.icmp_messages, pl.DataFrame)

    def test_packets_schema(self, parsed_pcap):
        expected = {
            "frame_id": pl.Int64,
            "timestamp": pl.Float64,
            "src_ip": pl.String,
            "dst_ip": pl.String,
            "protocol": pl.Int32,
            "length": pl.Int32,
            "ttl": pl.Int32,
        }
        assert parsed_pcap.packets.schema == pl.Schema(expected)

    def test_tcp_segments_schema(self, parsed_pcap):
        expected = {
            "frame_id": pl.Int64,
            "sport": pl.Int32,
            "dport": pl.Int32,
            "flags": pl.String,
            "seq": pl.Int64,
            "ack": pl.Int64,
            "payload": pl.Binary,
        }
        assert parsed_pcap.tcp_segments.schema == pl.Schema(expected)

    def test_udp_datagrams_schema(self, parsed_pcap):
        expected = {
            "frame_id": pl.Int64,
            "sport": pl.Int32,
            "dport": pl.Int32,
            "payload": pl.Binary,
        }
        assert parsed_pcap.udp_datagrams.schema == pl.Schema(expected)

    def test_icmp_messages_schema(self, parsed_pcap):
        expected = {
            "frame_id": pl.Int64,
            "type": pl.Int32,
            "code": pl.Int32,
            "payload": pl.Binary,
        }
        assert parsed_pcap.icmp_messages.schema == pl.Schema(expected)


class TestRowCounts:
    def test_packets_total(self, parsed_pcap):
        assert len(parsed_pcap.packets) == TOTAL_IP

    def test_tcp_segments_total(self, parsed_pcap):
        assert len(parsed_pcap.tcp_segments) == TCP_TOTAL

    def test_udp_datagrams_total(self, parsed_pcap):
        assert len(parsed_pcap.udp_datagrams) == UDP_TOTAL

    def test_icmp_messages_total(self, parsed_pcap):
        assert len(parsed_pcap.icmp_messages) == ICMP_PACKET_COUNT


class TestTcpStreamSpotCheck:
    @pytest.fixture(autouse=True)
    def _tcp_stream(self, parsed_pcap):
        self.tcp = parsed_pcap.tcp_segments.filter(pl.col("sport") == TCP_SPORT)

    def test_row_count(self):
        assert len(self.tcp) == TCP_PACKET_COUNT

    def test_src_ip(self, parsed_pcap):
        pkt_ids = self.tcp["frame_id"].to_list()
        src_ips = (
            parsed_pcap.packets.filter(pl.col("frame_id").is_in(pkt_ids))["src_ip"]
            .unique()
            .to_list()
        )
        assert src_ips == [TCP_SRC_IP]

    def test_dport(self):
        assert self.tcp["dport"].unique().to_list() == [TCP_DPORT]

    def test_flags(self):
        assert all("P" in f for f in self.tcp["flags"].to_list())


class TestUdpTopTalkerSpotCheck:
    @pytest.fixture(autouse=True)
    def _top_talker(self, parsed_pcap):
        pkt_ids = (
            parsed_pcap.packets.filter(pl.col("src_ip") == UDP_TOP_TALKER_IP)[
                "frame_id"
            ]
            .to_list()
        )
        self.udp = parsed_pcap.udp_datagrams.filter(
            pl.col("frame_id").is_in(pkt_ids)
        )

    def test_row_count(self):
        assert len(self.udp) == UDP_PACKET_COUNT

    def test_dport(self):
        assert self.udp["dport"].unique().to_list() == [UDP_DPORT]

    def test_sport(self):
        assert self.udp["sport"].unique().to_list() == [UDP_SPORT]


class TestUdpAnomalySpotCheck:
    @pytest.fixture(autouse=True)
    def _anomaly(self, parsed_pcap):
        self.udp = parsed_pcap.udp_datagrams.filter(pl.col("sport") == ANOMALY_SPORT)

    def test_row_count(self):
        assert len(self.udp) == ANOMALY_PACKET_COUNT

    def test_dport(self):
        assert self.udp["dport"].unique().to_list() == [ANOMALY_DPORT]

    def test_src_ip(self, parsed_pcap):
        pkt_ids = self.udp["frame_id"].to_list()
        src_ips = (
            parsed_pcap.packets.filter(pl.col("frame_id").is_in(pkt_ids))["src_ip"]
            .unique()
            .to_list()
        )
        assert src_ips == [ANOMALY_SRC_IP]


class TestIcmpSpotCheck:
    @pytest.fixture(autouse=True)
    def _icmp(self, parsed_pcap):
        self.icmp = parsed_pcap.icmp_messages

    def test_row_count(self):
        assert len(self.icmp) == ICMP_PACKET_COUNT

    def test_type(self):
        assert self.icmp["type"].unique().to_list() == [ICMP_TYPE]

    def test_code(self):
        assert self.icmp["code"].unique().to_list() == [ICMP_CODE]

    def test_src_ip(self, parsed_pcap):
        pkt_ids = self.icmp["frame_id"].to_list()
        src_ips = (
            parsed_pcap.packets.filter(pl.col("frame_id").is_in(pkt_ids))["src_ip"]
            .unique()
            .to_list()
        )
        assert src_ips == [ICMP_SRC_IP]

    def test_dst_ip(self, parsed_pcap):
        pkt_ids = self.icmp["frame_id"].to_list()
        dst_ips = (
            parsed_pcap.packets.filter(pl.col("frame_id").is_in(pkt_ids))["dst_ip"]
            .unique()
            .to_list()
        )
        assert dst_ips == [ICMP_DST_IP]


_IPV6_SRC = "2001:db8::1"
_IPV6_DST = "2001:db8::2"
_IPV6_TCP_SPORT = 44444
_IPV6_TCP_DPORT = 80
_IPV6_UDP_SPORT = 55555
_IPV6_UDP_DPORT = 53
_IPV6_ICMPV6_TYPE = 128  # ICMPv6EchoRequest
_IPV6_ICMPV6_CODE = 0


class TestIPv6Parsing:
    @pytest.fixture(scope="class")
    def ipv6_pcap(self, tmp_path_factory):
        tmp_path = tmp_path_factory.mktemp("ipv6_pcap")
        pcap_path = tmp_path / "ipv6.pcap"
        pkts = [
            IPv6(src=_IPV6_SRC, dst=_IPV6_DST)
            / TCP(sport=_IPV6_TCP_SPORT, dport=_IPV6_TCP_DPORT, flags="S"),
            IPv6(src=_IPV6_SRC, dst=_IPV6_DST)
            / UDP(sport=_IPV6_UDP_SPORT, dport=_IPV6_UDP_DPORT)
            / Raw(load=b"hello"),
            IPv6(src=_IPV6_SRC, dst=_IPV6_DST) / ICMPv6EchoRequest(),
        ]
        wrpcap(str(pcap_path), pkts)
        return pcap_path

    @pytest.fixture(scope="class")
    def parsed_ipv6(self, ipv6_pcap):
        from pcap_agent import parser

        return parser.parse(ipv6_pcap)

    def test_packet_count(self, parsed_ipv6):
        assert len(parsed_ipv6.packets) == 3

    def test_src_ip(self, parsed_ipv6):
        assert parsed_ipv6.packets["src_ip"].unique().to_list() == [_IPV6_SRC]

    def test_dst_ip(self, parsed_ipv6):
        assert parsed_ipv6.packets["dst_ip"].unique().to_list() == [_IPV6_DST]

    def test_tcp_segment_parsed(self, parsed_ipv6):
        assert len(parsed_ipv6.tcp_segments) == 1
        assert parsed_ipv6.tcp_segments["sport"].to_list() == [_IPV6_TCP_SPORT]
        assert parsed_ipv6.tcp_segments["dport"].to_list() == [_IPV6_TCP_DPORT]

    def test_udp_datagram_parsed(self, parsed_ipv6):
        assert len(parsed_ipv6.udp_datagrams) == 1
        assert parsed_ipv6.udp_datagrams["sport"].to_list() == [_IPV6_UDP_SPORT]
        assert parsed_ipv6.udp_datagrams["dport"].to_list() == [_IPV6_UDP_DPORT]

    def test_icmpv6_message_parsed(self, parsed_ipv6):
        assert len(parsed_ipv6.icmp_messages) == 1
        assert parsed_ipv6.icmp_messages["type"].to_list() == [_IPV6_ICMPV6_TYPE]
        assert parsed_ipv6.icmp_messages["code"].to_list() == [_IPV6_ICMPV6_CODE]
