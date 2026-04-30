"""Unit tests for pcap_agent.parser."""

import polars as pl
import pytest
from constants import (
    ANOMALY_DPORT,
    ANOMALY_PACKET_COUNT,
    ANOMALY_SPORT,
    ANOMALY_SRC_IP,
    SCAN_PORT_COUNT,
    TCP_DPORT,
    TCP_PACKET_COUNT,
    TCP_SPORT,
    TCP_SRC_IP,
    UDP_DPORT,
    UDP_PACKET_COUNT,
    UDP_SPORT,
    UDP_TOP_TALKER_IP,
)

_TCP_TOTAL = TCP_PACKET_COUNT + SCAN_PORT_COUNT
_UDP_TOTAL = UDP_PACKET_COUNT + ANOMALY_PACKET_COUNT
_TOTAL_IP = _TCP_TOTAL + _UDP_TOTAL


class TestParsedPcapTypes:
    def test_returns_four_dataframes(self, parsed_pcap):
        assert isinstance(parsed_pcap.packets, pl.DataFrame)
        assert isinstance(parsed_pcap.tcp_segments, pl.DataFrame)
        assert isinstance(parsed_pcap.udp_datagrams, pl.DataFrame)
        assert isinstance(parsed_pcap.icmp_messages, pl.DataFrame)

    def test_packets_schema(self, parsed_pcap):
        expected = {
            "packet_id": pl.Int64,
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
            "packet_id": pl.Int64,
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
            "packet_id": pl.Int64,
            "sport": pl.Int32,
            "dport": pl.Int32,
            "payload": pl.Binary,
        }
        assert parsed_pcap.udp_datagrams.schema == pl.Schema(expected)

    def test_icmp_messages_schema(self, parsed_pcap):
        expected = {
            "packet_id": pl.Int64,
            "type": pl.Int32,
            "code": pl.Int32,
            "payload": pl.Binary,
        }
        assert parsed_pcap.icmp_messages.schema == pl.Schema(expected)


class TestRowCounts:
    def test_packets_total(self, parsed_pcap):
        assert len(parsed_pcap.packets) == _TOTAL_IP

    def test_tcp_segments_total(self, parsed_pcap):
        assert len(parsed_pcap.tcp_segments) == _TCP_TOTAL

    def test_udp_datagrams_total(self, parsed_pcap):
        assert len(parsed_pcap.udp_datagrams) == _UDP_TOTAL

    def test_icmp_messages_empty(self, parsed_pcap):
        assert len(parsed_pcap.icmp_messages) == 0


class TestTcpStreamSpotCheck:
    @pytest.fixture(autouse=True)
    def _tcp_stream(self, parsed_pcap):
        self.tcp = parsed_pcap.tcp_segments.filter(
            pl.col("sport") == TCP_SPORT
        )

    def test_row_count(self):
        assert len(self.tcp) == TCP_PACKET_COUNT

    def test_src_ip(self, parsed_pcap):
        pkt_ids = self.tcp["packet_id"].to_list()
        src_ips = (
            parsed_pcap.packets.filter(pl.col("packet_id").is_in(pkt_ids))[
                "src_ip"
            ]
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
                "packet_id"
            ]
            .to_list()
        )
        self.udp = parsed_pcap.udp_datagrams.filter(
            pl.col("packet_id").is_in(pkt_ids)
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
        self.udp = parsed_pcap.udp_datagrams.filter(
            pl.col("sport") == ANOMALY_SPORT
        )

    def test_row_count(self):
        assert len(self.udp) == ANOMALY_PACKET_COUNT

    def test_dport(self):
        assert self.udp["dport"].unique().to_list() == [ANOMALY_DPORT]

    def test_src_ip(self, parsed_pcap):
        pkt_ids = self.udp["packet_id"].to_list()
        src_ips = (
            parsed_pcap.packets.filter(pl.col("packet_id").is_in(pkt_ids))[
                "src_ip"
            ]
            .unique()
            .to_list()
        )
        assert src_ips == [ANOMALY_SRC_IP]
