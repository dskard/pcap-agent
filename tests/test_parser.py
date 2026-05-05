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
    ARP,
    IP,
    TCP,
    UDP,
    Dot1Q,
    Dot11,
    Ether,
    ICMPv6EchoRequest,
    IPv6,
    RadioTap,
    Raw,
    wrpcap,
)


class TestParsedPcapTypes:
    def test_returns_six_dataframes(self, parsed_pcap):
        assert isinstance(parsed_pcap.packets, pl.DataFrame)
        assert isinstance(parsed_pcap.tcp_segments, pl.DataFrame)
        assert isinstance(parsed_pcap.udp_datagrams, pl.DataFrame)
        assert isinstance(parsed_pcap.icmp_messages, pl.DataFrame)
        assert isinstance(parsed_pcap.ethernet_frames, pl.DataFrame)
        assert isinstance(parsed_pcap.arp_packets, pl.DataFrame)

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

    def test_ethernet_frames_schema(self, parsed_pcap):
        expected = {
            "frame_id": pl.Int64,
            "src_mac": pl.String,
            "dst_mac": pl.String,
            "ethertype": pl.Int32,
            "vlan_id": pl.Int32,
        }
        assert parsed_pcap.ethernet_frames.schema == pl.Schema(expected)

    def test_arp_packets_schema(self, parsed_pcap):
        expected = {
            "frame_id": pl.Int64,
            "hw_type": pl.Int32,
            "proto_type": pl.Int32,
            "operation": pl.Int32,
            "sender_mac": pl.String,
            "sender_ip": pl.String,
            "target_mac": pl.String,
            "target_ip": pl.String,
        }
        assert parsed_pcap.arp_packets.schema == pl.Schema(expected)


class TestRowCounts:
    def test_packets_total(self, parsed_pcap):
        assert len(parsed_pcap.packets) == TOTAL_IP

    def test_tcp_segments_total(self, parsed_pcap):
        assert len(parsed_pcap.tcp_segments) == TCP_TOTAL

    def test_udp_datagrams_total(self, parsed_pcap):
        assert len(parsed_pcap.udp_datagrams) == UDP_TOTAL

    def test_icmp_messages_total(self, parsed_pcap):
        assert len(parsed_pcap.icmp_messages) == ICMP_PACKET_COUNT

    def test_no_ethernet_frames_for_raw_ip_capture(self, parsed_pcap):
        # The synthetic fixture uses raw IP packets (no Ether layer), so
        # ethernet_frames must be empty — this validates the non-Ethernet path.
        assert len(parsed_pcap.ethernet_frames) == 0

    def test_no_arp_packets_for_raw_ip_capture(self, parsed_pcap):
        assert len(parsed_pcap.arp_packets) == 0


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


_ETH_SRC_MAC = "aa:bb:cc:dd:ee:01"
_ETH_DST_MAC = "11:22:33:44:55:01"
_ARP_REQ_SRC_MAC = "aa:bb:cc:dd:ee:02"
_ARP_REQ_DST_MAC = "ff:ff:ff:ff:ff:ff"
_ARP_REP_SRC_MAC = "aa:bb:cc:dd:ee:03"
_ARP_REP_DST_MAC = "aa:bb:cc:dd:ee:02"
_ARP_SRC_IP = "192.168.10.1"
_ARP_DST_IP = "192.168.10.2"
_VLAN_ID = 100
_ETH_IP_SRC = "10.20.0.1"
_ETH_IP_DST = "10.20.0.2"
_VLAN_IP_SRC = "10.30.0.1"
_VLAN_IP_DST = "10.30.0.2"
_ETH_IP_ETHERTYPE = 0x0800  # IPv4


class TestEthernetParsing:
    """Ethernet, ARP, and VLAN parsing with dedicated Ether-framed fixture."""

    @pytest.fixture(scope="class")
    def eth_pcap(self, tmp_path_factory):
        tmp_path = tmp_path_factory.mktemp("eth_pcap")
        pcap_path = tmp_path / "ethernet.pcap"
        pkts = [
            # Regular Ethernet/IP/UDP frame
            Ether(src=_ETH_SRC_MAC, dst=_ETH_DST_MAC)
            / IP(src=_ETH_IP_SRC, dst=_ETH_IP_DST)
            / UDP(sport=1234, dport=5678)
            / Raw(load=b"hello"),
            # ARP request
            Ether(src=_ARP_REQ_SRC_MAC, dst=_ARP_REQ_DST_MAC)
            / ARP(
                op=1,
                hwsrc=_ARP_REQ_SRC_MAC,
                psrc=_ARP_SRC_IP,
                hwdst=_ARP_REQ_DST_MAC,
                pdst=_ARP_DST_IP,
            ),
            # ARP reply
            Ether(src=_ARP_REP_SRC_MAC, dst=_ARP_REP_DST_MAC)
            / ARP(
                op=2,
                hwsrc=_ARP_REP_SRC_MAC,
                psrc=_ARP_DST_IP,
                hwdst=_ARP_REP_DST_MAC,
                pdst=_ARP_SRC_IP,
            ),
            # VLAN-tagged frame (802.1Q)
            Ether(src=_ETH_SRC_MAC, dst=_ETH_DST_MAC)
            / Dot1Q(vlan=_VLAN_ID)
            / IP(src=_VLAN_IP_SRC, dst=_VLAN_IP_DST)
            / TCP(sport=9000, dport=80, flags="S"),
        ]
        wrpcap(str(pcap_path), pkts)
        return pcap_path

    @pytest.fixture(scope="class")
    def parsed_eth(self, eth_pcap):
        from pcap_agent import parser

        return parser.parse(eth_pcap)

    def test_ethernet_frames_row_count(self, parsed_eth):
        # 4 packets, all with Ether layer
        assert len(parsed_eth.ethernet_frames) == 4

    def test_ethernet_frame_src_mac(self, parsed_eth):
        eth_ip_frame = parsed_eth.ethernet_frames.filter(
            pl.col("frame_id") == 0
        )
        assert eth_ip_frame["src_mac"].to_list() == [_ETH_SRC_MAC]

    def test_ethernet_frame_dst_mac(self, parsed_eth):
        eth_ip_frame = parsed_eth.ethernet_frames.filter(
            pl.col("frame_id") == 0
        )
        assert eth_ip_frame["dst_mac"].to_list() == [_ETH_DST_MAC]

    def test_untagged_frame_vlan_id_is_null(self, parsed_eth):
        eth_ip_frame = parsed_eth.ethernet_frames.filter(
            pl.col("frame_id") == 0
        )
        assert eth_ip_frame["vlan_id"].to_list() == [None]

    def test_untagged_frame_ethertype(self, parsed_eth):
        eth_ip_frame = parsed_eth.ethernet_frames.filter(
            pl.col("frame_id") == 0
        )
        assert eth_ip_frame["ethertype"].to_list() == [_ETH_IP_ETHERTYPE]

    def test_arp_row_count(self, parsed_eth):
        assert len(parsed_eth.arp_packets) == 2

    def test_arp_request_operation(self, parsed_eth):
        arp_request = parsed_eth.arp_packets.filter(pl.col("frame_id") == 1)
        assert arp_request["operation"].to_list() == [1]

    def test_arp_reply_operation(self, parsed_eth):
        arp_reply = parsed_eth.arp_packets.filter(pl.col("frame_id") == 2)
        assert arp_reply["operation"].to_list() == [2]

    def test_arp_sender_ip(self, parsed_eth):
        arp_request = parsed_eth.arp_packets.filter(pl.col("frame_id") == 1)
        assert arp_request["sender_ip"].to_list() == [_ARP_SRC_IP]

    def test_arp_target_ip(self, parsed_eth):
        arp_request = parsed_eth.arp_packets.filter(pl.col("frame_id") == 1)
        assert arp_request["target_ip"].to_list() == [_ARP_DST_IP]

    def test_vlan_id_set(self, parsed_eth):
        vlan_frame = parsed_eth.ethernet_frames.filter(pl.col("frame_id") == 3)
        assert vlan_frame["vlan_id"].to_list() == [_VLAN_ID]

    def test_vlan_ethertype_is_inner_not_8100(self, parsed_eth):
        # 0x8100 is the outer 802.1Q tag; ethertype must reflect the inner type
        vlan_frame = parsed_eth.ethernet_frames.filter(pl.col("frame_id") == 3)
        assert vlan_frame["ethertype"].to_list() == [_ETH_IP_ETHERTYPE]
        assert vlan_frame["ethertype"].to_list()[0] != 0x8100

    def test_arp_frames_have_no_ip_packet_row(self, parsed_eth):
        # ARP frames (frame_id 1 and 2) must not appear in packets table
        arp_frame_ids = {1, 2}
        ip_frame_ids = set(parsed_eth.packets["frame_id"].to_list())
        assert arp_frame_ids.isdisjoint(ip_frame_ids)

    def test_ip_frames_have_ethernet_row(self, parsed_eth):
        # frame_id 0 (Ether/IP/UDP) and 3 (Ether/VLAN/IP/TCP) are in packets
        ip_frame_ids = set(parsed_eth.packets["frame_id"].to_list())
        eth_frame_ids = set(parsed_eth.ethernet_frames["frame_id"].to_list())
        assert ip_frame_ids.issubset(eth_frame_ids)

    def test_l3_analysis_works_for_ethernet_capture(self, parsed_eth):
        # IP-bearing Ethernet frames still produce packets rows
        assert len(parsed_eth.packets) == 2  # Ether/IP/UDP + VLAN/IP/TCP

    def test_link_type_is_ethernet(self, parsed_eth):
        assert parsed_eth.link_type == 1  # DLT_EN10MB

    def test_has_radiotap_false_for_ethernet(self, parsed_eth):
        assert parsed_eth.has_radiotap is False

    def test_wifi_fields_null_for_ethernet(self, parsed_eth):
        assert parsed_eth.signal_dbm is None
        assert parsed_eth.channel is None
        assert parsed_eth.data_rate_mbps is None


_RT_SIGNAL_DBM = -65
_RT_CHANNEL_FREQ = 2437  # channel 6
_RT_RATE_RAW = 108  # 108 * 0.5 = 54 Mbps
_RT_EXPECTED_CHANNEL = 6
_RT_EXPECTED_RATE_MBPS = 54.0
_RT_LINKTYPE = 127  # DLT_IEEE802_11_RADIO


class TestRadiotapParsing:
    @pytest.fixture(scope="class")
    def radiotap_pcap(self, tmp_path_factory):
        tmp_path = tmp_path_factory.mktemp("rt_pcap")
        pcap_path = tmp_path / "radiotap.pcap"
        pkts = [
            RadioTap(
                present="Rate+Channel+dBm_AntSignal",
                Rate=_RT_RATE_RAW,
                ChannelFrequency=_RT_CHANNEL_FREQ,
                dBm_AntSignal=_RT_SIGNAL_DBM,
            )
            / Dot11()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=1234, dport=80, flags="S"),
        ]
        wrpcap(str(pcap_path), pkts)
        return pcap_path

    @pytest.fixture(scope="class")
    def parsed_rt(self, radiotap_pcap):
        from pcap_agent import parser

        return parser.parse(radiotap_pcap)

    def test_link_type_is_radiotap(self, parsed_rt):
        assert parsed_rt.link_type == _RT_LINKTYPE

    def test_has_radiotap_true(self, parsed_rt):
        assert parsed_rt.has_radiotap is True

    def test_signal_dbm(self, parsed_rt):
        assert parsed_rt.signal_dbm == float(_RT_SIGNAL_DBM)

    def test_channel(self, parsed_rt):
        assert parsed_rt.channel == _RT_EXPECTED_CHANNEL

    def test_data_rate_mbps(self, parsed_rt):
        assert parsed_rt.data_rate_mbps == _RT_EXPECTED_RATE_MBPS


class TestRawIpLinkType:
    def test_link_type_is_integer(self, parsed_pcap):
        assert isinstance(parsed_pcap.link_type, int)

    def test_has_radiotap_false(self, parsed_pcap):
        assert parsed_pcap.has_radiotap is False

    def test_wifi_fields_null(self, parsed_pcap):
        assert parsed_pcap.signal_dbm is None
        assert parsed_pcap.channel is None
        assert parsed_pcap.data_rate_mbps is None
