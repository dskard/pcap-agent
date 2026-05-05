"""Integration tests for tools.layer2: get_layer2_summary."""

import duckdb
import pytest
from scapy.all import (  # type: ignore[import-untyped]
    ARP,
    IP,
    TCP,
    UDP,
    Dot1Q,
    Ether,
    Raw,
    wrpcap,
)

from pcap_agent import db
from pcap_agent.tools import _state
from pcap_agent.tools.layer2 import get_layer2_summary

_ETH_SRC_A = "aa:bb:cc:dd:ee:01"
_ETH_DST_A = "11:22:33:44:55:01"
_ARP_SRC_MAC = "aa:bb:cc:dd:ee:02"
_ARP_DST_MAC = "ff:ff:ff:ff:ff:ff"
_ARP_REP_SRC = "aa:bb:cc:dd:ee:03"
_ARP_REP_DST = "aa:bb:cc:dd:ee:02"
_ARP_SRC_IP = "192.168.10.1"
_ARP_DST_IP = "192.168.10.2"
_VLAN_ID = 100
_ETH_IP_SRC = "10.20.0.1"
_ETH_IP_DST = "10.20.0.2"
_VLAN_IP_SRC = "10.30.0.1"
_VLAN_IP_DST = "10.30.0.2"

_ETH_FRAME_COUNT = 4
_IP_FRAME_COUNT = 2  # only IP-bearing frames land in the packets table
_ARP_REQUEST_COUNT = 1
_ARP_REPLY_COUNT = 1
_UNIQUE_SRC_MACS = 3  # _ETH_SRC_A (x2), _ARP_SRC_MAC, _ARP_REP_SRC
_UNIQUE_DST_MACS = 3  # _ETH_DST_A (x2), _ARP_DST_MAC, _ARP_REP_DST
_LINK_TYPE_ETHERNET = 1


@pytest.fixture(scope="class")
def eth_pcap(tmp_path_factory):
    """Write a small Ethernet PCAP with ARP and VLAN frames."""
    tmp_path = tmp_path_factory.mktemp("eth_l2")
    pcap_path = tmp_path / "ethernet.pcap"
    pkts = [
        Ether(src=_ETH_SRC_A, dst=_ETH_DST_A)
        / IP(src=_ETH_IP_SRC, dst=_ETH_IP_DST)
        / UDP(sport=1234, dport=5678)
        / Raw(load=b"hello"),
        Ether(src=_ARP_SRC_MAC, dst=_ARP_DST_MAC)
        / ARP(
            op=1,
            hwsrc=_ARP_SRC_MAC,
            psrc=_ARP_SRC_IP,
            hwdst=_ARP_DST_MAC,
            pdst=_ARP_DST_IP,
        ),
        Ether(src=_ARP_REP_SRC, dst=_ARP_REP_DST)
        / ARP(
            op=2,
            hwsrc=_ARP_REP_SRC,
            psrc=_ARP_DST_IP,
            hwdst=_ARP_REP_DST,
            pdst=_ARP_SRC_IP,
        ),
        Ether(src=_ETH_SRC_A, dst=_ETH_DST_A)
        / Dot1Q(vlan=_VLAN_ID)
        / IP(src=_VLAN_IP_SRC, dst=_VLAN_IP_DST)
        / TCP(sport=9000, dport=80, flags="S"),
    ]
    wrpcap(str(pcap_path), pkts)
    return pcap_path


@pytest.fixture()
def eth_conn(eth_pcap):
    """Ingest the Ethernet PCAP into an in-memory DB and set the _state singleton."""
    from pcap_agent import parser

    conn = duckdb.connect(":memory:")
    db.create_schema(conn)
    parsed = parser.parse(eth_pcap)
    db.ingest(conn, parsed)
    db.set_capture_info(
        conn,
        sha256="test-sha256",
        link_type=parsed.link_type,
        has_radiotap=parsed.has_radiotap,
        signal_dbm=parsed.signal_dbm,
        channel=parsed.channel,
        data_rate_mbps=parsed.data_rate_mbps,
    )
    old = _state.get_connection()
    old_path = _state.get_db_path()
    _state.set_connection(conn, ":memory:")
    yield conn
    _state.set_connection(old, old_path) if old else _state.reset()
    conn.close()


class TestGetLayer2SummaryEthernetCapture:
    def test_returns_dict(self, eth_conn):
        result = get_layer2_summary()
        assert isinstance(result, dict)

    def test_no_error_key(self, eth_conn):
        result = get_layer2_summary()
        assert "error" not in result

    def test_link_type(self, eth_conn):
        result = get_layer2_summary()
        assert result["link_type"] == _LINK_TYPE_ETHERNET

    def test_has_radiotap_false(self, eth_conn):
        result = get_layer2_summary()
        assert result["has_radiotap"] is False

    def test_total_frame_count(self, eth_conn):
        result = get_layer2_summary()
        assert result["total_frame_count"] == _IP_FRAME_COUNT

    def test_ethernet_frame_count(self, eth_conn):
        result = get_layer2_summary()
        assert result["ethernet_frame_count"] == _ETH_FRAME_COUNT

    def test_arp_request_count(self, eth_conn):
        result = get_layer2_summary()
        assert result["arp_request_count"] == _ARP_REQUEST_COUNT

    def test_arp_reply_count(self, eth_conn):
        result = get_layer2_summary()
        assert result["arp_reply_count"] == _ARP_REPLY_COUNT

    def test_unique_src_mac_count(self, eth_conn):
        result = get_layer2_summary()
        assert result["unique_src_mac_count"] == _UNIQUE_SRC_MACS

    def test_unique_dst_mac_count(self, eth_conn):
        result = get_layer2_summary()
        assert result["unique_dst_mac_count"] == _UNIQUE_DST_MACS

    def test_distinct_vlan_ids(self, eth_conn):
        result = get_layer2_summary()
        assert result["distinct_vlan_ids"] == [_VLAN_ID]

    def test_top_5_src_macs_structure(self, eth_conn):
        result = get_layer2_summary()
        assert isinstance(result["top_5_src_macs"], list)
        assert all("mac" in r and "count" in r for r in result["top_5_src_macs"])

    def test_top_5_dst_macs_structure(self, eth_conn):
        result = get_layer2_summary()
        assert isinstance(result["top_5_dst_macs"], list)
        assert all("mac" in r and "count" in r for r in result["top_5_dst_macs"])

    def test_top_src_mac_is_most_frequent(self, eth_conn):
        result = get_layer2_summary()
        # _ETH_SRC_A appears in frames 0 and 3 (count=2)
        assert result["top_5_src_macs"][0]["mac"] == _ETH_SRC_A
        assert result["top_5_src_macs"][0]["count"] == 2

    def test_top_dst_mac_is_most_frequent(self, eth_conn):
        result = get_layer2_summary()
        # _ETH_DST_A appears in frames 0 and 3 (count=2)
        assert result["top_5_dst_macs"][0]["mac"] == _ETH_DST_A
        assert result["top_5_dst_macs"][0]["count"] == 2

    def test_result_keys(self, eth_conn):
        result = get_layer2_summary()
        expected_keys = {
            "link_type",
            "has_radiotap",
            "total_frame_count",
            "ethernet_frame_count",
            "arp_request_count",
            "arp_reply_count",
            "unique_src_mac_count",
            "unique_dst_mac_count",
            "distinct_vlan_ids",
            "top_5_src_macs",
            "top_5_dst_macs",
        }
        assert set(result.keys()) == expected_keys


class TestGetLayer2SummaryNoEthernetData:
    def test_returns_error_when_no_ethernet_frames(self, ingested_db):
        # The synthetic PCAP uses raw IP (no Ether layer), so ethernet_frames is empty.
        result = get_layer2_summary()
        assert "error" in result
        assert "hint" in result

    def test_error_message_mentions_ethernet(self, ingested_db):
        result = get_layer2_summary()
        assert "Ethernet" in result["error"] or "ethernet" in result["error"].lower()
