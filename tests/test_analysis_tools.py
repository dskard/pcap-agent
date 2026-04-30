"""Integration tests for tools.analysis: get_top_talkers, get_protocol_breakdown."""

from constants import (
    ICMP_PACKET_COUNT,
    TCP_TOTAL,
    TOTAL_IP,
    UDP_PACKET_COUNT,
    UDP_TOP_TALKER_IP,
    UDP_TOTAL,
)

from pcap_agent.tools.analysis import get_protocol_breakdown, get_top_talkers


class TestGetTopTalkers:
    def test_top_talker_is_heavy_udp_sender(self, ingested_db):
        talkers = get_top_talkers(1)
        assert talkers[0]["src_ip"] == UDP_TOP_TALKER_IP

    def test_top_talker_packet_count(self, ingested_db):
        talkers = get_top_talkers(1)
        assert talkers[0]["packet_count"] == UDP_PACKET_COUNT

    def test_returns_n_results(self, ingested_db):
        talkers = get_top_talkers(3)
        assert len(talkers) == 3

    def test_results_sorted_descending(self, ingested_db):
        talkers = get_top_talkers(10)
        counts = [t["packet_count"] for t in talkers]
        assert counts == sorted(counts, reverse=True)

    def test_result_keys(self, ingested_db):
        talkers = get_top_talkers(1)
        assert set(talkers[0].keys()) == {"src_ip", "packet_count"}


class TestGetProtocolBreakdown:
    def test_returns_list(self, ingested_db):
        result = get_protocol_breakdown()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_tcp_count(self, ingested_db):
        result = get_protocol_breakdown()
        tcp = next(r for r in result if r["protocol"] == "TCP")
        assert tcp["count"] == TCP_TOTAL

    def test_udp_count(self, ingested_db):
        result = get_protocol_breakdown()
        udp = next(r for r in result if r["protocol"] == "UDP")
        assert udp["count"] == UDP_TOTAL

    def test_icmp_count(self, ingested_db):
        result = get_protocol_breakdown()
        icmp = next(r for r in result if r["protocol"] == "ICMP")
        assert icmp["count"] == ICMP_PACKET_COUNT

    def test_total_equals_all_packets(self, ingested_db):
        result = get_protocol_breakdown()
        total = sum(r["count"] for r in result)
        assert total == TOTAL_IP

    def test_sorted_descending(self, ingested_db):
        result = get_protocol_breakdown()
        counts = [r["count"] for r in result]
        assert counts == sorted(counts, reverse=True)

    def test_result_keys(self, ingested_db):
        result = get_protocol_breakdown()
        assert set(result[0].keys()) == {"protocol", "count", "pct"}

    def test_pct_sums_to_100(self, ingested_db):
        result = get_protocol_breakdown()
        total_pct = sum(r["pct"] for r in result)
        assert abs(total_pct - 100.0) < 0.2
