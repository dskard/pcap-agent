"""Integration tests for tools.detection: detect_port_scans, detect_anomalies."""

from constants import (
    ANOMALY_PACKET_COUNT,
    ANOMALY_SRC_IP,
    SCAN_PORT_COUNT,
    SCANNER_IP,
)

from pcap_agent.tools.detection import detect_anomalies, detect_port_scans


class TestDetectPortScans:
    def test_scanner_ip_is_suspicious(self, ingested_db):
        results = detect_port_scans(threshold=10)
        scanner = next(r for r in results if r["src_ip"] == SCANNER_IP)
        assert scanner["classification"] == "Suspicious"

    def test_scanner_distinct_ports(self, ingested_db):
        results = detect_port_scans(threshold=10)
        scanner = next(r for r in results if r["src_ip"] == SCANNER_IP)
        assert scanner["distinct_ports"] == SCAN_PORT_COUNT

    def test_classification_labels_are_valid(self, ingested_db):
        results = detect_port_scans(threshold=10)
        valid = {"Suspicious", "Elevated", "Normal"}
        for r in results:
            assert r["classification"] in valid

    def test_result_keys(self, ingested_db):
        results = detect_port_scans(threshold=10)
        assert len(results) > 0
        assert set(results[0].keys()) == {"src_ip", "distinct_ports", "classification"}

    def test_sorted_descending_by_distinct_ports(self, ingested_db):
        results = detect_port_scans(threshold=10)
        counts = [r["distinct_ports"] for r in results]
        assert counts == sorted(counts, reverse=True)

    def test_elevated_classification(self, ingested_db):
        # With threshold=40, scanner (20 ports) falls in Elevated (>= 20)
        results = detect_port_scans(threshold=40)
        scanner = next(r for r in results if r["src_ip"] == SCANNER_IP)
        assert scanner["classification"] == "Elevated"

    def test_invalid_threshold_returns_error(self, ingested_db):
        result = detect_port_scans(threshold=0)
        assert "error" in result

    def test_returns_list(self, ingested_db):
        result = detect_port_scans(threshold=10)
        assert isinstance(result, list)


class TestDetectAnomalies:
    def test_flags_anomalous_packets(self, ingested_db):
        # contamination=0.03 is the threshold at which all 5 oversized anomaly
        # packets (payload=9000B) score anomalously enough to be flagged.
        result = detect_anomalies(contamination=0.03)
        flagged = [r for r in result if r["src_ip"] == ANOMALY_SRC_IP]
        assert len(flagged) >= ANOMALY_PACKET_COUNT

    def test_anomaly_src_ip_present(self, ingested_db):
        result = detect_anomalies(contamination=0.03)
        src_ips = {r["src_ip"] for r in result}
        assert ANOMALY_SRC_IP in src_ips

    def test_contamination_respected(self, ingested_db):
        low = detect_anomalies(contamination=0.01)
        high = detect_anomalies(contamination=0.1)
        assert len(high) >= len(low)

    def test_result_keys(self, ingested_db):
        result = detect_anomalies(contamination=0.02)
        assert len(result) > 0
        expected = {
            "frame_id", "timestamp", "src_ip", "dst_ip",
            "protocol", "length", "payload_size", "inter_arrival", "anomaly_score",
        }
        assert set(result[0].keys()) == expected

    def test_anomaly_score_is_float(self, ingested_db):
        result = detect_anomalies(contamination=0.02)
        for r in result:
            assert isinstance(r["anomaly_score"], float)

    def test_returns_list(self, ingested_db):
        result = detect_anomalies(contamination=0.02)
        assert isinstance(result, list)

    def test_invalid_contamination_returns_error(self, ingested_db):
        result = detect_anomalies(contamination=0.0)
        assert "error" in result

    def test_invalid_contamination_too_high(self, ingested_db):
        result = detect_anomalies(contamination=0.5)
        assert "error" in result
