"""Detection tools: port scan and anomaly detection."""

from __future__ import annotations

import logging

import numpy as np
from sklearn.ensemble import IsolationForest

from pcap_agent import telemetry
from pcap_agent.tools import _state

logger = logging.getLogger(__name__)

_PORT_SCAN_SQL = """
WITH port_contacts AS (
    SELECT p.src_ip, t.dport
    FROM packets p JOIN tcp_segments t ON p.packet_id = t.packet_id
    UNION ALL
    SELECT p.src_ip, u.dport
    FROM packets p JOIN udp_datagrams u ON p.packet_id = u.packet_id
)
SELECT src_ip, COUNT(DISTINCT dport) AS distinct_ports
FROM port_contacts
GROUP BY src_ip
ORDER BY distinct_ports DESC
"""

_ANOMALY_SQL = """
WITH payload_sizes AS (
    SELECT packet_id, OCTET_LENGTH(payload) AS payload_size FROM tcp_segments
    UNION ALL
    SELECT packet_id, OCTET_LENGTH(payload) AS payload_size FROM udp_datagrams
    UNION ALL
    SELECT packet_id, OCTET_LENGTH(payload) AS payload_size FROM icmp_messages
),
enriched AS (
    SELECT
        p.packet_id,
        p.timestamp,
        p.src_ip,
        p.dst_ip,
        p.protocol,
        p.length,
        COALESCE(ps.payload_size, 0) AS payload_size,
        COALESCE(
            p.timestamp - LAG(p.timestamp) OVER (ORDER BY p.timestamp, p.packet_id),
            0.0
        ) AS inter_arrival
    FROM packets p
    LEFT JOIN payload_sizes ps ON p.packet_id = ps.packet_id
)
SELECT
    packet_id, timestamp, src_ip, dst_ip,
    protocol, length, payload_size, inter_arrival
FROM enriched
ORDER BY timestamp
"""

_ANOMALY_COLS = [
    "packet_id", "timestamp", "src_ip", "dst_ip",
    "protocol", "length", "payload_size", "inter_arrival",
]


def detect_port_scans(threshold: int = 10) -> list[dict] | dict:
    """Find source IPs contacting many distinct destination ports.

    Classifies each result as Suspicious (>= threshold), Elevated
    (>= threshold // 2), or Normal.
    """
    if threshold <= 0:
        return {
            "error": "threshold must be a positive integer",
            "hint": "Use threshold >= 1",
        }

    logger.debug("detect_port_scans: threshold=%d", threshold)
    conn = _state.require_connection()
    rows = conn.execute(_PORT_SCAN_SQL).fetchall()

    half = max(1, threshold // 2)
    result = []
    for src_ip, distinct_ports in rows:
        if distinct_ports >= threshold:
            classification = "Suspicious"
        elif distinct_ports >= half:
            classification = "Elevated"
        else:
            classification = "Normal"
        result.append(
            {
                "src_ip": src_ip,
                "distinct_ports": int(distinct_ports),
                "classification": classification,
            }
        )
    suspicious_count = sum(1 for r in result if r["classification"] == "Suspicious")
    logger.info("detect_port_scans: found %d suspicious IP(s)", suspicious_count)
    return result


def detect_anomalies(contamination: float = 0.02) -> list[dict] | dict:
    """Detect anomalous packets using IsolationForest on four packet features.

    Features: packet size, protocol integer, inter-arrival time, payload size.
    Uses 200 estimators and random_state=42 for reproducibility.
    """
    if not (0.0 < contamination < 0.5):
        return {
            "error": "contamination must be in the open interval (0, 0.5)",
            "hint": "Try contamination=0.02",
        }

    logger.debug("detect_anomalies: contamination=%s", contamination)
    conn = _state.require_connection()
    rows = conn.execute(_ANOMALY_SQL).fetchall()

    if not rows:
        return []

    records = [dict(zip(_ANOMALY_COLS, row)) for row in rows]

    X = np.array(
        [
            [r["length"], r["protocol"], r["inter_arrival"], r["payload_size"]]
            for r in records
        ],
        dtype=float,
    )

    clf = IsolationForest(
        n_estimators=200, contamination=contamination, random_state=42
    )
    labels = clf.fit_predict(X)
    scores = clf.score_samples(X)

    anomalies = [
        {**rec, "anomaly_score": round(float(score), 6)}
        for rec, label, score in zip(records, labels, scores)
        if label == -1
    ]
    logger.info("detect_anomalies: flagged %d anomalous packet(s)", len(anomalies))
    telemetry.record_anomalies_detected(len(anomalies))
    return anomalies
