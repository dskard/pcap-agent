"""Layer 2 summary tool: link type, Ethernet, ARP, and MAC statistics."""

import logging

from pcap_agent.tools import _state

logger = logging.getLogger(__name__)


def get_layer2_summary() -> dict:
    """Return L2 statistics for the ingested capture.

    Fields: link_type, has_radiotap, ethernet_frame_count, ip_packet_count,
    arp_request_count, arp_reply_count, unique_src_mac_count,
    unique_dst_mac_count, distinct_vlan_ids, top_5_src_macs, top_5_dst_macs,
    avg_signal_dbm, min_signal_dbm, max_signal_dbm, distinct_channels,
    avg_data_rate_mbps (all signal fields are None when has_radiotap is False).

    Returns {"error": ..., "hint": ...} when no ethernet_frames rows exist.
    """
    conn = _state.require_connection()

    eth_count = conn.execute(
        "SELECT COUNT(*) FROM ethernet_frames"
    ).fetchone()[0]
    if eth_count == 0:
        return {
            "error": "No Ethernet frame data found",
            "hint": "This capture may use a non-Ethernet link type.",
        }

    ci = conn.execute(
        "SELECT link_type, has_radiotap FROM capture_info LIMIT 1"
    ).fetchone()
    link_type = ci[0] if ci else None
    has_radiotap = bool(ci[1]) if ci else False

    if has_radiotap:
        radio_row = conn.execute(
            "SELECT AVG(signal_dbm), MIN(signal_dbm), MAX(signal_dbm),"
            " AVG(data_rate_mbps) FROM radiotap_frames"
        ).fetchone()
        channel_rows = conn.execute(
            "SELECT DISTINCT channel FROM radiotap_frames"
            " WHERE channel IS NOT NULL ORDER BY channel"
        ).fetchall()
        avg_signal_dbm = radio_row[0]
        min_signal_dbm = radio_row[1]
        max_signal_dbm = radio_row[2]
        avg_data_rate_mbps = radio_row[3]
        distinct_channels = [r[0] for r in channel_rows]
    else:
        avg_signal_dbm = min_signal_dbm = max_signal_dbm = avg_data_rate_mbps = None
        distinct_channels = []

    arp_counts = conn.execute(
        "SELECT operation, COUNT(*) FROM arp_packets GROUP BY operation"
    ).fetchall()
    arp_by_op = {op: cnt for op, cnt in arp_counts}

    unique_src = conn.execute(
        "SELECT COUNT(DISTINCT src_mac) FROM ethernet_frames"
    ).fetchone()[0]
    unique_dst = conn.execute(
        "SELECT COUNT(DISTINCT dst_mac) FROM ethernet_frames"
    ).fetchone()[0]

    vlan_rows = conn.execute(
        "SELECT DISTINCT vlan_id FROM ethernet_frames"
        " WHERE vlan_id IS NOT NULL ORDER BY vlan_id"
    ).fetchall()
    distinct_vlan_ids = [r[0] for r in vlan_rows]

    top_src = conn.execute(
        "SELECT src_mac, COUNT(*) AS cnt FROM ethernet_frames"
        " GROUP BY src_mac ORDER BY cnt DESC LIMIT 5"
    ).fetchall()
    top_dst = conn.execute(
        "SELECT dst_mac, COUNT(*) AS cnt FROM ethernet_frames"
        " GROUP BY dst_mac ORDER BY cnt DESC LIMIT 5"
    ).fetchall()

    ip_count = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]

    result = {
        "link_type": link_type,
        "has_radiotap": has_radiotap,
        "ethernet_frame_count": eth_count,
        "ip_packet_count": ip_count,
        "arp_request_count": arp_by_op.get(1, 0),
        "arp_reply_count": arp_by_op.get(2, 0),
        "unique_src_mac_count": unique_src,
        "unique_dst_mac_count": unique_dst,
        "distinct_vlan_ids": distinct_vlan_ids,
        "top_5_src_macs": [{"mac": r[0], "count": r[1]} for r in top_src],
        "top_5_dst_macs": [{"mac": r[0], "count": r[1]} for r in top_dst],
        "avg_signal_dbm": avg_signal_dbm,
        "min_signal_dbm": min_signal_dbm,
        "max_signal_dbm": max_signal_dbm,
        "distinct_channels": distinct_channels,
        "avg_data_rate_mbps": avg_data_rate_mbps,
    }
    logger.debug("get_layer2_summary: %d ethernet frames", eth_count)
    return result
