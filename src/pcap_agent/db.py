"""DuckDB connection lifecycle, schema management, and DataFrame ingestion."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import duckdb

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from pcap_agent.parser import ParsedPcap

_DDL = """
CREATE TABLE IF NOT EXISTS packets (
    frame_id BIGINT PRIMARY KEY,
    timestamp DOUBLE,
    src_ip VARCHAR,
    dst_ip VARCHAR,
    protocol INTEGER,
    length INTEGER,
    ttl INTEGER
);

CREATE TABLE IF NOT EXISTS tcp_segments (
    frame_id BIGINT,
    sport INTEGER,
    dport INTEGER,
    flags VARCHAR,
    seq BIGINT,
    ack BIGINT,
    payload BLOB
);

CREATE TABLE IF NOT EXISTS udp_datagrams (
    frame_id BIGINT,
    sport INTEGER,
    dport INTEGER,
    payload BLOB
);

CREATE TABLE IF NOT EXISTS icmp_messages (
    frame_id BIGINT,
    type INTEGER,
    code INTEGER,
    payload BLOB
);

CREATE TABLE IF NOT EXISTS ethernet_frames (
    frame_id   BIGINT PRIMARY KEY,
    src_mac    VARCHAR,
    dst_mac    VARCHAR,
    ethertype  INTEGER,
    vlan_id    INTEGER
);

CREATE TABLE IF NOT EXISTS arp_packets (
    frame_id    BIGINT PRIMARY KEY,
    hw_type     INTEGER,
    proto_type  INTEGER,
    operation   INTEGER,
    sender_mac  VARCHAR,
    sender_ip   VARCHAR,
    target_mac  VARCHAR,
    target_ip   VARCHAR
);

CREATE TABLE IF NOT EXISTS pcap_meta (
    sha256 VARCHAR PRIMARY KEY,
    pcap_path VARCHAR,
    ingested_at TIMESTAMP DEFAULT current_timestamp
);

CREATE TABLE IF NOT EXISTS capture_info (
    sha256          VARCHAR PRIMARY KEY,
    link_type       INTEGER,
    has_radiotap    BOOLEAN
);

CREATE TABLE IF NOT EXISTS radiotap_frames (
    frame_id        BIGINT PRIMARY KEY,
    signal_dbm      DOUBLE,
    channel         INTEGER,
    data_rate_mbps  DOUBLE
);
"""


def create_schema(conn: duckdb.DuckDBPyConnection) -> None:
    """Create all normalized tables and the pcap_meta cache table."""
    logger.debug("Creating database schema")
    conn.execute(_DDL)


def ingest(
    conn: duckdb.DuckDBPyConnection,
    frames: ParsedPcap,
    *,
    begin_transaction: bool = True,
) -> None:
    """Insert parsed DataFrames into the database tables.

    When begin_transaction is True (default), ingest() opens and commits its
    own transaction, rolling back on failure.  Pass begin_transaction=False
    when the caller has already opened a transaction and wants ingest() to
    participate without touching commit/rollback — the caller is then
    responsible for commit and rollback.
    """
    if begin_transaction:
        conn.begin()
    try:
        _load_df(conn, "packets", frames.packets)
        _load_df(conn, "tcp_segments", frames.tcp_segments)
        _load_df(conn, "udp_datagrams", frames.udp_datagrams)
        _load_df(conn, "icmp_messages", frames.icmp_messages)
        _load_df(conn, "ethernet_frames", frames.ethernet_frames)
        _load_df(conn, "arp_packets", frames.arp_packets)
        _load_df(conn, "radiotap_frames", frames.radiotap_frames)
        if begin_transaction:
            conn.commit()
    except Exception:
        if begin_transaction:
            conn.rollback()
        raise


def _load_df(
    conn: duckdb.DuckDBPyConnection, table: str, df: Any
) -> None:
    if df.is_empty():
        return
    cols = ", ".join(f'"{c}"' for c in df.columns)
    placeholders = ", ".join(["?" for _ in df.columns])
    conn.executemany(
        f'INSERT INTO "{table}" ({cols}) VALUES ({placeholders})', df.rows()
    )


def set_capture_info(
    conn: duckdb.DuckDBPyConnection,
    sha256: str,
    link_type: int,
    has_radiotap: bool,
) -> None:
    """Insert or replace the capture_info row for sha256."""
    conn.execute(
        "INSERT INTO capture_info"
        " (sha256, link_type, has_radiotap)"
        " VALUES (?, ?, ?)"
        " ON CONFLICT (sha256) DO UPDATE SET"
        "   link_type = EXCLUDED.link_type,"
        "   has_radiotap = EXCLUDED.has_radiotap",
        [sha256, link_type, has_radiotap],
    )


def set_cached(
    conn: duckdb.DuckDBPyConnection, sha256: str, pcap_path: str
) -> None:
    """Insert sha256 and pcap_path into pcap_meta; no-op if sha256 already exists."""
    conn.execute(
        "INSERT INTO pcap_meta (sha256, pcap_path) VALUES (?, ?)"
        " ON CONFLICT (sha256) DO NOTHING",
        [sha256, pcap_path],
    )


_REQUIRED_TABLES = {"ethernet_frames", "arp_packets", "capture_info", "radiotap_frames"}

_DATA_TABLES = [
    "packets",
    "tcp_segments",
    "udp_datagrams",
    "icmp_messages",
    "ethernet_frames",
    "arp_packets",
    "capture_info",
    "radiotap_frames",
    "pcap_meta",
]


def is_schema_stale(conn: duckdb.DuckDBPyConnection) -> bool:
    """Return True if any of the new tables are missing from the database."""
    rows = conn.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
    ).fetchall()
    existing = {r[0] for r in rows}
    return not _REQUIRED_TABLES.issubset(existing)


def clear_data(conn: duckdb.DuckDBPyConnection, sha256: str) -> None:
    """Delete all rows from data tables and remove the pcap_meta cache entry.

    Used when a stale cache is detected so that re-ingest starts clean.
    """
    conn.execute("DELETE FROM pcap_meta WHERE sha256 = ?", [sha256])
    for table in _DATA_TABLES:
        if table == "pcap_meta":
            continue
        try:
            conn.execute(f'DELETE FROM "{table}"')
        except Exception as e:
            logger.warning("Failed to clear table %s: %s", table, e)


def get_cached(
    conn: duckdb.DuckDBPyConnection, sha256: str
) -> dict[str, Any] | None:
    """Return the pcap_meta row for sha256, or None if not cached."""
    row = conn.execute(
        "SELECT sha256, pcap_path, ingested_at FROM pcap_meta WHERE sha256 = ?",
        [sha256],
    ).fetchone()
    if row is None:
        logger.debug("Cache miss for sha256=%s", sha256)
        return None
    logger.debug("Cache hit for sha256=%s path=%s", sha256, row[1])
    return {"sha256": row[0], "pcap_path": row[1], "ingested_at": row[2]}
