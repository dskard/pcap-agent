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

CREATE TABLE IF NOT EXISTS pcap_meta (
    sha256 VARCHAR PRIMARY KEY,
    pcap_path VARCHAR,
    ingested_at TIMESTAMP DEFAULT current_timestamp
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


def set_cached(
    conn: duckdb.DuckDBPyConnection, sha256: str, pcap_path: str
) -> None:
    """Insert sha256 and pcap_path into pcap_meta; no-op if sha256 already exists."""
    conn.execute(
        "INSERT INTO pcap_meta (sha256, pcap_path) VALUES (?, ?)"
        " ON CONFLICT (sha256) DO NOTHING",
        [sha256, pcap_path],
    )


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
