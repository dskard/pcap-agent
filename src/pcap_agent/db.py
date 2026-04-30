"""DuckDB connection lifecycle, schema management, and DataFrame ingestion."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import duckdb

if TYPE_CHECKING:
    from pcap_agent.parser import ParsedPcap

_DDL = """
CREATE TABLE IF NOT EXISTS packets (
    packet_id BIGINT PRIMARY KEY,
    timestamp DOUBLE,
    src_ip VARCHAR,
    dst_ip VARCHAR,
    protocol INTEGER,
    length INTEGER,
    ttl INTEGER
);

CREATE TABLE IF NOT EXISTS tcp_segments (
    packet_id BIGINT,
    sport INTEGER,
    dport INTEGER,
    flags VARCHAR,
    seq BIGINT,
    ack BIGINT,
    payload BLOB
);

CREATE TABLE IF NOT EXISTS udp_datagrams (
    packet_id BIGINT,
    sport INTEGER,
    dport INTEGER,
    payload BLOB
);

CREATE TABLE IF NOT EXISTS icmp_messages (
    packet_id BIGINT,
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
    conn.execute(_DDL)


def ingest(conn: duckdb.DuckDBPyConnection, frames: ParsedPcap) -> None:
    """Insert parsed DataFrames into the database tables.

    Opens its own transaction when the connection is not already inside one.
    If the caller has an active transaction, ingest() participates in it
    without touching commit/rollback — the caller remains responsible.
    """
    try:
        conn.begin()
        own_txn = True
    except duckdb.TransactionException:
        own_txn = False
    try:
        _load_df(conn, "packets", frames.packets)
        _load_df(conn, "tcp_segments", frames.tcp_segments)
        _load_df(conn, "udp_datagrams", frames.udp_datagrams)
        _load_df(conn, "icmp_messages", frames.icmp_messages)
        if own_txn:
            conn.commit()
    except Exception:
        if own_txn:
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
        f"INSERT INTO {table} ({cols}) VALUES ({placeholders})", df.rows()
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
        return None
    return {"sha256": row[0], "pcap_path": row[1], "ingested_at": row[2]}
