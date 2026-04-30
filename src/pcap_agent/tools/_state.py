"""Module-level DuckDB connection shared across all tools."""

from __future__ import annotations

import duckdb

_conn: duckdb.DuckDBPyConnection | None = None
_db_path: str | None = None


def set_connection(conn: duckdb.DuckDBPyConnection, db_path: str) -> None:
    global _conn, _db_path
    _conn = conn
    _db_path = db_path


def require_connection() -> duckdb.DuckDBPyConnection:
    if _conn is None:
        raise RuntimeError("No PCAP ingested yet. Call ingest_pcap() first.")
    return _conn


def get_db_path() -> str | None:
    return _db_path


def reset(
    conn: duckdb.DuckDBPyConnection | None = None,
    db_path: str | None = None,
) -> None:
    global _conn, _db_path
    _conn = conn
    _db_path = db_path
