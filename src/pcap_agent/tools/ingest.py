"""Ingest tool: parse and persist a PCAP file, auto-run analysis."""

import hashlib
from pathlib import Path
from typing import Any

import duckdb

from pcap_agent import db, parser
from pcap_agent.config import config
from pcap_agent.tools import _state
from pcap_agent.tools.analysis import get_protocol_breakdown, get_top_talkers


def ingest_pcap(path: str | Path, db_dir: str | None = None) -> dict[str, Any]:
    """Ingest a PCAP file into DuckDB and return a summary dict.

    Returns cached results (cached=True) without re-parsing if the file was
    already ingested (same SHA256). Otherwise parses, persists, and auto-runs
    protocol breakdown and top-talker analysis.
    """
    pcap_path = Path(path)
    sha256 = _sha256(pcap_path)

    effective_db_dir = db_dir or config.pcap_agent_db_dir
    Path(effective_db_dir).mkdir(parents=True, exist_ok=True)
    db_path = str(Path(effective_db_dir) / f"{sha256[:12]}.duckdb")

    # Reuse the existing connection when the target file is already open to
    # avoid leaking the previous handle and conflicting with DuckDB's
    # single-writer constraint.
    if _state.get_db_path() == db_path and _state.get_connection() is not None:
        conn = _state.require_connection()
    else:
        old_conn = _state.get_connection()
        conn = duckdb.connect(db_path)
        try:
            db.create_schema(conn)
            _state.set_connection(conn, db_path)
        except Exception:
            conn.close()
            raise
        if old_conn is not None:
            old_conn.close()

    if db.get_cached(conn, sha256) is not None:
        return _summary(conn, sha256, db_path, cached=True)

    frames = parser.parse(pcap_path)
    conn.begin()
    try:
        db.ingest(conn, frames, begin_transaction=False)
        db.set_cached(conn, sha256, str(pcap_path))
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return _summary(conn, sha256, db_path, cached=False)


def _summary(
    conn: duckdb.DuckDBPyConnection,
    sha256: str,
    db_path: str,
    *,
    cached: bool,
) -> dict[str, Any]:
    n_packets = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    row = conn.execute(
        "SELECT MIN(timestamp), MAX(timestamp) FROM packets"
    ).fetchone()
    time_start, time_end = (row[0], row[1]) if row else (None, None)
    return {
        "cached": cached,
        "sha256": sha256,
        "n_packets": n_packets,
        "time_start": time_start,
        "time_end": time_end,
        "protocol_counts": get_protocol_breakdown(),
        "top_talkers": get_top_talkers(10),
        "db_path": db_path,
    }


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
