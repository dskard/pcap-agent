"""Query tool: validate and execute SQL against the DuckDB packet database."""

from __future__ import annotations

import re
from typing import Any

import duckdb

from pcap_agent.tools import _state

_MAX_ROWS = 500

# Statements allowed to execute against the packet database.
_ALLOWED_STMT_RE = re.compile(
    r"^\s*(SELECT|WITH|CREATE\s+TEMP\s+VIEW|CREATE\s+TEMPORARY\s+VIEW)\b",
    re.IGNORECASE,
)


def query(sql: str) -> dict[str, Any]:
    """Execute a SQL statement and return up to 500 rows as a list of dicts.

    Only SELECT and CREATE TEMP VIEW statements are permitted. All others are
    rejected before execution with a structured error dict. Malformed SQL that
    DuckDB cannot parse also returns a structured error dict. Unexpected
    exceptions propagate.

    Return shape on success:
        {"rows": [...], "truncated": bool, "row_count": int}

    Return shape on error:
        {"error": str, "hint": str}
    """
    if not _ALLOWED_STMT_RE.match(sql):
        stmt_type = sql.strip().split()[0].upper() if sql.strip() else "(empty)"
        return {
            "error": f"Statement type '{stmt_type}' is not allowed.",
            "hint": "Only SELECT and CREATE TEMP VIEW statements are permitted.",
        }

    conn = _state.require_connection()

    try:
        relation = conn.execute(sql)
    except duckdb.Error as exc:
        return {
            "error": str(exc),
            "hint": "Check your SQL syntax and column/table names.",
        }

    if relation is None:
        # CREATE TEMP VIEW succeeds with no result set
        return {"rows": [], "truncated": False, "row_count": 0}

    columns = [desc[0] for desc in relation.description]
    fetched = relation.fetchmany(_MAX_ROWS + 1)

    truncated = len(fetched) > _MAX_ROWS
    rows = fetched[:_MAX_ROWS]

    return {
        "rows": [dict(zip(columns, row)) for row in rows],
        "truncated": truncated,
        "row_count": len(rows),
    }
