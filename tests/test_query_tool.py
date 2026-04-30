"""Integration tests for tools.query: SQL guardrails and result handling."""

import pytest
from constants import TOTAL_FRAMES

from pcap_agent.tools import _state
from pcap_agent.tools.query import _MAX_ROWS, query


class TestSelectQueries:
    def test_select_returns_list_of_dicts(self, ingested_db):
        result = query("SELECT src_ip, dst_ip FROM packets LIMIT 5")
        assert isinstance(result["rows"], list)
        assert len(result["rows"]) == 5
        assert set(result["rows"][0].keys()) == {"src_ip", "dst_ip"}

    def test_select_all_returns_up_to_max_rows(self, ingested_db):
        result = query("SELECT * FROM packets")
        assert result["row_count"] <= _MAX_ROWS

    def test_truncation_flag_false_when_within_limit(self, ingested_db):
        # TOTAL_FRAMES (278) < _MAX_ROWS (500), so no truncation expected.
        assert TOTAL_FRAMES < _MAX_ROWS
        result = query("SELECT * FROM packets")
        assert result["truncated"] is False
        assert result["row_count"] == TOTAL_FRAMES

    def test_truncation_flag_true_when_over_limit(self, ingested_db):
        # Build a large synthetic result by cross-joining packets with itself.
        sql = (
            "SELECT a.src_ip FROM packets a "
            "CROSS JOIN packets b "
            f"LIMIT {_MAX_ROWS + 10}"
        )
        result = query(sql)
        assert result["truncated"] is True
        assert result["row_count"] == _MAX_ROWS

    def test_row_count_matches_rows_length(self, ingested_db):
        result = query("SELECT * FROM packets LIMIT 10")
        assert result["row_count"] == len(result["rows"])

    def test_with_clause_allowed(self, ingested_db):
        sql = "WITH t AS (SELECT src_ip FROM packets LIMIT 3) SELECT * FROM t"
        result = query(sql)
        assert "error" not in result
        assert len(result["rows"]) == 3


class TestCreateTempView:
    def test_create_temp_view_succeeds(self, ingested_db):
        sql = "CREATE TEMP VIEW tcp_only AS SELECT * FROM packets WHERE protocol = 6"
        result = query(sql)
        assert "error" not in result
        assert result["rows"] == []
        assert result["truncated"] is False


class TestRejectedStatements:
    def test_drop_table_rejected(self, ingested_db):
        result = query("DROP TABLE packets")
        assert "error" in result
        assert "hint" in result
        assert "DROP" in result["error"]

    def test_insert_rejected(self, ingested_db):
        result = query("INSERT INTO packets SELECT * FROM packets LIMIT 1")
        assert "error" in result
        assert "hint" in result
        assert "INSERT" in result["error"]

    def test_update_rejected(self, ingested_db):
        result = query("UPDATE packets SET src_ip = '0.0.0.0'")
        assert "error" in result
        assert "hint" in result

    def test_delete_rejected(self, ingested_db):
        result = query("DELETE FROM packets WHERE 1=1")
        assert "error" in result
        assert "hint" in result


class TestMalformedSQL:
    def test_bad_syntax_returns_error_dict(self, ingested_db):
        result = query("SELECT FROM WHERE")
        assert "error" in result
        assert "hint" in result

    def test_unknown_column_returns_error_dict(self, ingested_db):
        result = query("SELECT nonexistent_column FROM packets")
        assert "error" in result
        assert "hint" in result

    def test_unknown_table_returns_error_dict(self, ingested_db):
        result = query("SELECT * FROM no_such_table")
        assert "error" in result
        assert "hint" in result


class TestNoConnection:
    def test_raises_when_no_connection(self):
        original_conn = _state.get_connection()
        original_path = _state.get_db_path()
        _state.reset()
        try:
            with pytest.raises(RuntimeError, match="No PCAP ingested yet"):
                query("SELECT 1")
        finally:
            if original_conn is not None:
                _state.set_connection(original_conn, original_path)
