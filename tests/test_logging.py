"""Tests verifying structured logging in agent.py, analysis.py, and query.py."""

import logging

from pcap_agent.tools.analysis import get_protocol_breakdown, get_top_talkers
from pcap_agent.tools.query import query


class TestAgentLogging:
    def test_session_start_logged_at_info(self, caplog):
        from pcap_agent.agent import create_agent

        with caplog.at_level(logging.INFO, logger="pcap_agent.agent"):
            create_agent(api_key="test-dummy-key", model="test-model")

        info_msgs = [r for r in caplog.records if r.levelno == logging.INFO]
        assert any("test-model" in r.message for r in info_msgs)

    def test_session_start_not_logged_at_warning(self, caplog):
        from pcap_agent.agent import create_agent

        with caplog.at_level(logging.WARNING, logger="pcap_agent.agent"):
            create_agent(api_key="test-dummy-key", model="test-model")

        assert not any("test-model" in r.message for r in caplog.records)

    def test_tool_registrations_logged_at_debug(self, caplog):
        from pcap_agent.agent import create_agent

        with caplog.at_level(logging.DEBUG, logger="pcap_agent.agent"):
            create_agent(api_key="test-dummy-key", model="test-model")

        debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
        expected_tools = [
            "ingest_pcap",
            "get_protocol_breakdown",
            "get_top_talkers",
            "get_layer2_summary",
            "query",
            "detect_port_scans",
            "detect_anomalies",
            "reassemble_stream",
        ]
        for tool_name in expected_tools:
            assert any(tool_name in msg for msg in debug_msgs)

    def test_nine_tool_registrations_logged(self, caplog):
        from pcap_agent.agent import create_agent

        with caplog.at_level(logging.DEBUG, logger="pcap_agent.agent"):
            create_agent(api_key="test-dummy-key", model="test-model")

        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "pcap_agent.agent"
        ]
        assert len(debug_msgs) == 9

    def test_logger_uses_module_name(self):
        import pcap_agent.agent as agent_mod

        assert agent_mod.logger.name == "pcap_agent.agent"


class TestAnalysisLogging:
    def test_protocol_breakdown_logged_at_debug(self, ingested_db, caplog):
        with caplog.at_level(logging.DEBUG, logger="pcap_agent.tools.analysis"):
            result = get_protocol_breakdown()

        debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
        assert any(str(len(result)) in msg for msg in debug_msgs)

    def test_protocol_breakdown_not_logged_at_warning(self, ingested_db, caplog):
        with caplog.at_level(logging.WARNING, logger="pcap_agent.tools.analysis"):
            get_protocol_breakdown()

        assert not caplog.records

    def test_top_talkers_logged_at_debug(self, ingested_db, caplog):
        with caplog.at_level(logging.DEBUG, logger="pcap_agent.tools.analysis"):
            result = get_top_talkers(3)

        debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
        assert any("3" in msg for msg in debug_msgs)
        assert any(str(len(result)) in msg for msg in debug_msgs)

    def test_top_talkers_not_logged_at_warning(self, ingested_db, caplog):
        with caplog.at_level(logging.WARNING, logger="pcap_agent.tools.analysis"):
            get_top_talkers(5)

        assert not caplog.records

    def test_logger_uses_module_name(self):
        import pcap_agent.tools.analysis as analysis_mod

        assert analysis_mod.logger.name == "pcap_agent.tools.analysis"


class TestQueryLogging:
    def test_sql_logged_at_debug(self, ingested_db, caplog):
        sql = "SELECT src_ip FROM packets LIMIT 1"
        with caplog.at_level(logging.DEBUG, logger="pcap_agent.tools.query"):
            query(sql)

        debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
        assert any(sql in msg for msg in debug_msgs)

    def test_row_count_logged_at_info(self, ingested_db, caplog):
        with caplog.at_level(logging.INFO, logger="pcap_agent.tools.query"):
            result = query("SELECT src_ip FROM packets LIMIT 5")

        info_msgs = [r.message for r in caplog.records if r.levelno == logging.INFO]
        assert any(str(result["row_count"]) in msg for msg in info_msgs)

    def test_row_count_not_logged_at_warning(self, ingested_db, caplog):
        with caplog.at_level(logging.WARNING, logger="pcap_agent.tools.query"):
            query("SELECT src_ip FROM packets LIMIT 5")

        assert not caplog.records

    def test_rejected_statement_logged_at_warning(self, ingested_db, caplog):
        with caplog.at_level(logging.WARNING, logger="pcap_agent.tools.query"):
            query("DROP TABLE packets")

        warning_msgs = [
            r.message for r in caplog.records if r.levelno == logging.WARNING
        ]
        assert any("DROP" in msg for msg in warning_msgs)

    def test_duckdb_error_logged_at_error(self, ingested_db, caplog):
        with caplog.at_level(logging.ERROR, logger="pcap_agent.tools.query"):
            query("SELECT FROM WHERE")

        error_msgs = [r.message for r in caplog.records if r.levelno == logging.ERROR]
        assert len(error_msgs) >= 1

    def test_logger_uses_module_name(self):
        import pcap_agent.tools.query as query_mod

        assert query_mod.logger.name == "pcap_agent.tools.query"
