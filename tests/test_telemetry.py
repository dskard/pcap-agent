"""Tests for the telemetry module."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

import pcap_agent.telemetry as telemetry


@pytest.fixture(autouse=True)
def reset_telemetry():
    """Reset telemetry module state around each test."""
    telemetry._reset()
    yield
    telemetry._reset()


@pytest.fixture()
def memory_telemetry():
    """Configure telemetry with in-memory OTel exporters (no real OTLP server)."""
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    span_exporter = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(span_exporter))
    telemetry._tracer = tp.get_tracer("test")

    metric_reader = InMemoryMetricReader()
    mp = MeterProvider(metric_readers=[metric_reader])
    meter = mp.get_meter("test")
    telemetry._meter = meter
    telemetry._metrics = {
        "packets_ingested": meter.create_counter("pcap_agent.packets_ingested"),
        "queries_run": meter.create_counter("pcap_agent.queries_run"),
        "anomalies_detected": meter.create_counter("pcap_agent.anomalies_detected"),
        "tool_call_latency": meter.create_histogram("pcap_agent.tool_call_latency"),
    }

    return span_exporter, metric_reader


def _get_metric_sum(metric_reader, name: str) -> float:
    """Extract the sum for a named counter from InMemoryMetricReader."""
    data = metric_reader.get_metrics_data()
    for rm in data.resource_metrics:
        for sm in rm.scope_metrics:
            for metric in sm.metrics:
                if metric.name == name:
                    return sum(dp.value for dp in metric.data.data_points)
    return 0.0


def _get_histogram_count(metric_reader, name: str) -> int:
    """Extract data point count for a named histogram."""
    data = metric_reader.get_metrics_data()
    for rm in data.resource_metrics:
        for sm in rm.scope_metrics:
            for metric in sm.metrics:
                if metric.name == name:
                    return sum(dp.count for dp in metric.data.data_points)
    return 0


class TestSetupNoOp:
    def test_empty_endpoint_leaves_tracer_none(self):
        telemetry.setup("")
        assert telemetry._tracer is None

    def test_empty_endpoint_leaves_meter_none(self):
        telemetry.setup("")
        assert telemetry._meter is None

    def test_empty_endpoint_leaves_metrics_empty(self):
        telemetry.setup("")
        assert telemetry._metrics == {}

    def test_no_args_does_not_raise(self):
        telemetry.setup()

    def test_empty_endpoint_does_not_raise(self):
        telemetry.setup("")

    def test_no_endpoint_sets_root_logger_level(self):
        root = logging.getLogger()
        original_level = root.level
        original_handlers = root.handlers[:]
        try:
            telemetry.setup("", log_level="DEBUG")
            assert root.level == logging.DEBUG
        finally:
            root.handlers[:] = original_handlers
            root.setLevel(original_level)


class TestSetupWithEndpoint:
    def _patched_setup(self, mock_tracer: MagicMock, mock_meter: MagicMock) -> None:
        """Call telemetry.setup() with all OTel SDK symbols mocked out."""
        from contextlib import ExitStack

        targets = [
            ("opentelemetry.sdk.trace.TracerProvider", {}),
            ("opentelemetry.sdk.trace.export.BatchSpanProcessor", {}),
            (
                "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter",
                {},
            ),
            ("opentelemetry.sdk.metrics.MeterProvider", {}),
            ("opentelemetry.sdk.metrics.export.PeriodicExportingMetricReader", {}),
            (
                "opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter",
                {},
            ),
            ("opentelemetry.sdk._logs.LoggerProvider", {}),
            ("opentelemetry.sdk._logs.export.BatchLogRecordProcessor", {}),
            (
                "opentelemetry.exporter.otlp.proto.http._log_exporter.OTLPLogExporter",
                {},
            ),
            ("opentelemetry._logs.set_logger_provider", {}),
            ("opentelemetry.instrumentation.logging.LoggingInstrumentor", {}),
            ("opentelemetry.trace.set_tracer_provider", {}),
            ("opentelemetry.metrics.set_meter_provider", {}),
            ("opentelemetry.trace.get_tracer", {"return_value": mock_tracer}),
            ("opentelemetry.metrics.get_meter", {"return_value": mock_meter}),
        ]
        with ExitStack() as stack:
            for target, kwargs in targets:
                stack.enter_context(patch(target, **kwargs))
            telemetry.setup("http://localhost:4318")

    def test_endpoint_sets_tracer(self):
        mock_tracer = MagicMock()
        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = MagicMock()
        mock_meter.create_histogram.return_value = MagicMock()
        self._patched_setup(mock_tracer, mock_meter)
        assert telemetry._tracer is mock_tracer

    def test_endpoint_sets_meter(self):
        mock_tracer = MagicMock()
        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = MagicMock()
        mock_meter.create_histogram.return_value = MagicMock()
        self._patched_setup(mock_tracer, mock_meter)
        assert telemetry._meter is mock_meter

    def test_endpoint_creates_all_metric_instruments(self):
        mock_tracer = MagicMock()
        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = MagicMock()
        mock_meter.create_histogram.return_value = MagicMock()
        self._patched_setup(mock_tracer, mock_meter)
        assert "packets_ingested" in telemetry._metrics
        assert "queries_run" in telemetry._metrics
        assert "anomalies_detected" in telemetry._metrics
        assert "tool_call_latency" in telemetry._metrics


class TestInstrumentTool:
    def test_noop_without_setup_passes_through(self):
        def my_tool(x: int) -> int:
            return x * 2

        wrapped = telemetry.instrument_tool(my_tool)
        assert wrapped(3) == 6

    def test_noop_preserves_function_name(self):
        def my_tool(x: int) -> int:
            return x

        wrapped = telemetry.instrument_tool(my_tool)
        assert wrapped.__name__ == "my_tool"

    def test_span_created_with_tool_name(self, memory_telemetry):
        span_exporter, _ = memory_telemetry

        def sample_tool(x: int) -> dict:
            return {"x": x}

        wrapped = telemetry.instrument_tool(sample_tool)
        wrapped(42)

        spans = span_exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "sample_tool"

    def test_span_has_tool_name_attribute(self, memory_telemetry):
        span_exporter, _ = memory_telemetry

        def sample_tool(x: int) -> dict:
            return {"x": x}

        wrapped = telemetry.instrument_tool(sample_tool)
        wrapped(42)

        spans = span_exporter.get_finished_spans()
        assert spans[0].attributes["tool.name"] == "sample_tool"

    def test_span_has_argument_attributes(self, memory_telemetry):
        span_exporter, _ = memory_telemetry

        def sample_tool(x: int, y: str = "default") -> dict:
            return {"x": x, "y": y}

        wrapped = telemetry.instrument_tool(sample_tool)
        wrapped(42, y="hello")

        spans = span_exporter.get_finished_spans()
        assert spans[0].attributes["tool.arg.x"] == "42"
        assert spans[0].attributes["tool.arg.y"] == "hello"

    def test_span_records_latency_histogram(self, memory_telemetry):
        _, metric_reader = memory_telemetry

        def sample_tool() -> dict:
            return {}

        wrapped = telemetry.instrument_tool(sample_tool)
        wrapped()

        count = _get_histogram_count(metric_reader, "pcap_agent.tool_call_latency")
        assert count == 1

    def test_return_value_preserved(self, memory_telemetry):
        def sample_tool(x: int) -> dict:
            return {"result": x * 2}

        wrapped = telemetry.instrument_tool(sample_tool)
        assert wrapped(5) == {"result": 10}


class TestMetricRecording:
    def test_record_packets_ingested_noop_without_setup(self):
        telemetry.record_packets_ingested(100)  # should not raise

    def test_record_queries_run_noop_without_setup(self):
        telemetry.record_queries_run()  # should not raise

    def test_record_anomalies_detected_noop_without_setup(self):
        telemetry.record_anomalies_detected(5)  # should not raise

    def test_record_packets_ingested_increments_counter(self, memory_telemetry):
        _, metric_reader = memory_telemetry
        telemetry.record_packets_ingested(278)
        assert _get_metric_sum(metric_reader, "pcap_agent.packets_ingested") == 278

    def test_record_queries_run_increments_counter(self, memory_telemetry):
        _, metric_reader = memory_telemetry
        telemetry.record_queries_run()
        telemetry.record_queries_run()
        assert _get_metric_sum(metric_reader, "pcap_agent.queries_run") == 2

    def test_record_anomalies_detected_increments_counter(self, memory_telemetry):
        _, metric_reader = memory_telemetry
        telemetry.record_anomalies_detected(3)
        assert _get_metric_sum(metric_reader, "pcap_agent.anomalies_detected") == 3
