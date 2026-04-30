"""OpenTelemetry SDK initialisation and instrumentation helpers."""

from __future__ import annotations

import functools
import inspect
import logging
import sys
import time
from typing import Any, Callable

_tracer: Any = None
_meter: Any = None
_metrics: dict[str, Any] = {}


def setup(endpoint: str = "", log_level: str = "WARNING") -> None:
    """Initialize OTel SDK with OTLP HTTP exporters. No-op if endpoint is empty."""
    global _tracer, _meter, _metrics

    logging.basicConfig(
        stream=sys.stderr,
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        force=True,
    )

    if not endpoint:
        return

    from opentelemetry import metrics as otel_metrics
    from opentelemetry import trace
    from opentelemetry._logs import set_logger_provider
    from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
        OTLPMetricExporter,
    )
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.logging import LoggingInstrumentor
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    base = endpoint.rstrip("/")
    resource = Resource.create({"service.name": "pcap-agent"})

    # Traces
    tp = TracerProvider(resource=resource)
    tp.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{base}/v1/traces"))
    )
    trace.set_tracer_provider(tp)
    _tracer = trace.get_tracer("pcap-agent")

    # Metrics
    reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=f"{base}/v1/metrics")
    )
    mp = MeterProvider(resource=resource, metric_readers=[reader])
    otel_metrics.set_meter_provider(mp)
    _meter = otel_metrics.get_meter("pcap-agent")

    _metrics["packets_ingested"] = _meter.create_counter(
        "pcap_agent.packets_ingested",
        description="Total packets ingested",
    )
    _metrics["queries_run"] = _meter.create_counter(
        "pcap_agent.queries_run",
        description="Total SQL queries run",
    )
    _metrics["anomalies_detected"] = _meter.create_counter(
        "pcap_agent.anomalies_detected",
        description="Total anomalies detected",
    )
    _metrics["tool_call_latency"] = _meter.create_histogram(
        "pcap_agent.tool_call_latency",
        unit="s",
        description="Tool call latency in seconds",
    )

    # Logs bridge
    lp = LoggerProvider(resource=resource)
    lp.add_log_record_processor(
        BatchLogRecordProcessor(OTLPLogExporter(endpoint=f"{base}/v1/logs"))
    )
    set_logger_provider(lp)
    LoggingInstrumentor().instrument()


def instrument_tool(func: Callable) -> Callable:
    """Wrap a tool function in an OTel span with arguments as attributes.

    Returns the original function unchanged when telemetry is not configured.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if _tracer is None:
            return func(*args, **kwargs)

        tool_name = func.__name__
        with _tracer.start_as_current_span(tool_name) as span:
            span.set_attribute("tool.name", tool_name)
            try:
                sig = inspect.signature(func)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                for k, v in bound.arguments.items():
                    span.set_attribute(f"tool.arg.{k}", str(v))
            except (TypeError, ValueError):
                pass

            t0 = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - t0
                _record_latency(tool_name, elapsed)

    return wrapper


def record_packets_ingested(count: int) -> None:
    """Increment the packets-ingested counter."""
    counter = _metrics.get("packets_ingested")
    if counter is not None:
        counter.add(count)


def record_queries_run() -> None:
    """Increment the queries-run counter."""
    counter = _metrics.get("queries_run")
    if counter is not None:
        counter.add(1)


def record_anomalies_detected(count: int) -> None:
    """Increment the anomalies-detected counter."""
    counter = _metrics.get("anomalies_detected")
    if counter is not None:
        counter.add(count)


def _record_latency(tool_name: str, elapsed: float) -> None:
    hist = _metrics.get("tool_call_latency")
    if hist is not None:
        hist.record(elapsed, {"tool": tool_name})


def _reset() -> None:
    """Reset module state. For testing only."""
    global _tracer, _meter, _metrics
    _tracer = None
    _meter = None
    _metrics = {}
