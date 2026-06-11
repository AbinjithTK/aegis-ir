"""Phoenix Tracer — Official phoenix.otel.register() based setup.

Uses the OFFICIAL Phoenix SDK approach per docs.arize.com/phoenix:
- phoenix.otel.register(auto_instrument=True) handles ALL instrumentation
- Phoenix Client SDK for querying own traces (self-introspection)
- Annotations API for logging eval results back to spans

Supports:
- Phoenix Cloud (production — app.phoenix.arize.com)
- Phoenix Local (development — self-hosted localhost:6006)
- In-Memory (testing — fallback when no Phoenix server available)
"""

import os
from typing import Optional, Any
from enum import Enum

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.sdk.resources import Resource


class PhoenixMode(str, Enum):
    CLOUD = "cloud"
    LOCAL = "local"
    MEMORY = "memory"
    DISABLED = "disabled"


class MemoryExporter(SpanExporter):
    """Collects spans in-memory for testing and offline evaluation."""
    def __init__(self):
        self._spans = []

    def export(self, spans):
        self._spans.extend(spans)
        return SpanExportResult.SUCCESS

    def get_spans(self):
        return list(self._spans)

    def clear(self):
        self._spans.clear()

    def shutdown(self):
        pass

    def force_flush(self, timeout_millis=None):
        pass

    @property
    def stats(self) -> dict:
        spans = self._spans
        return {
            "total": len(spans),
            "agents": len([s for s in spans if "agent" in s.name.lower()]),
            "tools": len([s for s in spans if "FunctionTool" in s.name]),
            "guardrails": len([s for s in spans if "guardrail" in s.name]),
            "llm_calls": len([s for s in spans if hasattr(s, 'attributes') and
                             s.attributes.get("openinference.span.kind") == "LLM"]),
        }


class PhoenixTracer:
    """Enterprise Phoenix tracer using official phoenix.otel.register().
    
    This replaces manual OpenTelemetry setup with the official SDK approach.
    Auto-instruments Google ADK, Google GenAI, and all OpenInference-compatible libraries.
    """

    _instance: Optional["PhoenixTracer"] = None

    def __init__(self):
        self.mode = PhoenixMode.DISABLED
        self.provider: Optional[Any] = None
        self.exporter: Optional[SpanExporter] = None
        self._initialized = False
        self._client = None  # Phoenix Client for self-introspection

    @classmethod
    def get_instance(cls) -> "PhoenixTracer":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls):
        cls._instance = None

    def initialize(self, mode: Optional[str] = None) -> "PhoenixTracer":
        """Initialize tracing using phoenix.otel.register().
        
        This is the OFFICIAL approach per Phoenix docs.
        auto_instrument=True handles GoogleADKInstrumentor automatically.
        """
        if self._initialized:
            return self

        if mode:
            self.mode = PhoenixMode(mode)
        else:
            self.mode = self._detect_mode()

        if self.mode == PhoenixMode.CLOUD:
            self._init_cloud()
        elif self.mode == PhoenixMode.LOCAL:
            self._init_local()
        elif self.mode == PhoenixMode.MEMORY:
            self._init_memory()
        else:
            self._init_disabled()

        self._initialized = True
        return self

    def get_tracer(self, name: str = "sift_defender"):
        return trace.get_tracer(name)

    def get_memory_exporter(self) -> Optional[MemoryExporter]:
        if isinstance(self.exporter, MemoryExporter):
            return self.exporter
        return None

    def get_client(self):
        """Get Phoenix Client for self-introspection (querying own traces)."""
        if self._client is None and self.mode in (PhoenixMode.LOCAL, PhoenixMode.CLOUD):
            try:
                from phoenix.client import Client
                endpoint = os.environ.get("PHOENIX_LOCAL_ENDPOINT", "http://localhost:6006")
                if self.mode == PhoenixMode.CLOUD:
                    endpoint = os.environ.get("PHOENIX_COLLECTOR_ENDPOINT", "https://app.phoenix.arize.com")
                self._client = Client(endpoint=endpoint)
            except Exception:
                pass
        return self._client

    def flush(self, timeout_ms: int = 10000):
        if self.provider:
            try:
                self.provider.force_flush(timeout_millis=timeout_ms)
            except Exception:
                pass

    def _detect_mode(self) -> PhoenixMode:
        phoenix_mode = os.environ.get("PHOENIX_MODE", "").lower()
        if phoenix_mode == "memory":
            return PhoenixMode.MEMORY
        if phoenix_mode == "local":
            return PhoenixMode.LOCAL
        if phoenix_mode == "cloud":
            return PhoenixMode.CLOUD
        if phoenix_mode == "disabled":
            return PhoenixMode.DISABLED
        if os.environ.get("PHOENIX_API_KEY"):
            return PhoenixMode.CLOUD
        if os.environ.get("PHOENIX_LOCAL_ENDPOINT"):
            return PhoenixMode.LOCAL
        return PhoenixMode.MEMORY

    def _init_cloud(self):
        """Use phoenix.otel.register() for Phoenix Cloud."""
        try:
            from phoenix.otel import register
            self.provider = register(
                project_name=os.environ.get("PHOENIX_PROJECT_NAME", "aegis-ir"),
                auto_instrument=True,
                batch=True,
            )
            print(f"✓ Phoenix Cloud: {os.environ.get('PHOENIX_COLLECTOR_ENDPOINT', 'app.phoenix.arize.com')}")
        except Exception as e:
            print(f"⚠ Phoenix Cloud init failed: {e}")
            self._init_memory()

    def _init_local(self):
        """Use phoenix.otel.register() for local Phoenix server."""
        endpoint = os.environ.get("PHOENIX_LOCAL_ENDPOINT", "http://localhost:6006")
        try:
            from phoenix.otel import register
            self.provider = register(
                project_name=os.environ.get("PHOENIX_PROJECT_NAME", "aegis-ir"),
                endpoint=f"{endpoint}/v1/traces",
                auto_instrument=True,
                batch=False,  # Immediate export for local dev
            )
            print(f"✓ Phoenix Local: {endpoint}")
        except Exception as e:
            # Fallback: manual OTLP exporter (works even without phoenix.otel)
            print(f"⚠ phoenix.otel.register() failed ({e}), using manual OTLP")
            self._init_local_fallback(endpoint)

    def _init_local_fallback(self, endpoint: str):
        """Manual OTLP setup when phoenix.otel is not available."""
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from openinference.instrumentation.google_adk import GoogleADKInstrumentor

            self.exporter = OTLPSpanExporter(
                endpoint=f"{endpoint}/v1/traces",
                timeout=5,
            )
            resource = Resource.create({
                "service.name": "aegis-ir",
                "service.version": "1.0.0",
                "openinference.project.name": os.environ.get("PHOENIX_PROJECT_NAME", "aegis-ir"),
            })
            provider = TracerProvider(resource=resource)
            provider.add_span_processor(SimpleSpanProcessor(self.exporter))
            trace.set_tracer_provider(provider)
            self.provider = provider

            try:
                GoogleADKInstrumentor().instrument(tracer_provider=provider)
            except Exception:
                pass

            print(f"✓ Phoenix Local (fallback OTLP): {endpoint}")
        except Exception as e:
            print(f"⚠ Phoenix Local fallback failed: {e}")
            self._init_memory()

    def _init_memory(self):
        """In-memory spans for testing."""
        self.exporter = MemoryExporter()
        resource = Resource.create({
            "service.name": "aegis-ir",
            "openinference.project.name": "aegis-ir",
        })
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        trace.set_tracer_provider(provider)
        self.provider = provider

        try:
            from openinference.instrumentation.google_adk import GoogleADKInstrumentor
            GoogleADKInstrumentor().instrument(tracer_provider=provider)
        except Exception:
            pass

        print("✓ Phoenix Memory: spans collected in-process")

    def _init_disabled(self):
        print("⚠ Phoenix disabled: no observability")
