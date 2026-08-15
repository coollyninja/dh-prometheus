from __future__ import annotations

import math
import re
import ssl
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from deckhand.adapters import (
    AdapterCancellation,
    AdapterError,
    AdapterErrorKind,
    AdapterExecution,
    AdapterHealth,
    AdapterHealthState,
    AdapterObservation,
    AdapterPlan,
    AdapterVerification,
    CancellationDisposition,
)
from deckhand.models import (
    ActionDefinition,
    ActionRequest,
    ConfirmationMode,
    RetryDisposition,
    RiskClass,
    StatusValue,
    StrictModel,
)
from deckhand.plugin_api import (
    DeckhandPlugin,
    PluginContext,
    PluginContribution,
    PluginManifest,
    PluginPermissions,
)
from pydantic import Field, field_validator, model_validator


class PrometheusCheckKind(StrEnum):
    SCALAR = "scalar"
    ALERTS = "alerts"
    TARGETS = "targets"


class Comparison(StrEnum):
    GT = "gt"
    GE = "ge"
    LT = "lt"
    LE = "le"
    EQ = "eq"
    NE = "ne"


class PrometheusCheck(StrictModel):
    kind: PrometheusCheckKind
    expression: str | None = Field(default=None, min_length=1, max_length=2048)
    operator: Comparison | None = None
    threshold: float | None = Field(default=None, allow_inf_nan=False)
    match_labels: dict[str, str] = Field(default_factory=dict)
    job: str | None = Field(default=None, min_length=1, max_length=256)
    stale_after_seconds: int = Field(default=30, ge=1, le=3600)

    @field_validator("match_labels")
    @classmethod
    def validate_match_labels(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 16:
            raise ValueError("match_labels supports at most 16 exact labels")
        for name, label_value in value.items():
            if re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", name) is None:
                raise ValueError("match label names must use Prometheus label syntax")
            if not label_value or len(label_value) > 256:
                raise ValueError("match label values must contain 1 to 256 characters")
        return value

    @model_validator(mode="after")
    def validate_shape(self) -> PrometheusCheck:
        if self.kind == PrometheusCheckKind.SCALAR:
            if self.expression is None or self.operator is None or self.threshold is None:
                raise ValueError("scalar checks require expression, operator, and threshold")
            if self.match_labels or self.job is not None:
                raise ValueError("scalar checks do not accept match_labels or job")
        elif self.kind == PrometheusCheckKind.ALERTS:
            if (
                self.expression is not None
                or self.operator is not None
                or self.threshold is not None
            ):
                raise ValueError("alert checks do not accept scalar fields")
            if self.job is not None:
                raise ValueError("alert checks do not accept job")
        else:
            if (
                self.expression is not None
                or self.operator is not None
                or self.threshold is not None
                or self.match_labels
            ):
                raise ValueError("target checks accept only an optional job filter")
        return self


class PrometheusConfig(StrictModel):
    endpoint: str
    bearer_token_file: Path | None = None
    verify_tls: bool = True
    ca_file: Path | None = None
    timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    checks: dict[str, PrometheusCheck] = Field(min_length=1)

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("endpoint must be an absolute HTTPS origin")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("endpoint must not contain credentials, query, or fragment")
        if parsed.path not in {"", "/"}:
            raise ValueError("endpoint must not contain a path")
        return value.rstrip("/")

    @field_validator("bearer_token_file", "ca_file")
    @classmethod
    def validate_file_path(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("credential and CA file paths must be absolute")
        return value

    @field_validator("checks")
    @classmethod
    def validate_check_aliases(
        cls, value: dict[str, PrometheusCheck]
    ) -> dict[str, PrometheusCheck]:
        invalid = [alias for alias in value if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", alias) is None]
        if invalid:
            raise ValueError("check aliases must be lowercase logical identifiers")
        return value


class PrometheusClient:
    def __init__(
        self,
        config: PrometheusConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self.transport = transport

    @staticmethod
    def _credential(path: Path) -> str:
        try:
            if path.stat().st_size > 4096:
                raise AdapterError(
                    "credential file exceeds size limit",
                    kind=AdapterErrorKind.CONFIGURATION,
                )
            value = path.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise AdapterError(
                "credential file is unavailable",
                kind=AdapterErrorKind.CONFIGURATION,
            ) from error
        if not value:
            raise AdapterError("credential file is empty", kind=AdapterErrorKind.CONFIGURATION)
        return value

    def _verify(self) -> bool | ssl.SSLContext:
        if not self.config.verify_tls:
            return False
        if self.config.ca_file is None:
            return True
        try:
            return ssl.create_default_context(cafile=str(self.config.ca_file))
        except (OSError, ssl.SSLError) as error:
            raise AdapterError(
                "TLS CA file is unavailable or invalid",
                kind=AdapterErrorKind.CONFIGURATION,
            ) from error

    def _headers(self) -> dict[str, str]:
        if self.config.bearer_token_file is None:
            return {}
        token = self._credential(self.config.bearer_token_file)
        return {"Authorization": f"Bearer {token}"}

    async def get(self, path: str, *, params: Mapping[str, str] | None = None) -> Any:
        try:
            async with httpx.AsyncClient(
                base_url=self.config.endpoint,
                timeout=self.config.timeout_seconds,
                verify=self._verify(),
                follow_redirects=False,
                trust_env=False,
                transport=self.transport,
            ) as client:
                response = await client.get(path, params=params, headers=self._headers())
        except httpx.TimeoutException as error:
            raise AdapterError(
                "Prometheus request timed out",
                kind=AdapterErrorKind.TIMEOUT,
                retry=RetryDisposition.SAFE,
            ) from error
        except httpx.HTTPError as error:
            raise AdapterError(
                "Prometheus is unavailable",
                kind=AdapterErrorKind.UNAVAILABLE,
                retry=RetryDisposition.SAFE,
            ) from error
        if response.is_redirect:
            raise AdapterError("Prometheus redirect refused", kind=AdapterErrorKind.PROTOCOL)
        if response.status_code == 401:
            raise AdapterError(
                "Prometheus authentication failed",
                kind=AdapterErrorKind.AUTHENTICATION,
            )
        if response.status_code == 403:
            raise AdapterError(
                "Prometheus authorization failed",
                kind=AdapterErrorKind.AUTHORIZATION,
            )
        if response.status_code == 404:
            raise AdapterError(
                "Prometheus API endpoint was not found",
                kind=AdapterErrorKind.NOT_FOUND,
            )
        if response.status_code == 429:
            raise AdapterError(
                "Prometheus rate limit reached",
                kind=AdapterErrorKind.RATE_LIMITED,
                retry=RetryDisposition.SAFE,
            )
        if response.status_code >= 500:
            raise AdapterError(
                "Prometheus returned a server error",
                kind=AdapterErrorKind.UNAVAILABLE,
                retry=RetryDisposition.SAFE,
            )
        if response.status_code >= 400:
            raise AdapterError("Prometheus request failed", kind=AdapterErrorKind.PROTOCOL)
        try:
            document = response.json()
        except ValueError as error:
            raise AdapterError(
                "Prometheus returned invalid JSON",
                kind=AdapterErrorKind.PROTOCOL,
            ) from error
        if (
            not isinstance(document, dict)
            or document.get("status") != "success"
            or "data" not in document
        ):
            raise AdapterError(
                "Prometheus response envelope is invalid",
                kind=AdapterErrorKind.PROTOCOL,
            )
        return document["data"]

    async def health(self) -> AdapterHealth:
        data = await self.get("/api/v1/status/buildinfo")
        details = {"api": "reachable"}
        if isinstance(data, dict) and isinstance(data.get("version"), str):
            details["version"] = data["version"]
        return AdapterHealth(state=AdapterHealthState.HEALTHY, details=details)

    async def observe(self, check: PrometheusCheck) -> AdapterObservation:
        if check.kind == PrometheusCheckKind.SCALAR:
            return await self._observe_scalar(check)
        if check.kind == PrometheusCheckKind.ALERTS:
            return await self._observe_alerts(check)
        return await self._observe_targets(check)

    @staticmethod
    def _sample_value(data: Any) -> float:
        sample: Any
        if isinstance(data, dict) and data.get("resultType") == "scalar":
            sample = data.get("result")
        elif isinstance(data, dict) and data.get("resultType") == "vector":
            result = data.get("result")
            if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
                raise AdapterError(
                    "Prometheus scalar check returned an ambiguous vector",
                    kind=AdapterErrorKind.PROTOCOL,
                )
            sample = result[0].get("value")
        else:
            raise AdapterError(
                "Prometheus scalar check returned an unsupported result",
                kind=AdapterErrorKind.PROTOCOL,
            )
        if not isinstance(sample, list) or len(sample) != 2:
            raise AdapterError(
                "Prometheus sample has invalid shape",
                kind=AdapterErrorKind.PROTOCOL,
            )
        try:
            value = float(sample[1])
        except (TypeError, ValueError) as error:
            raise AdapterError(
                "Prometheus sample is not numeric",
                kind=AdapterErrorKind.PROTOCOL,
            ) from error
        if not math.isfinite(value):
            raise AdapterError(
                "Prometheus sample is not finite",
                kind=AdapterErrorKind.PROTOCOL,
            )
        return value

    @staticmethod
    def _compare(value: float, operator: Comparison, threshold: float) -> bool:
        return {
            Comparison.GT: value > threshold,
            Comparison.GE: value >= threshold,
            Comparison.LT: value < threshold,
            Comparison.LE: value <= threshold,
            Comparison.EQ: value == threshold,
            Comparison.NE: value != threshold,
        }[operator]

    async def _observe_scalar(self, check: PrometheusCheck) -> AdapterObservation:
        if check.expression is None or check.operator is None or check.threshold is None:
            raise AdapterError(
                "Prometheus scalar check is incomplete",
                kind=AdapterErrorKind.CONFIGURATION,
            )
        data = await self.get("/api/v1/query", params={"query": check.expression})
        value = self._sample_value(data)
        healthy = self._compare(value, check.operator, check.threshold)
        return AdapterObservation(
            state="healthy" if healthy else "degraded",
            details={
                "value": value,
                "operator": check.operator.value,
                "threshold": check.threshold,
            },
        )

    async def _observe_alerts(self, check: PrometheusCheck) -> AdapterObservation:
        data = await self.get("/api/v1/alerts")
        if not isinstance(data, dict) or not isinstance(data.get("alerts"), list):
            raise AdapterError(
                "Prometheus alerts response has invalid shape",
                kind=AdapterErrorKind.PROTOCOL,
            )
        matching = []
        for alert in data["alerts"]:
            if not isinstance(alert, dict) or not isinstance(alert.get("labels"), dict):
                continue
            if all(alert["labels"].get(key) == value for key, value in check.match_labels.items()):
                matching.append(alert)
        firing = sum(alert.get("state") == "firing" for alert in matching)
        pending = sum(alert.get("state") == "pending" for alert in matching)
        return AdapterObservation(
            state="healthy" if firing == 0 else "degraded",
            details={
                "matching_count": len(matching),
                "firing_count": firing,
                "pending_count": pending,
            },
        )

    async def _observe_targets(self, check: PrometheusCheck) -> AdapterObservation:
        data = await self.get("/api/v1/targets", params={"state": "active"})
        if not isinstance(data, dict) or not isinstance(data.get("activeTargets"), list):
            raise AdapterError(
                "Prometheus targets response has invalid shape",
                kind=AdapterErrorKind.PROTOCOL,
            )
        targets = []
        for target in data["activeTargets"]:
            if not isinstance(target, dict):
                continue
            labels = target.get("labels")
            if check.job is None or (isinstance(labels, dict) and labels.get("job") == check.job):
                targets.append(target)
        healthy = sum(target.get("health") == "up" for target in targets)
        state = "unknown" if not targets else "healthy" if healthy == len(targets) else "degraded"
        return AdapterObservation(
            state=state,
            details={"active_count": len(targets), "healthy_count": healthy},
        )


class PrometheusReadAdapter:
    def __init__(self, client: PrometheusClient, checks: Mapping[str, PrometheusCheck]) -> None:
        self.client = client
        self.checks = dict(checks)

    def _check(self, request: ActionRequest) -> PrometheusCheck:
        try:
            return self.checks[request.target.id]
        except KeyError as error:
            raise AdapterError(
                "Prometheus check alias is not configured",
                kind=AdapterErrorKind.NOT_FOUND,
            ) from error

    async def health(self) -> AdapterHealth:
        return await self.client.health()

    async def plan(self, action: ActionDefinition, request: ActionRequest) -> AdapterPlan:
        self._check(request)
        return AdapterPlan(
            steps=["resolve configured check alias", "query Prometheus API", "verify observation"]
        )

    async def execute(self, action: ActionDefinition, request: ActionRequest) -> AdapterExecution:
        self._check(request)
        return AdapterExecution(reference=f"observe:{request.target.id}")

    async def observe(self, action: ActionDefinition, request: ActionRequest) -> AdapterObservation:
        return await self.client.observe(self._check(request))

    async def verify(
        self,
        action: ActionDefinition,
        request: ActionRequest,
        execution: AdapterExecution,
        observation: AdapterObservation,
    ) -> AdapterVerification:
        return AdapterVerification(
            satisfied=observation.state != "unknown",
            details={"execution_reference": execution.reference},
        )

    async def cancel(
        self,
        action: ActionDefinition,
        request: ActionRequest,
        execution: AdapterExecution | None,
    ) -> AdapterCancellation:
        return AdapterCancellation(disposition=CancellationDisposition.ALREADY_TERMINAL)


class PrometheusStatusProvider:
    def __init__(self, client: PrometheusClient, check: PrometheusCheck) -> None:
        self.client = client
        self.check = check

    async def observe(self) -> StatusValue:
        observation = await self.client.observe(self.check)
        return StatusValue(
            state=observation.state,
            observed_at=observation.observed_at,
            stale_after_seconds=self.check.stale_after_seconds,
            details=observation.details,
        )


OBSERVE_ACTION = ActionDefinition(
    id="prometheus.check.observe",
    version=1,
    title="Observe Prometheus check",
    description="Read a configured logical Prometheus check alias.",
    risk_class=RiskClass.READ,
    plugin="dh-prometheus",
    adapter="dh-prometheus.read",
    target_types=["prometheus_check"],
    parameter_schema={
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "properties": {},
    },
    policy_action="prometheus.check.observe",
    confirmation=ConfirmationMode.NONE,
    timeout_seconds=30,
    idempotency="read-only",
    mutation=False,
)


CONFIG_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["endpoint", "checks"],
    "properties": {
        "endpoint": {"type": "string", "format": "uri", "pattern": "^https://"},
        "bearer_token_file": {"type": "string", "pattern": "^/"},
        "verify_tls": {"type": "boolean", "default": True},
        "ca_file": {"type": "string", "pattern": "^/"},
        "timeout_seconds": {"type": "number", "exclusiveMinimum": 0, "maximum": 30},
        "checks": {
            "type": "object",
            "minProperties": 1,
            "propertyNames": {"pattern": "^[a-z][a-z0-9_]{0,63}$"},
            "additionalProperties": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind"],
                "properties": {
                    "kind": {"enum": ["scalar", "alerts", "targets"]},
                    "expression": {"type": "string", "minLength": 1, "maxLength": 2048},
                    "operator": {"enum": ["gt", "ge", "lt", "le", "eq", "ne"]},
                    "threshold": {"type": "number"},
                    "match_labels": {
                        "type": "object",
                        "maxProperties": 16,
                        "propertyNames": {"pattern": "^[a-zA-Z_][a-zA-Z0-9_]*$"},
                        "additionalProperties": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 256,
                        },
                    },
                    "job": {"type": "string", "minLength": 1, "maxLength": 256},
                    "stale_after_seconds": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 3600,
                    },
                },
                "allOf": [
                    {
                        "if": {"properties": {"kind": {"const": "scalar"}}},
                        "then": {
                            "required": ["expression", "operator", "threshold"],
                            "not": {
                                "anyOf": [
                                    {"required": ["match_labels"]},
                                    {"required": ["job"]},
                                ]
                            },
                        },
                    },
                    {
                        "if": {"properties": {"kind": {"const": "alerts"}}},
                        "then": {
                            "not": {
                                "anyOf": [
                                    {"required": ["expression"]},
                                    {"required": ["operator"]},
                                    {"required": ["threshold"]},
                                    {"required": ["job"]},
                                ]
                            }
                        },
                    },
                    {
                        "if": {"properties": {"kind": {"const": "targets"}}},
                        "then": {
                            "not": {
                                "anyOf": [
                                    {"required": ["expression"]},
                                    {"required": ["operator"]},
                                    {"required": ["threshold"]},
                                    {"required": ["match_labels"]},
                                ]
                            }
                        },
                    },
                ],
            },
        },
    },
}


class PrometheusPlugin:
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="dh-prometheus",
            name="Prometheus",
            version="0.1.0",
            description="Read-only scalar, alert, and target observation through logical checks.",
            adapters=["dh-prometheus.read"],
            status_provider_types=["prometheus-check"],
            actions=[OBSERVE_ACTION.id],
            permissions=PluginPermissions(
                mutation=False,
                credential_slots=["prometheus.bearer_token", "prometheus.tls_ca"],
                egress_bindings=["endpoint"],
            ),
            config_schema=CONFIG_SCHEMA,
        )

    def build(self, context: PluginContext) -> PluginContribution:
        config = PrometheusConfig.model_validate(dict(context.config))
        client = PrometheusClient(config)
        return PluginContribution(
            adapters={"dh-prometheus.read": PrometheusReadAdapter(client, config.checks)},
            status_providers={
                alias: PrometheusStatusProvider(client, check)
                for alias, check in config.checks.items()
            },
            actions=(OBSERVE_ACTION,),
        )


def create_plugin() -> DeckhandPlugin:
    return PrometheusPlugin()
