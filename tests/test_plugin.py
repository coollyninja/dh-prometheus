from pathlib import Path
from uuid import UUID

import httpx
import pytest
import yaml
from deckhand.adapters import AdapterError, AdapterErrorKind, CancellationDisposition
from deckhand.models import ActionRequest, RequestContext, Target
from deckhand.plugins import (
    PluginActivation,
    PluginConfiguration,
    PluginLock,
    PluginLockEntry,
    PluginManager,
)

from dh_prometheus.plugin import (
    OBSERVE_ACTION,
    PrometheusCheck,
    PrometheusClient,
    PrometheusConfig,
    PrometheusReadAdapter,
    create_plugin,
)


def write_credential(path: Path, value: str) -> Path:
    path.write_text(value, encoding="utf-8")
    return path


def config(tmp_path: Path, *, checks: dict[str, dict[str, object]]) -> PrometheusConfig:
    return PrometheusConfig.model_validate(
        {
            "endpoint": "https://prometheus.example.invalid",
            "bearer_token_file": write_credential(tmp_path / "token", "test-secret"),
            "checks": checks,
        }
    )


def request(alias: str) -> ActionRequest:
    return ActionRequest(
        action_id=OBSERVE_ACTION.id,
        action_version=1,
        target=Target(type="prometheus_check", id=alias),
        parameters={},
        context=RequestContext(client="test"),
        idempotency_key=UUID("00000000-0000-4000-8000-000000000001"),
    )


def test_manifest_is_read_only_and_matches_repository() -> None:
    manifest = create_plugin().manifest
    assert manifest.id == "dh-prometheus"
    assert manifest.api_version == 1
    assert manifest.permissions.mutation is False
    assert OBSERVE_ACTION.mutation is False
    with open("deckhand-plugin.yaml", encoding="utf-8") as manifest_file:
        assert yaml.safe_load(manifest_file) == manifest.model_dump(mode="json")


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://prometheus.example.invalid",
        "https://user:password@prometheus.example.invalid",
        "https://prometheus.example.invalid/api/v1",
        "https://prometheus.example.invalid?token=secret",
    ],
)
def test_config_rejects_unsafe_endpoints(tmp_path: Path, endpoint: str) -> None:
    with pytest.raises(ValueError):
        PrometheusConfig(
            endpoint=endpoint,
            bearer_token_file=write_credential(tmp_path / "token", "value"),
            checks={"targets": PrometheusCheck(kind="targets")},
        )


@pytest.mark.parametrize(
    "check",
    [
        {"kind": "scalar", "expression": "up", "operator": "ge"},
        {"kind": "scalar", "expression": "up", "operator": "ge", "threshold": float("nan")},
        {"kind": "alerts", "threshold": 1},
        {"kind": "targets", "match_labels": {"job": "example"}},
    ],
)
def test_check_rejects_mixed_or_incomplete_shapes(check: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        PrometheusCheck.model_validate(check)


@pytest.mark.asyncio
async def test_scalar_check_uses_configured_query_and_bearer_file(tmp_path: Path) -> None:
    def handler(http_request: httpx.Request) -> httpx.Response:
        assert http_request.url.path == "/api/v1/query"
        assert http_request.url.params["query"] == "scalar(up)"
        assert http_request.headers["Authorization"] == "Bearer test-secret"
        return httpx.Response(
            200,
            json={"status": "success", "data": {"resultType": "scalar", "result": [1, "1"]}},
        )

    check = PrometheusCheck(kind="scalar", expression="scalar(up)", operator="ge", threshold=1)
    client = PrometheusClient(
        config(
            tmp_path,
            checks={
                "availability": {
                    "kind": "scalar",
                    "expression": "scalar(up)",
                    "operator": "ge",
                    "threshold": 1,
                }
            },
        ),
        transport=httpx.MockTransport(handler),
    )
    observation = await client.observe(check)
    assert observation.state == "healthy"
    assert observation.details == {"value": 1.0, "operator": "ge", "threshold": 1.0}


@pytest.mark.asyncio
async def test_scalar_check_rejects_ambiguous_vector(tmp_path: Path) -> None:
    client = PrometheusClient(
        config(
            tmp_path,
            checks={
                "availability": {
                    "kind": "scalar",
                    "expression": "up",
                    "operator": "ge",
                    "threshold": 1,
                }
            },
        ),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "resultType": "vector",
                        "result": [
                            {"metric": {"instance": "one"}, "value": [1, "1"]},
                            {"metric": {"instance": "two"}, "value": [1, "1"]},
                        ],
                    },
                },
            )
        ),
    )
    with pytest.raises(AdapterError) as captured:
        await client.observe(
            PrometheusCheck(kind="scalar", expression="up", operator="ge", threshold=1)
        )
    assert captured.value.kind == AdapterErrorKind.PROTOCOL


@pytest.mark.asyncio
async def test_alert_summary_filters_and_minimizes_details(tmp_path: Path) -> None:
    client = PrometheusClient(
        config(tmp_path, checks={"critical_alerts": {"kind": "alerts"}}),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "alerts": [
                            {
                                "labels": {"severity": "critical", "instance": "private-name"},
                                "state": "firing",
                            },
                            {"labels": {"severity": "warning"}, "state": "pending"},
                        ]
                    },
                },
            )
        ),
    )
    observation = await client.observe(
        PrometheusCheck(kind="alerts", match_labels={"severity": "critical"})
    )
    assert observation.state == "degraded"
    assert observation.details == {
        "matching_count": 1,
        "firing_count": 1,
        "pending_count": 0,
    }
    assert "private-name" not in str(observation.details)


@pytest.mark.asyncio
async def test_target_summary_filters_job_without_returning_labels(tmp_path: Path) -> None:
    client = PrometheusClient(
        config(tmp_path, checks={"scrape_health": {"kind": "targets"}}),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "activeTargets": [
                            {"labels": {"job": "selected", "instance": "one"}, "health": "up"},
                            {"labels": {"job": "selected", "instance": "two"}, "health": "down"},
                            {"labels": {"job": "other"}, "health": "up"},
                        ]
                    },
                },
            )
        ),
    )
    observation = await client.observe(PrometheusCheck(kind="targets", job="selected"))
    assert observation.state == "degraded"
    assert observation.details == {"active_count": 2, "healthy_count": 1}
    assert "instance" not in str(observation.details)


@pytest.mark.asyncio
async def test_redirect_and_upstream_body_are_not_exposed(tmp_path: Path) -> None:
    redirecting = PrometheusClient(
        config(tmp_path, checks={"alerts": {"kind": "alerts"}}),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(302, headers={"location": "https://other.example.invalid"})
        ),
    )
    with pytest.raises(AdapterError) as redirect:
        await redirecting.health()
    assert redirect.value.kind == AdapterErrorKind.PROTOCOL

    unauthorized = PrometheusClient(
        config(tmp_path, checks={"alerts": {"kind": "alerts"}}),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(401, text="diagnostic containing test-secret")
        ),
    )
    with pytest.raises(AdapterError) as captured:
        await unauthorized.health()
    assert captured.value.kind == AdapterErrorKind.AUTHENTICATION
    assert "test-secret" not in str(captured.value)
    assert "diagnostic" not in str(captured.value)


@pytest.mark.asyncio
async def test_adapter_implements_full_read_only_lifecycle(tmp_path: Path) -> None:
    prometheus_config = config(
        tmp_path,
        checks={
            "availability": {
                "kind": "scalar",
                "expression": "scalar(up)",
                "operator": "ge",
                "threshold": 1,
            }
        },
    )
    client = PrometheusClient(
        prometheus_config,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {"resultType": "scalar", "result": [1, "1"]},
                },
            )
        ),
    )
    adapter = PrometheusReadAdapter(client, prometheus_config.checks)
    action_request = request("availability")
    plan = await adapter.plan(OBSERVE_ACTION, action_request)
    execution = await adapter.execute(OBSERVE_ACTION, action_request)
    observation = await adapter.observe(OBSERVE_ACTION, action_request)
    verification = await adapter.verify(OBSERVE_ACTION, action_request, execution, observation)
    cancellation = await adapter.cancel(OBSERVE_ACTION, action_request, execution)

    assert len(plan.steps) == 3
    assert execution.reference == "observe:availability"
    assert observation.state == "healthy"
    assert verification.satisfied is True
    assert cancellation.disposition == CancellationDisposition.ALREADY_TERMINAL


def test_core_discovers_loads_and_wraps_installed_plugin(tmp_path: Path) -> None:
    plugin_config = config(tmp_path, checks={"alerts": {"kind": "alerts"}})
    loaded = PluginManager().load(
        PluginConfiguration(
            plugins={
                "dh-core": PluginActivation(),
                "dh-prometheus": PluginActivation(
                    config=plugin_config.model_dump(mode="json", exclude_none=True)
                ),
            }
        ),
        PluginLock(
            plugins=[
                PluginLockEntry(id="dh-core", version="0.4.0", source="builtin"),
                PluginLockEntry(id="dh-prometheus", version="0.1.0", source="python"),
            ]
        ),
        allow_external=True,
    )
    assert [manifest.id for manifest in loaded.manifests] == ["dh-core", "dh-prometheus"]
    assert loaded.adapters.get("dh-prometheus.read")
    assert set(loaded.status.providers) == {"alerts"}
    assert set(loaded.resilience) == {"dh-core", "dh-prometheus"}
