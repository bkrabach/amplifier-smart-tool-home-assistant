from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from ha_analysis import AnalysisRuntime, load_manifest
from ha_analysis import live
from ha_analysis.cli import main as cli_main
from ha_analysis.live import EntityAbsentError, OriginChangeError, TransportError

ROOT = Path(__file__).parents[1]
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T.*Z$")
BASE_KEYS = {
    "contract_version", "operation", "execution_class", "evidence_sources",
    "processed_at", "request_scope", "output", "redaction", "warnings", "failures",
}


class FakeReader:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.calls: list[tuple[dict[str, object], str, str]] = []

    def read_entity(self, origin: dict[str, object], entity_id: str, credential: str) -> object:
        self.calls.append((origin, entity_id, credential))
        response = self.responses[entity_id]
        if isinstance(response, BaseException):
            raise response
        return response


class FakeModel:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[tuple[object, str]] = []

    def interpret(self, selected_evidence: object, interpretation_kind: str) -> object:
        self.calls.append((selected_evidence, interpretation_kind))
        return self.response


def test_t1_t9_all_operations_have_precise_operation_matched_envelopes() -> None:
    runtime = AnalysisRuntime()
    results = [
        runtime.offline_analyze([{"observed_at": "2024-01-15T12:00:00Z"}], {"analysis_kind": "structural_summary"}),
        runtime.inspect_live_entities("https://ha.example", [], None),
        runtime.interpret_evidence([{"state": "on"}], {"interpretation_kind": "advice"}),
    ]
    assert [result["operation"] for result in results] == [
        "offline_analyze", "inspect_live_entities", "interpret_evidence"
    ]
    assert [result["output"]["kind"] for result in results] == [
        "offline_analysis", "live_entity_inspection", "model_interpretation"
    ]
    for result in results:
        extra = {"requested_targets", "target_resolution"} if result["operation"] == "inspect_live_entities" else set()
        assert set(result) == BASE_KEYS | extra
        assert result["contract_version"] == "ha-analysis.v2"
        assert TIMESTAMP.fullmatch(result["processed_at"])
        json.dumps(result)


def test_c1_valid_zero_partial_and_malformed_utf8_results(tmp_path: Path) -> None:
    runtime = AnalysisRuntime()
    partial = runtime.offline_analyze(
        [{"observed_at": "2024-01-15T12:00:00Z"}, {"observed_at": "bad"}],
        {"analysis_kind": "structural_summary"},
    )
    assert partial["request_scope"]["evidence_source_count"] == 2
    assert partial["failures"][0]["code"] == "invalid_observed_at"
    assert runtime.offline_analyze([], {"analysis_kind": "structural_summary"})["request_scope"]["evidence_source_count"] == 0
    assert runtime.inspect_live_entities("https://ha.example", [], None)["request_scope"]["target_count"] == 0
    assert runtime.interpret_evidence([], {"interpretation_kind": "advice"})["request_scope"]["evidence_source_count"] == 0

    malformed = tmp_path / "malformed.json"
    malformed.write_bytes(b"\xff\xfe")
    for operation, flag, request in (
        ("offline_analyze", "--evidence-file", '{"analysis_kind":"structural_summary"}'),
        ("interpret_evidence", "--selected-evidence-file", '{"interpretation_kind":"advice"}'),
    ):
        completed = _cli(operation, flag, str(malformed), "--request", request)
        document = json.loads(completed.stdout)
        assert completed.returncode == 1 and completed.stderr == ""
        assert document["operation"] == operation
        assert document["request_scope"]["evidence_source_count"] == 0
        assert document["failures"][0]["code"] == "invalid_evidence"


def test_c2_cli_delegates_to_library_and_in_process_configured_runtime(
    capsys: pytest.CaptureFixture[str],
) -> None:
    library = AnalysisRuntime().offline_analyze(
        [{"state": "on"}], {"analysis_kind": "structural_summary"}
    )
    completed = _cli(
        "offline_analyze", "--evidence", '[{"state":"on"}]',
        "--request", '{"analysis_kind":"structural_summary"}',
    )
    rendered = json.loads(completed.stdout)
    for field in BASE_KEYS - {"processed_at"}:
        assert rendered[field] == library[field]

    library_reader = FakeReader({"light.kitchen": {"state": "on"}})
    library_model = FakeModel({"advice": "review it"})
    expected_live = AnalysisRuntime(entity_reader=library_reader).inspect_live_entities(
        "https://ha.example", ["light.kitchen"], lambda: "credential"
    )
    expected_model = AnalysisRuntime(model_interpreter=library_model).interpret_evidence(
        [{"state": "on"}], {"interpretation_kind": "advice"}
    )

    reader = FakeReader({"light.kitchen": {"state": "on"}})
    model = FakeModel({"advice": "review it"})
    runtime = AnalysisRuntime(entity_reader=reader, model_interpreter=model)
    assert cli_main(
        ["inspect_live_entities", "--origin", "https://ha.example", "--targets", '["light.kitchen"]'],
        runtime=runtime, credential_provider=lambda: "credential",
    ) == 0
    live_result = json.loads(capsys.readouterr().out)
    assert _without_timestamp(live_result) == _without_timestamp(expected_live)
    assert reader.calls == [({"scheme": "https", "host": "ha.example", "port": 443}, "light.kitchen", "credential")]

    assert cli_main(
        ["interpret_evidence", "--selected-evidence", '[{"state":"on"}]', "--request", '{"interpretation_kind":"advice"}'],
        runtime=runtime,
    ) == 0
    model_result = json.loads(capsys.readouterr().out)
    assert _without_timestamp(model_result) == _without_timestamp(expected_model)
    assert model.calls == [([{"state": "on"}], "advice")]


def test_c3_c4_exact_only_ordered_reads_and_encoded_default_get(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = FakeReader({
        "light.kitchen": {"state": "on", "attributes": {"password": "not-for-output"}},
        "sensor.missing": EntityAbsentError(),
        "group.downstairs": {"state": "off", "attributes": {"members": ["light.kitchen"]}},
    })
    result = AnalysisRuntime(entity_reader=reader).inspect_live_entities(
        "https://HA.EXAMPLE", ["light.kitchen", "sensor.missing", "group.downstairs"], lambda: "credential"
    )
    assert [call[1] for call in reader.calls] == ["light.kitchen", "sensor.missing", "group.downstairs"]
    assert [item["status"] for item in result["target_resolution"]] == ["resolved", "absent", "resolved"]
    assert result["output"]["entities"] == [
        {"entity_id": "light.kitchen", "state": "on", "evidence_kind": "observed_home_assistant"},
        {"entity_id": "group.downstairs", "state": "off", "evidence_kind": "observed_home_assistant"},
    ]
    assert "attributes" not in json.dumps(result["output"])

    invalid = AnalysisRuntime(entity_reader=reader).inspect_live_entities(
        "https://ha.example", ["light.*", "light", "light.kitchen"], lambda: "credential"
    )
    assert [item["status"] for item in invalid["target_resolution"]] == ["invalid", "invalid", "resolved"]

    captured: list[object] = []
    class Response:
        def __enter__(self) -> "Response": return self
        def __exit__(self, *args: object) -> None: return None
        def read(self) -> bytes: return b'{"state":"on"}'
    class Opener:
        def open(self, request: object, timeout: int) -> Response:
            captured.append(request)
            return Response()
    monkeypatch.setattr(live, "build_opener", lambda *handlers: Opener())
    AnalysisRuntime().inspect_live_entities("https://ha.example", ["light.kitchen"], lambda: "credential")
    assert captured[0].get_method() == "GET"
    assert captured[0].full_url == "https://ha.example:443/api/states/light.kitchen"


def test_c5_c6_profile_cannot_be_replaced_and_redaction_is_fail_closed() -> None:
    assert "redactor" not in AnalysisRuntime.__init__.__annotations__
    with pytest.raises(TypeError):
        AnalysisRuntime(redactor=lambda value, keys: (value, 0))  # type: ignore[call-arg]
    model = FakeModel({"nested": {"private_key": "model-secret"}, "code": "model-code", "advice": "safe"})
    runtime = AnalysisRuntime(model_interpreter=model)
    result = runtime.interpret_evidence(
        [{"nested": {"token": "source-secret"}, "address": "private place"}],
        {"interpretation_kind": "advice"},
    )
    payload, _ = model.calls[0]
    serialized = runtime.serialize_result(result)
    for secret in ("source-secret", "private place", "model-secret", "model-code"):
        assert secret not in repr(payload)
        assert secret not in json.dumps(result)
        assert secret not in serialized
    assert result["redaction"]["status"] == "complete"

    malformed_model = FakeModel(object())
    withheld = AnalysisRuntime(model_interpreter=malformed_model).interpret_evidence(
        [{"token": "not-leaked"}], {"interpretation_kind": "advice"}
    )
    assert malformed_model.calls == [([{"token": "[REDACTED]"}], "advice")]
    assert withheld["redaction"]["status"] == "withheld"
    assert "not-leaked" not in json.dumps(withheld)
    assert "redaction_failed" in runtime.serialize_result(withheld)


def test_c7_c8_transport_credentials_and_failure_honesty() -> None:
    reader = FakeReader({"light.kitchen": {"state": "on"}})
    calls = 0
    def credential() -> str:
        nonlocal calls
        calls += 1
        return "credential"
    rejected = AnalysisRuntime(entity_reader=reader).inspect_live_entities(
        "http://ha.example", ["light.kitchen"], credential
    )
    assert rejected["failures"][0]["code"] == "insecure_transport_rejected"
    assert calls == 0 and reader.calls == []
    trusted = AnalysisRuntime(entity_reader=reader, transport_mode="trusted_local_or_vpn").inspect_live_entities(
        "http://ha.example", ["light.kitchen"], credential
    )
    assert trusted["target_resolution"][0]["status"] == "resolved" and calls == 1
    redirect = AnalysisRuntime(entity_reader=FakeReader({"light.kitchen": OriginChangeError()})).inspect_live_entities(
        "https://ha.example", ["light.kitchen"], credential
    )
    assert redirect["failures"][0]["code"] == "origin_change_rejected"
    transport = AnalysisRuntime(entity_reader=FakeReader({"light.kitchen": TransportError()})).inspect_live_entities(
        "https://ha.example", ["light.kitchen"], lambda: "credential"
    )
    assert transport["failures"][0]["code"] == "live_read_failed"
    assert "physical" not in json.dumps(transport).lower()


def test_upstream_descriptor_manifest_and_format() -> None:
    manifest = load_manifest()
    assert set(manifest) == {"smart_tool_format", "name", "version", "description", "use_cases", "platforms"}
    assert manifest["name"] == "ha-analysis"
    assert manifest["version"] == _package_version()
    descriptor = json.loads((ROOT / "smart-tool.json").read_text())
    assert set(descriptor) == {"manifest", "cli_argv", "deterministic_smoke"}
    assert json.loads(_cli("manifest", "--format", "json").stdout) == manifest
    assert _cli("manifest", "--format", "text").returncode != 0


def test_cli_named_failure_and_syntax_error_exit_nonzero() -> None:
    named = _cli(
        "offline_analyze", "--evidence", "[]",
        "--request", '{"analysis_kind":"structural_summary"}',
    )
    assert named.returncode != 0
    assert json.loads(named.stdout)["failures"][0]["code"] == "empty_evidence"
    syntax = _cli("__not_a_command__")
    assert syntax.returncode != 0 and syntax.stdout == ""


def _cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ha_analysis.cli", *arguments],
        cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        text=True, capture_output=True, check=False,
    )


def _package_version() -> str:
    import tomllib

    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def _without_timestamp(result: dict[str, object]) -> dict[str, object]:
    normalized = dict(result)
    normalized.pop("processed_at")
    return normalized
