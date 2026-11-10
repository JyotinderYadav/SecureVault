"""
Stage 4: Feedback-Based Test Runner Module
Executes stateful test sequences, injects category-tailored payloads, handles triggering requests,
and evaluates multi-signal oracle verdicts.
"""
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
import httpx
from framework.stage4_feedback_testing.oracles import VulnerabilityOracle
from framework.stage3_sequence_generation.sequencer import TestSequenceGenerator, TestSequence

DEFAULT_PAYLOADS_PATH = Path(__file__).resolve().parent.parent.parent / "datasets" / "vulnerability_corpus" / "processed" / "test_payloads.json"


class OracleVerdictValue(str):
    """
    String subclass that provides .value property for UI view compatibility
    while maintaining direct equality comparisons with string literals in tests.
    """
    @property
    def value(self) -> str:
        return str(self)


class TestExecutionResult(dict):
    """
    Dual dictionary and object representation of a test execution result.
    Supports both dict indexing (res["verdict"], res["status_code"])
    and attribute access (res.verdict.value, res.analysis, res.evidence, res.response_body).
    """
    def __init__(self, data: Dict[str, Any]):
        super().__init__(data)
        self._data = data
        self._verdict = OracleVerdictValue(data.get("verdict", "NEGATIVE"))
        self._analysis = data.get("explanation", data.get("analysis", ""))
        self._status_code = int(data.get("status_code", 0))
        self._latency_ms = float(data.get("latency_ms", 0.0))
        self._evidence = data.get("evidence", [])
        self._response_body = data.get("response_preview", data.get("response_body", ""))

    @property
    def verdict(self) -> OracleVerdictValue:
        return self._verdict

    @property
    def analysis(self) -> str:
        return self._analysis

    @property
    def explanation(self) -> str:
        return self._analysis

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def latency_ms(self) -> float:
        return self._latency_ms

    @property
    def evidence(self) -> List[str]:
        return self._evidence

    @property
    def response_body(self) -> str:
        return self._response_body

    @property
    def response_preview(self) -> str:
        return self._response_body

    @property
    def candidate(self) -> Dict[str, Any]:
        return self._data.get("candidate", {})

    @property
    def target_parameter(self) -> Optional[str]:
        return self._data.get("target_parameter")

    @property
    def payload_used(self) -> str:
        return self._data.get("payload_used", "")

    @property
    def payload(self) -> str:
        return self.payload_used

    @property
    def confidence(self) -> float:
        return float(self._data.get("confidence", 1.0))

    @property
    def execution_trace(self) -> List[Dict[str, Any]]:
        return self._data.get("execution_trace", [])


class FeedbackTestRunner:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        payloads_file: Optional[Path] = None,
        client: Optional[Any] = None
    ):
        self.base_url = base_url.rstrip("/")
        self.payloads_path = payloads_file or DEFAULT_PAYLOADS_PATH
        self.payload_categories: Dict[str, Any] = self._load_payloads()
        self.client = client  # Can be httpx.Client or fastapi.testclient.TestClient

    @property
    def payload_library(self) -> Dict[str, Any]:
        """Alias for payload_categories used by interactive UI lab."""
        return self.payload_categories

    def _load_payloads(self) -> Dict[str, Any]:
        if self.payloads_path.exists():
            with open(self.payloads_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("payload_categories", {})
        return {}

    def _get_client(self):
        if self.client:
            return self.client
        return httpx.Client(base_url=self.base_url, timeout=5, follow_redirects=False)

    def _execute_http(
        self,
        client: Any,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None
    ) -> Tuple[int, str, float]:
        """Executes an HTTP request and measures latency in milliseconds."""
        t0 = time.perf_counter()
        m = method.upper()

        if hasattr(client, "request"):
            resp = client.request(
                method=m,
                url=path,
                params=params,
                json=json_data,
                files=files,
                headers=headers
            )
        else:
            func = getattr(client, m.lower())
            resp = func(path, params=params, json=json_data, files=files, headers=headers)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return resp.status_code, resp.text, elapsed_ms

    def run_sequence(
        self,
        sequence: Any,
        candidate: Any,
        custom_payload: Optional[str] = None
    ) -> TestExecutionResult:
        """
        Executes a sequence against candidate target endpoint, providing seamless integration
        for interactive attack simulation lab.
        """
        # Create a lightweight sequencer instance for parameter value generation
        endpoints = []
        for step in (sequence.steps if hasattr(sequence, "steps") else sequence):
            endpoints.append(step.endpoint if hasattr(step, "endpoint") else step)
        sequencer = TestSequenceGenerator(endpoints)
        return self.run_candidate_test(candidate, sequence, sequencer, payload_override=custom_payload)

    def run_candidate_test(
        self,
        candidate: Any,
        sequence: Any,
        sequencer: TestSequenceGenerator,
        payload_override: Optional[str] = None
    ) -> TestExecutionResult:
        """
        Executes the full test sequence for a candidate interface:
        1. Executes prerequisite producer steps, capturing context values
        2. Executes the candidate target request with payload injection
        3. Executes triggering requests if required (e.g. for stored XSS)
        4. Calls oracle to determine verdict
        """
        cwe_id = candidate.cwe_category if hasattr(candidate, "cwe_category") else candidate.get("cwe_id", candidate.get("cwe_category", ""))
        
        target_param = None
        if hasattr(candidate, "primary_parameter") and candidate.primary_parameter:
            target_param = candidate.primary_parameter
        elif hasattr(candidate, "target_parameters") and candidate.target_parameters:
            target_param = candidate.target_parameters[0]
        elif isinstance(candidate, dict) and candidate.get("target_parameters"):
            target_param = candidate["target_parameters"][0]

        cand_path = candidate.path if hasattr(candidate, "path") else candidate["path"]
        cand_method = candidate.method if hasattr(candidate, "method") else candidate["method"]
        cand_vuln_type = candidate.vulnerability_type if hasattr(candidate, "vulnerability_type") else candidate.get("vulnerability_type", "")

        # Select payload
        cwe_payload_meta = self.payload_categories.get(cwe_id, {})
        payload_list = cwe_payload_meta.get("payloads", [])
        if payload_override:
            payload = payload_override
        elif payload_list:
            payload = payload_list[0]
        else:
            payload = "VoAPITestPayload"

        runtime_context: Dict[str, Any] = {}
        execution_trace: List[Dict[str, Any]] = []

        is_custom_client = self.client is not None
        client = self.client if is_custom_client else httpx.Client(base_url=self.base_url, timeout=5)

        try:
            # Extract list of sequence steps
            seq_steps = sequence.steps if hasattr(sequence, "steps") else list(sequence)

            # Step 1: Execute sequence prerequisites (producers)
            for step_op in seq_steps[:-1]:
                step_method = step_op.method if hasattr(step_op, "method") else step_op["method"]
                step_path = step_op.path if hasattr(step_op, "path") else step_op["path"]
                step_params = step_op.parameters if hasattr(step_op, "parameters") else step_op.get("parameters", [])

                req_params = {}
                req_json = {}

                # If step_params is a list of param schemas
                if isinstance(step_params, list):
                    for p in step_params:
                        p_meta = p.to_dict() if hasattr(p, "to_dict") else (p if isinstance(p, dict) else {"name": getattr(p, "name", "")})
                        p_name = p_meta.get("name", "")
                        val, _ = sequencer.generate_parameter_value(p_meta, runtime_context=runtime_context)
                        if p_meta.get("in") == "path":
                            step_path = step_path.replace(f"{{{p_name}}}", str(val))
                        elif p_meta.get("in") == "query":
                            req_params[p_name] = val
                        elif p_meta.get("in") == "body":
                            req_json[p_name] = val
                elif isinstance(step_params, dict):
                    for p_name, val in step_params.items():
                        if f"{{{p_name}}}" in step_path:
                            step_path = step_path.replace(f"{{{p_name}}}", str(val))
                        else:
                            req_params[p_name] = val

                st_code, st_body, st_time = self._execute_http(
                    client, step_method, step_path, params=req_params if req_params else None, json_data=req_json if req_json else None
                )

                # Capture produced values
                try:
                    resp_dict = json.loads(st_body)
                    if isinstance(resp_dict, dict):
                        runtime_context.update(resp_dict)
                except Exception:
                    pass

                execution_trace.append({
                    "role": "PRODUCER",
                    "method": step_method,
                    "path": step_path,
                    "status": st_code,
                    "latency_ms": round(st_time, 2)
                })

            # Step 2: Execute Target Candidate API
            cand_params = candidate.all_parameters if hasattr(candidate, "all_parameters") else candidate.get("all_parameters", [])
            if not cand_params and hasattr(candidate, "endpoint") and candidate.endpoint:
                cand_params = candidate.endpoint.parameters

            req_params = {}
            req_json = {}
            files_dict = None

            for p in cand_params:
                p_meta = p.to_dict() if hasattr(p, "to_dict") else (p if isinstance(p, dict) else {
                    "name": getattr(p, "name", ""),
                    "in": getattr(p, "location", "query")
                })
                p_name = p_meta.get("name")
                is_target = (p_name == target_param)

                if is_target:
                    val = payload
                else:
                    if p_name == "url":
                        val = "http://127.0.0.1:8000/api/v1/internal/health"
                    elif p_name == "host":
                        val = "127.0.0.1"
                    elif p_name == "filename":
                        val = "sample.txt"
                    else:
                        val, _ = sequencer.generate_parameter_value(
                            p_meta,
                            is_target_param=False,
                            runtime_context=runtime_context
                        )

                if p_meta.get("in") == "path":
                    cand_path = cand_path.replace(f"{{{p_name}}}", str(val))
                elif p_meta.get("in") == "query":
                    req_params[p_name] = val
                elif p_meta.get("in") == "body":
                    req_json[p_name] = val

            # Special case for File Upload (CWE-434): construct multipart form
            if cwe_id == "CWE-434":
                file_content = b"<?php echo 'VoAPITestPhp'; ?>"
                files_dict = {"file": ("webshell.php", file_content, "application/x-php")}
                req_json = None

            status_code, body_text, latency_ms = self._execute_http(
                client,
                cand_method,
                cand_path,
                params=req_params if req_params else None,
                json_data=req_json if req_json else None,
                files=files_dict
            )

            execution_trace.append({
                "role": "CANDIDATE_TARGET",
                "method": cand_method,
                "path": cand_path,
                "status": status_code,
                "latency_ms": round(latency_ms, 2),
                "payload_injected": payload,
                "target_parameter": target_param
            })

            # Step 3: Triggering Request if needed (VOAPI² Section 3.4.2)
            trigger_status = None
            trigger_body = None

            if cwe_id == "CWE-79":
                trig_code, trig_resp, trig_time = self._execute_http(client, "GET", "/api/v1/vault/audit/logs/view")
                trigger_status = trig_code
                trigger_body = trig_resp
                execution_trace.append({
                    "role": "TRIGGER",
                    "method": "GET",
                    "path": "/api/v1/vault/audit/logs/view",
                    "status": trig_code,
                    "latency_ms": round(trig_time, 2)
                })

            # Step 4: Oracle Evaluation
            verdict, explanation, confidence = VulnerabilityOracle.evaluate(
                cwe_id=cwe_id,
                response_status=status_code,
                response_body=body_text,
                payload_used=str(payload),
                trigger_status=trigger_status,
                trigger_body=trigger_body
            )

            # Build evidence signals
            evidence_signals = []
            if verdict in ("CONFIRMED_VULNERABILITY", "POTENTIAL_VULNERABILITY"):
                evidence_signals.append(f"Oracle Verdict: {verdict} (Confidence: {confidence:.2f})")
                evidence_signals.append(explanation)
                if status_code == 200:
                    evidence_signals.append(f"Target returned HTTP 200 with vulnerable payload reflection / canary leak")

            raw_result = {
                "candidate": {
                    "path": cand_path,
                    "method": cand_method,
                    "cwe_id": cwe_id,
                    "vulnerability_type": cand_vuln_type
                },
                "target_parameter": target_param,
                "payload_used": payload,
                "status_code": status_code,
                "latency_ms": round(latency_ms, 2),
                "verdict": verdict,
                "confidence": confidence,
                "explanation": explanation,
                "analysis": explanation,
                "evidence": evidence_signals,
                "response_preview": body_text[:500],
                "response_body": body_text[:500],
                "execution_trace": execution_trace
            }
            return TestExecutionResult(raw_result)
        finally:
            if not is_custom_client:
                client.close()
