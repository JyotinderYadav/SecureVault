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
from framework.stage3_sequence_generation.sequencer import TestSequenceGenerator

DEFAULT_PAYLOADS_PATH = Path(__file__).resolve().parent.parent.parent / "datasets" / "vulnerability_corpus" / "processed" / "test_payloads.json"

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

    def run_candidate_test(
        self,
        candidate: Dict[str, Any],
        sequence: List[Dict[str, Any]],
        sequencer: TestSequenceGenerator,
        payload_override: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes the full test sequence for a candidate interface:
        1. Executes prerequisite producer steps, capturing context values
        2. Executes the candidate target request with payload injection
        3. Executes triggering requests if required (e.g. for stored XSS)
        4. Calls oracle to determine verdict
        """
        cwe_id = candidate["cwe_id"]
        target_param = candidate["target_parameters"][0] if candidate.get("target_parameters") else None

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
            # Step 1: Execute sequence prerequisites (producers)
            for step_op in sequence[:-1]:
                step_method = step_op["method"]
                step_path = step_op["path"]
                step_params = step_op.get("parameters", [])

                req_params = {}
                req_json = {}

                for p in step_params:
                    val, _ = sequencer.generate_parameter_value(p, runtime_context=runtime_context)
                    if p.get("in") == "path":
                        step_path = step_path.replace(f"{{{p['name']}}}", str(val))
                    elif p.get("in") == "query":
                        req_params[p["name"]] = val
                    elif p.get("in") == "body":
                        req_json[p["name"]] = val

                st_code, st_body, st_time = self._execute_http(
                    client, step_method, step_path, params=req_params, json_data=req_json if req_json else None
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
            cand_method = candidate["method"]
            cand_path = candidate["path"]
            cand_params = candidate.get("all_parameters", [])

            req_params = {}
            req_json = {}
            files_dict = None

            for p in cand_params:
                p_name = p.get("name")
                is_target = (p_name == target_param)

                if is_target:
                    val = payload
                    strategy = "TARGET_INJECTION"
                else:
                    # Provide sensible valid defaults for known required fields when not being injected
                    if p_name == "url":
                        val = "http://127.0.0.1:8000/api/v1/internal/health"
                        strategy = "FALLBACK_URL"
                    elif p_name == "host":
                        val = "127.0.0.1"
                        strategy = "FALLBACK_HOST"
                    elif p_name == "filename":
                        val = "sample.txt"
                        strategy = "FALLBACK_FILENAME"
                    else:
                        val, strategy = sequencer.generate_parameter_value(
                            p,
                            is_target_param=False,
                            runtime_context=runtime_context
                        )

                if p.get("in") == "path":
                    cand_path = cand_path.replace(f"{{{p_name}}}", str(val))
                elif p.get("in") == "query":
                    req_params[p_name] = val
                elif p.get("in") == "body":
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
                # Stored XSS trigger: read audit logs
                trig_code, trig_resp, trig_time = self._execute_http(client, "GET", "/api/v1/vault/audit/logs")
                trigger_status = trig_code
                trigger_body = trig_resp
                execution_trace.append({
                    "role": "TRIGGER",
                    "method": "GET",
                    "path": "/api/v1/vault/audit/logs",
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

            return {
                "candidate": {
                    "path": candidate["path"],
                    "method": candidate["method"],
                    "cwe_id": cwe_id,
                    "vulnerability_type": candidate.get("vulnerability_type", "")
                },
                "target_parameter": target_param,
                "payload_used": payload,
                "status_code": status_code,
                "latency_ms": round(latency_ms, 2),
                "verdict": verdict,
                "confidence": confidence,
                "explanation": explanation,
                "response_preview": body_text[:300],
                "execution_trace": execution_trace
            }
        finally:
            if not is_custom_client:
                client.close()
