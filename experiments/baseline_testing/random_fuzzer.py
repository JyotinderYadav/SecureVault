"""
Baseline Generic API Fuzzer
Implements unguided/random black-box REST API testing as a comparative baseline against VOAPI².
Sends indiscriminate generic test inputs and random fuzz strings without vulnerability orientation.
"""
import random
import string
import time
from typing import Dict, List, Any, Optional
from framework.stage4_feedback_testing.oracles import VulnerabilityOracle

GENERIC_FUZZ_STRINGS = [
    "",
    "A" * 500,
    "%s%p%x%d",
    "'",
    "\"",
    "<tag>",
    "null",
    "NaN",
    "-1",
    "9999999999",
    "true",
    "false",
    "0",
    "undefined",
    "../../",
    "http://example.com"
]

class BaselineRandomFuzzer:
    def __init__(self, endpoints: List[Dict[str, Any]], client: Any):
        self.endpoints = endpoints
        self.client = client

    def _execute_http(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None
    ):
        t0 = time.perf_counter()
        m = method.upper()
        if hasattr(self.client, "request"):
            resp = self.client.request(m, path, params=params, json=json_data, files=files)
        else:
            func = getattr(self.client, m.lower())
            resp = func(path, params=params, json=json_data, files=files)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return resp.status_code, resp.text, elapsed_ms

    def run_fuzzing(self, max_requests_per_endpoint: int = 5) -> Dict[str, Any]:
        """
        Executes generic indiscriminate fuzzing across all endpoints.
        """
        total_requests = 0
        total_time_ms = 0.0
        findings = []
        execution_trace = []

        for ep in self.endpoints:
            method = ep["method"]
            path_template = ep["path"]
            params_meta = ep.get("parameters", [])

            for _ in range(max_requests_per_endpoint):
                req_path = path_template
                req_params = {}
                req_json = {}
                files_dict = None

                fuzz_val = random.choice(GENERIC_FUZZ_STRINGS)

                for p in params_meta:
                    p_name = p.get("name")
                    p_in = p.get("in", "query")

                    # Indiscriminate value generation without semantic awareness
                    if p.get("type") == "integer":
                        val = random.choice([0, -1, 99999, 1])
                    elif p.get("type") == "boolean":
                        val = random.choice([True, False])
                    else:
                        val = fuzz_val

                    if p_in == "path":
                        req_path = req_path.replace(f"{{{p_name}}}", str(val))
                    elif p_in == "query":
                        req_params[p_name] = val
                    elif p_in == "body":
                        req_json[p_name] = val

                if method == "POST" and "upload" in path_template:
                    files_dict = {"file": ("random_test.bin", b"RandomFuzzBytes", "application/octet-stream")}
                    req_json = None

                try:
                    status_code, body_text, latency = self._execute_http(
                        method, req_path, params=req_params if req_params else None, json_data=req_json if req_json else None, files=files_dict
                    )
                    total_requests += 1
                    total_time_ms += latency

                    # Check generic 500 error or accidental trigger
                    cwe_detected = None
                    if status_code == 500:
                        cwe_detected = "CWE-Generic-ServerError"
                    elif "root:x:" in body_text or "VAULT_SECRET_KEY" in body_text:
                        cwe_detected = "CWE-22"
                    elif "VoAPICmdTest" in body_text:
                        cwe_detected = "CWE-78"

                    if cwe_detected:
                        findings.append({
                            "path": path_template,
                            "method": method,
                            "cwe": cwe_detected,
                            "status": status_code,
                            "payload": fuzz_val,
                            "latency_ms": round(latency, 2)
                        })

                    execution_trace.append({
                        "method": method,
                        "path": req_path,
                        "status": status_code,
                        "payload": fuzz_val,
                        "latency_ms": round(latency, 2)
                    })
                except Exception:
                    total_requests += 1

        return {
            "strategy": "BASELINE_RANDOM_FUZZING",
            "total_requests": total_requests,
            "total_time_ms": round(total_time_ms, 2),
            "findings_count": len(findings),
            "findings": findings,
            "execution_trace": execution_trace
        }
