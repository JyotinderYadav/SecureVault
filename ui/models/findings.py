"""
Findings Model & Data Loader for SecureVault UI
Ensures robust deserialization of test result logs, providing uniform dictionary
and attribute access across all evaluation runs without type mismatches.
"""
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Union


class FindingRecord(dict):
    """
    Normalized vulnerability finding record supporting both dict access and properties.
    Ensures backwards compatibility between legacy and modernized log schemas.
    """
    def __init__(self, data: Dict[str, Any]):
        super().__init__(data)
        self._data = dict(data)
        
        # Normalize nested candidate
        cand = self._data.get("candidate", {})
        if not isinstance(cand, dict):
            cand = {}
            
        cwe = (
            cand.get("cwe_id")
            or cand.get("cwe_category")
            or self._data.get("cwe_id")
            or self._data.get("cwe_category")
            or "CWE-UNKNOWN"
        )
        path = (
            cand.get("path")
            or cand.get("endpoint_path")
            or self._data.get("endpoint_path")
            or self._data.get("path")
            or ""
        )
        method = (
            cand.get("method")
            or cand.get("endpoint_method")
            or self._data.get("endpoint_method")
            or self._data.get("method")
            or "GET"
        )
        vuln_type = (
            cand.get("vulnerability_type")
            or self._data.get("vulnerability_type")
            or ""
        )
        target_param = (
            self._data.get("target_parameter")
            or self._data.get("primary_parameter")
            or cand.get("primary_parameter")
            or ""
        )
        payload = (
            self._data.get("payload_used")
            or self._data.get("payload")
            or ""
        )
        explanation = (
            self._data.get("explanation")
            or self._data.get("analysis")
            or ""
        )
        verdict = self._data.get("verdict", "INCONCLUSIVE")
        status_code = int(self._data.get("status_code", 0))
        latency = float(self._data.get("latency_ms", 0.0))
        confidence = float(self._data.get("confidence", 1.0))
        preview = self._data.get("response_preview", self._data.get("response_body", ""))

        # Synthesize evidence if missing
        evidence = self._data.get("evidence", [])
        if not evidence and verdict in ("CONFIRMED_VULNERABILITY", "POTENTIAL_VULNERABILITY"):
            evidence = [
                f"Oracle Verdict: {verdict} (Confidence: {confidence:.2f})",
                explanation
            ]
            if status_code == 200:
                evidence.append(f"HTTP 200 OK returned with target reflection / leaked data")

        # Update dictionary entries for seamless dict indexing
        self["candidate"] = {
            "path": path,
            "endpoint_path": path,
            "method": method,
            "endpoint_method": method,
            "cwe_id": cwe,
            "cwe_category": cwe,
            "vulnerability_type": vuln_type,
            "primary_parameter": target_param
        }
        self["cwe_id"] = cwe
        self["cwe_category"] = cwe
        self["endpoint_path"] = path
        self["endpoint_method"] = method
        self["primary_parameter"] = target_param
        self["target_parameter"] = target_param
        self["payload"] = payload
        self["payload_used"] = payload
        self["verdict"] = verdict
        self["explanation"] = explanation
        self["analysis"] = explanation
        self["status_code"] = status_code
        self["latency_ms"] = latency
        self["confidence"] = confidence
        self["evidence"] = evidence
        self["response_preview"] = preview
        self["response_body"] = preview

    @property
    def cwe_id(self) -> str:
        return self["cwe_id"]

    @property
    def cwe_category(self) -> str:
        return self["cwe_category"]

    @property
    def endpoint_path(self) -> str:
        return self["endpoint_path"]

    @property
    def endpoint_method(self) -> str:
        return self["endpoint_method"]

    @property
    def target_parameter(self) -> str:
        return self["target_parameter"]

    @property
    def primary_parameter(self) -> str:
        return self["primary_parameter"]

    @property
    def payload(self) -> str:
        return self["payload"]

    @property
    def verdict(self) -> str:
        return self["verdict"]

    @property
    def analysis(self) -> str:
        return self["analysis"]

    @property
    def explanation(self) -> str:
        return self["explanation"]

    @property
    def status_code(self) -> int:
        return self["status_code"]

    @property
    def latency_ms(self) -> float:
        return self["latency_ms"]

    @property
    def confidence(self) -> float:
        return self["confidence"]

    @property
    def evidence(self) -> List[str]:
        return self["evidence"]

    @property
    def response_preview(self) -> str:
        return self["response_preview"]

    @property
    def response_body(self) -> str:
        return self["response_body"]


def load_finding_records(file_path: Union[str, Path]) -> List[FindingRecord]:
    """
    Safely loads finding records from a JSON log file, unpacking top-level
    'results' lists or direct record lists.
    """
    path = Path(file_path)
    if not path.exists():
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    raw_list: List[Any] = []
    if isinstance(data, dict):
        raw_list = data.get("results", [])
    elif isinstance(data, list):
        raw_list = data

    records: List[FindingRecord] = []
    for item in raw_list:
        if isinstance(item, dict):
            records.append(FindingRecord(item))

    return records

