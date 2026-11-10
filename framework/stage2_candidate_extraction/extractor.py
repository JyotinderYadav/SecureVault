"""
Stage 2: Candidate Interface Extraction Module
Implements the VOAPI² semantic keyword matching algorithm to identify candidate interfaces
and tag target test parameters across the six vulnerability categories (CWE-918, 434, 22, 78, 89, 79).
"""
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from framework.stage1_spec_analysis.parser import EndpointSchema

DEFAULT_KEYWORDS_PATH = Path(__file__).resolve().parent.parent.parent / "datasets" / "vulnerability_corpus" / "processed" / "semantic_keywords.json"


class CandidateInterface(dict):
    """
    Dual dict and object representation of an extracted candidate interface.
    Supports:
    - Dict access: c["cwe_id"], c["path"], c["method"], c["target_parameters"], etc.
    - Object access: c.endpoint, c.cwe_category, c.cwe_id, c.primary_parameter, c.score, etc.
    """
    def __init__(self, data: Dict[str, Any], endpoint_schema: Optional[EndpointSchema] = None):
        super().__init__(data)
        self._data = data
        if endpoint_schema is not None:
            self._endpoint = endpoint_schema
        else:
            self._endpoint = EndpointSchema(
                path=data.get("path", ""),
                method=data.get("method", "GET"),
                parameters=data.get("all_parameters", []),
                operation_id=data.get("operation_id", ""),
                summary=data.get("summary", "")
            )

    @property
    def endpoint(self) -> EndpointSchema:
        return self._endpoint

    @property
    def cwe_category(self) -> str:
        return self._data.get("cwe_id", self._data.get("cwe_category", ""))

    @property
    def cwe_id(self) -> str:
        return self.cwe_category

    @property
    def primary_parameter(self) -> Optional[str]:
        target_params = self._data.get("target_parameters", [])
        if target_params:
            return target_params[0]
        return self._data.get("primary_parameter")

    @property
    def target_parameters(self) -> List[str]:
        return self._data.get("target_parameters", [])

    @property
    def score(self) -> float:
        return float(self._data.get("priority_score", self._data.get("score", 0.0)))

    @property
    def priority_score(self) -> float:
        return self.score

    @property
    def matched_path_keywords(self) -> List[str]:
        return self._data.get("matched_path_keywords", [])

    @property
    def matched_param_keywords(self) -> List[str]:
        return self._data.get("matched_param_keywords", [])

    @property
    def path(self) -> str:
        return self._data.get("path", "")

    @property
    def method(self) -> str:
        return self._data.get("method", "GET")

    @property
    def vulnerability_type(self) -> str:
        return self._data.get("vulnerability_type", "")

    @property
    def api_type(self) -> str:
        return self._data.get("api_type", "")

    @property
    def selection_reason(self) -> str:
        return self._data.get("selection_reason", "")


class CandidateInterfaceExtractor:
    def __init__(self, keywords_file: Optional[Path] = None):
        self.keywords_path = keywords_file or DEFAULT_KEYWORDS_PATH
        self.keyword_mappings: Dict[str, Any] = self._load_keywords()

    def _load_keywords(self) -> Dict[str, Any]:
        if self.keywords_path.exists():
            with open(self.keywords_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("keyword_mappings", {})
        # Fallback keyword definitions directly from Table 2 / VoAPIGlobalData.py
        return {
            "CWE-918": {
                "vulnerability_type": "Server-Side Request Forgery",
                "api_type": "Resource Request APIs",
                "path_keywords": ["host", "link", "proxy", "fetch", "redirect", "callback", "hook", "img", "image", "connect"],
                "param_keywords": ["url", "uri", "host", "endpoint", "path", "href", "link", "proxy", "client", "remote", "fetch", "dest", "redirect", "site", "callback", "hook", "img", "image", "access", "domain", "agent", "ping"]
            },
            "CWE-434": {
                "vulnerability_type": "Unrestricted Upload of File",
                "api_type": "File Upload APIs",
                "path_keywords": ["upload", "import", "file", "pic", "image", "img", "content", "page", "avatar", "attach", "submit", "post"],
                "param_keywords": ["upload", "file", "path", "category", "dir", "pic", "image", "img"]
            },
            "CWE-22": {
                "vulnerability_type": "Path Traversal",
                "api_type": "Path Processing APIs",
                "path_keywords": ["download", "export", "fetch", "file", "path", "category"],
                "param_keywords": ["file", "path", "category"]
            },
            "CWE-78": {
                "vulnerability_type": "OS Command Injection",
                "api_type": "System Configuration APIs",
                "path_keywords": ["set", "command", "cmd", "conf", "cfg", "rpc", "exec", "diagnose", "ping", "system", "ip", "nslookup"],
                "param_keywords": ["set", "command", "cmd", "exec", "ping", "ip", "nslookup"]
            },
            "CWE-89": {
                "vulnerability_type": "SQL Injection",
                "api_type": "Database Operation APIs",
                "path_keywords": ["sql", "database", "db", "query", "list", "search", "order", "select", "table", "column", "row"],
                "param_keywords": ["sql", "query", "id", "select", "field"]
            },
            "CWE-79": {
                "vulnerability_type": "Cross-Site Scripting",
                "api_type": "Text Display APIs",
                "path_keywords": ["name", "content", "edit", "desc", "title", "view", "html", "link", "display", "code", "text", "tab", "comment", "tag", "note"],
                "param_keywords": ["name", "content", "desc", "title", "view", "html", "code", "text", "tab", "comment", "tag", "note"]
            }
        }

    def _tokenize(self, text: str) -> List[str]:
        """Splits path or identifier into lowercase semantic tokens."""
        s1 = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
        tokens = re.split(r"[/_\-\.\s{}]+", s1)
        return [t.lower() for t in tokens if t]

    def extract(self, endpoints: List[Any]) -> List[CandidateInterface]:
        """Convenience alias for extract_candidates matching UI view invocations."""
        return self.extract_candidates(endpoints)

    def extract_candidates(self, endpoints: List[Any]) -> List[CandidateInterface]:
        """
        Processes normalized endpoints from Stage 1 and identifies candidate APIs
        matching the six vulnerability categories.
        """
        candidate_interfaces: List[CandidateInterface] = []

        for ep in endpoints:
            # Handle both EndpointSchema objects and dicts
            path = ep.path if hasattr(ep, "path") else ep["path"]
            method = ep.method if hasattr(ep, "method") else ep["method"]
            op_id = ep.operation_id if hasattr(ep, "operation_id") else ep.get("operation_id", "")
            summary = ep.summary if hasattr(ep, "summary") else ep.get("summary", "")
            params = ep.parameters if hasattr(ep, "parameters") else ep.get("parameters", [])

            # Normalize params to dicts if they are ParameterSchema objects
            norm_params = []
            for p in params:
                if hasattr(p, "to_dict"):
                    norm_params.append(p.to_dict())
                elif isinstance(p, dict):
                    norm_params.append(dict(p))
                elif hasattr(p, "name"):
                    p_in = getattr(p, "location", getattr(p, "in_", getattr(p, "in", "query")))
                    norm_params.append({
                        "name": p.name,
                        "in": p_in,
                        "required": getattr(p, "required", False),
                        "type": getattr(p, "param_type", getattr(p, "type", "string"))
                    })
                else:
                    norm_params.append(p)

            path_tokens = set(self._tokenize(path))

            for cwe_id, cwe_meta in self.keyword_mappings.items():
                vuln_name = cwe_meta.get("vulnerability_type", cwe_id)
                api_type = cwe_meta.get("api_type", "")
                path_keywords = set(k.lower() for k in cwe_meta.get("path_keywords", []))
                param_keywords = set(k.lower() for k in cwe_meta.get("param_keywords", []))

                # 1. Match Path Keywords
                matched_path_kw = [k for k in path_keywords if k in path_tokens or any(k in tok for tok in path_tokens)]

                # 2. Match Parameter Keywords
                matched_param_kw = []
                tagged_params = []

                for p in norm_params:
                    p_name = p.get("name", "")
                    p_tokens = set(self._tokenize(p_name))
                    matching = [k for k in param_keywords if k in p_tokens or any(k in tok for tok in p_tokens)]
                    if matching:
                        matched_param_kw.extend(matching)
                        tagged_params.append(p_name)

                # Parameter priority ranking: prefer exact matches and required parameters
                PRIMARY_PARAMS = {
                    "CWE-918": ["url", "uri", "endpoint", "link", "remote", "proxy", "host"],
                    "CWE-434": ["file", "upload", "attachment", "pic"],
                    "CWE-22":  ["filename", "path", "file", "download"],
                    "CWE-78":  ["host", "cmd", "command", "ip", "ping", "system"],
                    "CWE-89":  ["query", "search", "id", "sql", "select"],
                    "CWE-79":  ["content", "comment", "desc", "title", "text", "name"]
                }

                if tagged_params:
                    preferred = PRIMARY_PARAMS.get(cwe_id, [])
                    tagged_params.sort(
                        key=lambda p: (
                            0 if any(p.lower() == pref for pref in preferred) else
                            1 if any(pref in p.lower() for pref in preferred) else 2
                        )
                    )

                # VOAPI² Decision Logic (Section 3.2):
                is_candidate = False
                reason = ""
                priority_score = 0.0

                if matched_path_kw and tagged_params:
                    # Condition 1: Both path and param keywords match (Highest Confidence)
                    is_candidate = True
                    priority_score = 3.0
                    reason = f"Path matched {matched_path_kw} and parameters matched {list(set(matched_param_kw))}"
                elif matched_path_kw and not tagged_params and norm_params:
                    # Condition 2: Path matched, but no specific parameter matched -> tag all parameters
                    is_candidate = True
                    priority_score = 2.0
                    tagged_params = [p.get("name") for p in norm_params if p.get("name")]
                    reason = f"Path matched {matched_path_kw}; all {len(tagged_params)} parameters designated for testing"
                elif tagged_params and any(p.lower() in [pref for pref in PRIMARY_PARAMS.get(cwe_id, [])] for p in tagged_params):
                    # Condition 3: Primary target parameter matched keyword
                    is_candidate = True
                    priority_score = 1.0
                    reason = f"Parameters matched {list(set(matched_param_kw))}"

                if is_candidate and tagged_params:
                    cand_data = {
                        "path": path,
                        "method": method,
                        "operation_id": op_id,
                        "summary": summary,
                        "cwe_id": cwe_id,
                        "cwe_category": cwe_id,
                        "vulnerability_type": vuln_name,
                        "api_type": api_type,
                        "priority_score": priority_score,
                        "score": priority_score,
                        "primary_parameter": tagged_params[0],
                        "target_parameters": tagged_params,
                        "all_parameters": norm_params,
                        "matched_path_keywords": list(set(matched_path_kw)),
                        "matched_param_keywords": list(set(matched_param_kw)),
                        "selection_reason": reason
                    }
                    ep_schema = ep if isinstance(ep, EndpointSchema) else None
                    candidate_interfaces.append(CandidateInterface(cand_data, endpoint_schema=ep_schema))

        # Sort candidates: highest priority score first
        candidate_interfaces.sort(key=lambda x: x.score, reverse=True)
        return candidate_interfaces

    def count_by_category(self, candidates: List[Any]) -> Dict[str, int]:
        """Provides category distribution mapping for charts and filters."""
        counts: Dict[str, int] = {
            "CWE-918": 0,
            "CWE-434": 0,
            "CWE-22": 0,
            "CWE-78": 0,
            "CWE-89": 0,
            "CWE-79": 0
        }
        for c in candidates:
            cwe = c.cwe_category if hasattr(c, "cwe_category") else c.get("cwe_id", c.get("cwe_category", "Unknown"))
            counts[cwe] = counts.get(cwe, 0) + 1
        return counts

    def get_breakdown(self, candidates: List[Any]) -> Dict[str, Any]:
        """Provides category distribution summary of extracted candidates."""
        counts = self.count_by_category(candidates)
        return {
            "total_candidate_interfaces": len(candidates),
            "by_cwe": counts
        }
