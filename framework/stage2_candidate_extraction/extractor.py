"""
Stage 2: Candidate Interface Extraction Module
Implements the VOAPI² semantic keyword matching algorithm to identify candidate interfaces
and tag target test parameters across the six vulnerability categories (CWE-918, 434, 22, 78, 89, 79).
"""
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

DEFAULT_KEYWORDS_PATH = Path(__file__).resolve().parent.parent.parent / "datasets" / "vulnerability_corpus" / "processed" / "semantic_keywords.json"

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
        # Split on slashes, hyphens, underscores, dots, and camelCase
        s1 = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
        tokens = re.split(r"[/_\-\.\s{}]+", s1)
        return [t.lower() for t in tokens if t]

    def extract_candidates(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Processes normalized endpoints from Stage 1 and identifies candidate APIs
        matching the six vulnerability categories.
        """
        candidate_interfaces: List[Dict[str, Any]] = []

        for ep in endpoints:
            path = ep["path"]
            method = ep["method"]
            path_tokens = set(self._tokenize(path))
            params = ep.get("parameters", [])

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

                for p in params:
                    p_name = p.get("name", "")
                    p_tokens = set(self._tokenize(p_name))
                    matching = [k for k in param_keywords if k in p_tokens or any(k in tok for tok in p_tokens)]
                    if matching:
                        matched_param_kw.extend(matching)
                        tagged_params.append(p_name)

                # Parameter priority ranking: prefer exact matches and required parameters
                # Priority order for known key parameters
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
                priority_score = 0

                if matched_path_kw and tagged_params:
                    # Condition 1: Both path and param keywords match (Highest Confidence)
                    is_candidate = True
                    priority_score = 3
                    reason = f"Path matched {matched_path_kw} and parameters matched {list(set(matched_param_kw))}"
                elif matched_path_kw and not tagged_params and params:
                    # Condition 2: Path matched, but no specific parameter matched -> tag all parameters
                    is_candidate = True
                    priority_score = 2
                    tagged_params = [p.get("name") for p in params if p.get("name")]
                    reason = f"Path matched {matched_path_kw}; all {len(tagged_params)} parameters designated for testing"
                elif tagged_params and any(p.lower() in [pref for pref in PRIMARY_PARAMS.get(cwe_id, [])] for p in tagged_params):
                    # Condition 3: Primary target parameter matched keyword
                    is_candidate = True
                    priority_score = 1
                    reason = f"Parameters matched {list(set(matched_param_kw))}"

                if is_candidate and tagged_params:
                    candidate_interfaces.append({
                        "path": path,
                        "method": method,
                        "operation_id": ep.get("operation_id", ""),
                        "cwe_id": cwe_id,
                        "vulnerability_type": vuln_name,
                        "api_type": api_type,
                        "priority_score": priority_score,
                        "target_parameters": tagged_params,
                        "all_parameters": params,
                        "matched_path_keywords": list(set(matched_path_kw)),
                        "matched_param_keywords": list(set(matched_param_kw)),
                        "selection_reason": reason
                    })

        # Sort candidates: highest priority score first
        candidate_interfaces.sort(key=lambda x: x.get("priority_score", 0), reverse=True)
        return candidate_interfaces

    def get_breakdown(self, candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Provides category distribution summary of extracted candidates."""
        counts: Dict[str, int] = {}
        for c in candidates:
            cwe = c["cwe_id"]
            counts[cwe] = counts.get(cwe, 0) + 1
        return {
            "total_candidate_interfaces": len(candidates),
            "by_cwe": counts
        }
