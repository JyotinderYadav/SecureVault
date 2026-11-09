"""
Stage 4: Feedback Detection Oracles Module
Implements multi-signal feedback analysis for vulnerability verification:
  - Status code transitions
  - Response body signature matching
  - Canary reflections
  - Triggering request confirmations
"""
import re
from typing import Dict, Any, Tuple, Optional

class VulnerabilityOracle:
    """
    Evaluates response evidence and returns a conservative verdict:
      - CONFIRMED_VULNERABILITY
      - POTENTIAL_VULNERABILITY
      - NEGATIVE
      - INCONCLUSIVE
    """

    @staticmethod
    def evaluate(
        cwe_id: str,
        response_status: int,
        response_body: str,
        payload_used: str,
        trigger_status: Optional[int] = None,
        trigger_body: Optional[str] = None
    ) -> Tuple[str, str, float]:
        """
        Returns (verdict, explanation, confidence_score [0.0 - 1.0]).
        """
        body_lower = response_body.lower()

        # ----------------------------------------------------
        # 1. CWE-918: Server-Side Request Forgery (SSRF)
        # ----------------------------------------------------
        if cwe_id == "CWE-918":
            # Conclusive: Internal loopback secret flag or sensitive metadata in response
            if "secvault_flag_{ssrf" in body_lower or "loopback_reached" in body_lower or "vaultinternalkeyrelease" in body_lower:
                return "CONFIRMED_VULNERABILITY", "SSRF triggered: internal service response and private loopback flag exposed.", 1.0
            if response_status == 200 and ("127.0.0.1" in payload_used or "localhost" in payload_used or "169.254" in payload_used):
                if len(response_body.strip()) > 0 and "error" not in body_lower:
                    return "CONFIRMED_VULNERABILITY", "SSRF confirmed: successful HTTP 200 retrieval from loopback/metadata address.", 0.95
            if response_status in [400, 403] and ("blocked" in body_lower or "private" in body_lower or "forbidden" in body_lower):
                return "NEGATIVE", "Defended: Destination address strictly blocked by network validation policy.", 0.95
            if response_status == 502:
                return "NEGATIVE", "Connection refused / target unreachable (no SSRF leakage).", 0.8
            return "INCONCLUSIVE", f"Ambiguous HTTP {response_status} response.", 0.4

        # ----------------------------------------------------
        # 2. CWE-434: Unrestricted File Upload
        # ----------------------------------------------------
        if cwe_id == "CWE-434":
            if response_status in [200, 201]:
                if '"is_executable":true' in response_body or '"is_executable": true' in response_body or "dangerous executable" in body_lower:
                    return "CONFIRMED_VULNERABILITY", "Unrestricted Upload confirmed: dangerous executable extension accepted and stored.", 1.0
                if any(ext in payload_used.lower() for ext in [".php", ".jsp", ".asp", ".aspx", ".sh"]):
                    return "POTENTIAL_VULNERABILITY", "Script upload returned HTTP 200 without explicit rejection.", 0.75
            if response_status in [400, 403, 415]:
                return "NEGATIVE", "Defended: Upload rejected by extension or MIME type whitelist.", 0.95
            return "INCONCLUSIVE", f"Upload returned HTTP {response_status}.", 0.5

        # ----------------------------------------------------
        # 3. CWE-22: Path Traversal
        # ----------------------------------------------------
        if cwe_id == "CWE-22":
            if "vault_secret_key" in body_lower or "root:x:" in body_lower or "[fonts]" in body_lower or "secvault_flag_{path" in body_lower:
                return "CONFIRMED_VULNERABILITY", "Path Traversal confirmed: unauthorized file contents leaked from outside root.", 1.0
            if response_status in [400, 403] and ("traversal" in body_lower or "violation" in body_lower or "forbidden" in body_lower):
                return "NEGATIVE", "Defended: Traversal sequence blocked by canonical path verification.", 0.95
            if response_status == 404:
                return "NEGATIVE", "Target file not found / path resolution contained.", 0.85
            return "INCONCLUSIVE", f"Response HTTP {response_status} with no signature match.", 0.4

        # ----------------------------------------------------
        # 4. CWE-78: OS Command Injection
        # ----------------------------------------------------
        if cwe_id == "CWE-78":
            if "voapicmdtest" in body_lower:
                return "CONFIRMED_VULNERABILITY", "Command Injection confirmed: injected probe string 'VoAPICmdTest' executed and reflected in output.", 1.0
            if response_status in [400, 403] and ("metacharacters" in body_lower or "invalid" in body_lower):
                return "NEGATIVE", "Defended: Shell metacharacters rejected by input validation.", 0.95
            if response_status == 200 and "echo" in body_lower:
                return "POTENTIAL_VULNERABILITY", "Command executed without error, but probe output not definitively matched.", 0.6
            return "NEGATIVE", "Command injection not triggered.", 0.85

        # ----------------------------------------------------
        # 5. CWE-89: SQL Injection
        # ----------------------------------------------------
        if cwe_id == "CWE-89":
            # Tautology check: returned multiple confidential records when given tautology
            if response_status == 200:
                if '"count":' in response_body or '"count": ' in response_body:
                    match = re.search(r'"count":\s*(\d+)', response_body)
                    count_val = int(match.group(1)) if match else 0
                    if count_val >= 3 and ("' or '" in payload_used.lower() or '" or "' in payload_used.lower()):
                        return "CONFIRMED_VULNERABILITY", f"SQL Injection confirmed: boolean tautology bypass returned {count_val} records.", 1.0
                    if count_val == 0:
                        return "NEGATIVE", "Defended: Parameterized query treated input as literal string.", 0.95
            if response_status == 500 and ("syntax error" in body_lower or "sqlite" in body_lower or "sql" in body_lower):
                return "POTENTIAL_VULNERABILITY", "SQL Injection potential: unhandled database error message exposed in response.", 0.85
            return "NEGATIVE", "No SQL injection symptoms detected.", 0.85

        # ----------------------------------------------------
        # 6. CWE-79: Cross-Site Scripting (XSS)
        # ----------------------------------------------------
        if cwe_id == "CWE-79":
            # Check for raw unescaped script/img reflection in trigger or primary response
            eval_body = trigger_body if trigger_body else response_body
            if "<script>alert('voapitestxss')</script>" in eval_body.lower() or "<svg/onload=alert('voapitestxss')>" in eval_body.lower() or "<img src=x onerror=alert('voapitestxss')>" in eval_body.lower():
                return "CONFIRMED_VULNERABILITY", "XSS confirmed: unescaped executable script payload stored and reflected in markup.", 1.0
            if "&lt;script&gt;" in eval_body.lower() or "&lt;img" in eval_body.lower():
                return "NEGATIVE", "Defended: HTML entities properly escaped and sanitized.", 0.95
            return "NEGATIVE", "Payload safely escaped or not reflected.", 0.85

        return "INCONCLUSIVE", "Unknown vulnerability category or inconclusive feedback.", 0.3
