"""
Integration Tests for the VOAPI² 4-Stage Security Testing Pipeline
Verifies Stages 1-4 end-to-end against the local SecureVault testbed.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from config.settings import system_config
from framework import (
    OpenAPISpecParser,
    CandidateInterfaceExtractor,
    TestSequenceGenerator,
    FeedbackTestRunner
)

@pytest.fixture
def api_spec():
    parser = OpenAPISpecParser(app.openapi())
    parser.analyze()
    return parser

@pytest.fixture
def test_client():
    return TestClient(app)

def test_stage1_spec_analysis(api_spec):
    summary = api_spec.get_summary()
    assert summary["total_endpoints"] >= 10
    paths = [ep["path"] for ep in api_spec.endpoints]
    assert "/api/v1/vault/sync" in paths
    assert "/api/v1/vault/upload" in paths
    assert "/api/v1/vault/files/read" in paths
    assert "/api/v1/vault/tools/ping-backup" in paths
    assert "/api/v1/vault/records/search" in paths
    assert "/api/v1/vault/audit/logs" in paths

def test_stage2_candidate_extraction(api_spec):
    extractor = CandidateInterfaceExtractor()
    candidates = extractor.extract_candidates(api_spec.endpoints)
    assert len(candidates) > 0
    
    cwes_found = set(c["cwe_id"] for c in candidates)
    for target_cwe in ["CWE-918", "CWE-434", "CWE-22", "CWE-78", "CWE-89", "CWE-79"]:
        assert target_cwe in cwes_found

def test_stage3_sequence_generation(api_spec):
    sequencer = TestSequenceGenerator(api_spec.endpoints)
    consumer = [ep for ep in api_spec.endpoints if ep["path"] == "/api/v1/vault/items/{id}" and ep["method"] == "GET"][0]
    seq = sequencer.generate_sequence(consumer)
    
    # Must precede consumer with POST /api/v1/vault/items
    assert len(seq) == 2
    assert seq[0]["method"] == "POST"
    assert seq[0]["path"] == "/api/v1/vault/items"
    assert seq[1]["method"] == "GET"
    assert seq[1]["path"] == "/api/v1/vault/items/{id}"

def test_stage4_end_to_end_vulnerable(api_spec, test_client):
    system_config.set_mode("VULNERABLE")
    extractor = CandidateInterfaceExtractor()
    candidates = extractor.extract_candidates(api_spec.endpoints)
    sequencer = TestSequenceGenerator(api_spec.endpoints)
    runner = FeedbackTestRunner(client=test_client)

    # Primary endpoints mapped to each CWE
    PRIMARY_TARGETS = {
        "CWE-918": "/api/v1/vault/sync",
        "CWE-434": "/api/v1/vault/upload",
        "CWE-22":  "/api/v1/vault/files/read",
        "CWE-78":  "/api/v1/vault/tools/ping-backup",
        "CWE-89":  "/api/v1/vault/records/search",
        "CWE-79":  "/api/v1/vault/audit/logs"
    }

    verdicts = {}
    for cwe, path in PRIMARY_TARGETS.items():
        matching = [c for c in candidates if c["cwe_id"] == cwe and c["path"] == path]
        if matching:
            cand = matching[0]
            seq = sequencer.generate_sequence(cand)
            res = runner.run_candidate_test(cand, seq, sequencer)
            verdicts[cwe] = res["verdict"]

    # In VULNERABLE mode, all 6 target endpoints should trigger CONFIRMED or POTENTIAL
    assert verdicts["CWE-918"] in ["CONFIRMED_VULNERABILITY", "POTENTIAL_VULNERABILITY"]
    assert verdicts["CWE-434"] in ["CONFIRMED_VULNERABILITY", "POTENTIAL_VULNERABILITY"]
    assert verdicts["CWE-22"] in ["CONFIRMED_VULNERABILITY", "POTENTIAL_VULNERABILITY"]
    assert verdicts["CWE-78"] in ["CONFIRMED_VULNERABILITY", "POTENTIAL_VULNERABILITY"]
    assert verdicts["CWE-89"] in ["CONFIRMED_VULNERABILITY", "POTENTIAL_VULNERABILITY"]
    assert verdicts["CWE-79"] in ["CONFIRMED_VULNERABILITY", "POTENTIAL_VULNERABILITY"]

def test_stage4_end_to_end_hardened(api_spec, test_client):
    system_config.set_mode("HARDENED")
    # Clean audit logs so prior vulnerable test runs do not taint trigger evaluation
    from app.core.database import get_db_connection
    conn = get_db_connection()
    conn.cursor().execute("DELETE FROM audit_logs WHERE title LIKE '%VoAPI%' OR content LIKE '%VoAPI%' OR content LIKE '%<script>%';")
    conn.commit()
    conn.close()

    extractor = CandidateInterfaceExtractor()
    candidates = extractor.extract_candidates(api_spec.endpoints)
    sequencer = TestSequenceGenerator(api_spec.endpoints)
    runner = FeedbackTestRunner(client=test_client)

    PRIMARY_TARGETS = {
        "CWE-918": "/api/v1/vault/sync",
        "CWE-434": "/api/v1/vault/upload",
        "CWE-22":  "/api/v1/vault/files/read",
        "CWE-78":  "/api/v1/vault/tools/ping-backup",
        "CWE-89":  "/api/v1/vault/records/search",
        "CWE-79":  "/api/v1/vault/audit/logs"
    }

    verdicts = {}
    for cwe, path in PRIMARY_TARGETS.items():
        matching = [c for c in candidates if c["cwe_id"] == cwe and c["path"] == path]
        if matching:
            cand = matching[0]
            seq = sequencer.generate_sequence(cand)
            res = runner.run_candidate_test(cand, seq, sequencer)
            verdicts[cwe] = res["verdict"]

    # In HARDENED mode, all attacks must be mitigated (NEGATIVE)
    assert verdicts["CWE-918"] == "NEGATIVE"
    assert verdicts["CWE-434"] == "NEGATIVE"
    assert verdicts["CWE-22"] == "NEGATIVE"
    assert verdicts["CWE-78"] == "NEGATIVE"
    assert verdicts["CWE-89"] == "NEGATIVE"
    assert verdicts["CWE-79"] == "NEGATIVE"
