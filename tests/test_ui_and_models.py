"""
Unit and Integration Tests for UI Models, Parser Interface, and View Entrypoints
Verifies regression fixes for Error A (SystemConfig.mode), Error B (OpenAPISpecParser.parse),
Error C (Findings data loader), and all 15 modular views.
"""
import pytest
from pathlib import Path
from config.settings import system_config, BASE_DIR, SecurityMode
from framework.stage1_spec_analysis.parser import OpenAPISpecParser
from ui.models.findings import FindingRecord, load_finding_records

def test_system_config_interface():
    """Verify Error A fix: SystemConfig mode property, enum, and toggling."""
    system_config.set_mode("VULNERABLE")
    assert system_config.mode == SecurityMode.VULNERABLE
    assert system_config.security_mode == "VULNERABLE"
    assert system_config.is_vulnerable() is True
    assert system_config.is_hardened() is False

    system_config.toggle_mode()
    assert system_config.mode == SecurityMode.HARDENED
    assert system_config.security_mode == "HARDENED"
    assert system_config.is_hardened() is True
    assert system_config.is_vulnerable() is False

    # Restore default
    system_config.set_mode(SecurityMode.VULNERABLE)
    assert system_config.is_vulnerable() is True

def test_openapi_spec_parser_canonical_parse():
    """Verify Error B fix: canonical .parse() and .analyze() on OpenAPISpecParser."""
    spec_path = BASE_DIR / "datasets" / "api_specifications" / "raw" / "securevault_openapi.json"
    parser = OpenAPISpecParser(spec_path)
    
    # Verify .parse() returns EndpointSchema list with normalized properties
    endpoints = parser.parse()
    assert isinstance(endpoints, list)
    assert len(endpoints) >= 10
    
    first_ep = endpoints[0]
    assert hasattr(first_ep, "method")
    assert hasattr(first_ep, "path")
    assert hasattr(first_ep, "parameters")
    assert hasattr(first_ep, "request_body")

    # Verify .analyze() backward compatibility alias
    analyzed = parser.analyze()
    assert len(analyzed) == len(endpoints)

def test_findings_model_and_loader(tmp_path):
    """Verify Error C fix: FindingRecord normalization for dict and attribute access."""
    # Test valid record
    rec_data = {
        "candidate": {
            "cwe_id": "CWE-918",
            "path": "/api/v1/vault/sync",
            "method": "POST",
            "primary_parameter": "target_url"
        },
        "verdict": "CONFIRMED_VULNERABILITY",
        "status_code": 200,
        "latency_ms": 14.5,
        "analysis": "Internal loopback reflected canary flag",
        "evidence": ["HTTP 200", "Flag matched"],
        "response_body": "{\"flag\": \"SECUREVAULT_FLAG\"}"
    }
    rec = FindingRecord(rec_data)
    assert rec.cwe_id == "CWE-918"
    assert rec.endpoint_path == "/api/v1/vault/sync"
    assert rec.endpoint_method == "POST"
    assert rec.target_parameter == "target_url"
    assert rec.verdict == "CONFIRMED_VULNERABILITY"
    assert rec.status_code == 200
    assert rec.latency_ms == 14.5
    assert "flag" in rec.response_body
    assert rec["cwe_id"] == "CWE-918"

    # Test load_finding_records with wrapped dict {"results": [...]}
    import json
    test_json_file = tmp_path / "test_log.json"
    test_json_file.write_text(json.dumps({"results": [rec_data]}), encoding="utf-8")
    loaded = load_finding_records(test_json_file)
    assert len(loaded) == 1
    assert loaded[0].cwe_id == "CWE-918"

    # Test load_finding_records with non-existent and empty files
    assert load_finding_records(tmp_path / "non_existent.json") == []
    empty_file = tmp_path / "empty.json"
    empty_file.write_text("", encoding="utf-8")
    assert load_finding_records(empty_file) == []

def test_all_15_views_importable():
    """Verify that all 15 views can be imported and their render functions are callable."""
    from ui.views.overview import render_overview_view
    from ui.views.methodology import render_methodology_view
    from ui.views.dataset_explorer import render_dataset_explorer_view
    from ui.views.vulnerability_kb import render_vulnerability_kb_view
    from ui.views.spec_analyzer import render_spec_analyzer_view
    from ui.views.candidate_extractor import render_candidate_extractor_view
    from ui.views.sequence_generator import render_sequence_generator_view
    from ui.views.feedback_testing import render_feedback_testing_view
    from ui.views.attack_simulation import render_attack_simulation_view
    from ui.views.benchmarks import render_benchmarks_view
    from ui.views.experimental_evaluation import render_experimental_evaluation_view
    from ui.views.performance_analytics import render_performance_analytics_view
    from ui.views.research_findings import render_research_findings_view
    from ui.views.research_reports import render_research_reports_view
    from ui.views.documentation import render_documentation_view

    views = [
        render_overview_view,
        render_methodology_view,
        render_dataset_explorer_view,
        render_vulnerability_kb_view,
        render_spec_analyzer_view,
        render_candidate_extractor_view,
        render_sequence_generator_view,
        render_feedback_testing_view,
        render_attack_simulation_view,
        render_benchmarks_view,
        render_experimental_evaluation_view,
        render_performance_analytics_view,
        render_research_findings_view,
        render_research_reports_view,
        render_documentation_view
    ]
    assert len(views) == 15
    for v in views:
        assert callable(v)

def test_cloud_environment_detection_and_safeguards(monkeypatch):
    """Verify that cloud hosting environments strictly enforce HARDENED policy."""
    from config.settings import SystemConfig, SecurityMode
    
    # Simulate cloud environment
    monkeypatch.setattr("config.settings.IS_HOSTED", True)
    cloud_config = SystemConfig()
    assert cloud_config.is_hosted is True
    assert cloud_config.mode == SecurityMode.HARDENED
    assert cloud_config.is_hardened() is True
    
    # Attempt to switch to VULNERABLE must be rejected
    res = cloud_config.set_mode("VULNERABLE")
    assert res is False
    assert cloud_config.mode == SecurityMode.HARDENED
    
    # Attempt to toggle must remain HARDENED
    toggled = cloud_config.toggle_mode()
    assert toggled == "HARDENED"
    assert cloud_config.mode == SecurityMode.HARDENED

def test_ui_app_navigation_structure():
    """Verify Phase 7.3: exactly 15 modules organized across 6 groups."""
    from ui.app import NAV_ITEMS, PAGE_MAP, GROUP_MAP
    
    assert len(NAV_ITEMS) == 15
    assert len(PAGE_MAP) == 15
    
    # Verify the 6 groups
    groups = set(GROUP_MAP.values())
    expected_groups = {
        "1. Overview",
        "2. Research",
        "3. Analysis Pipeline",
        "4. Security Testing",
        "5. Results",
        "6. Documentation"
    }
    assert groups == expected_groups
    
    # Verify all callables
    for name, func in PAGE_MAP.items():
        assert callable(func)
