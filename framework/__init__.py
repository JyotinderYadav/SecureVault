"""
SecureVault Framework Engine
4-Stage REST API Security Testing Pipeline Inspired by VOAPI² (USENIX Security 2024):
  Stage 1: Specification Analysis (OpenAPISpecParser)
  Stage 2: Candidate Interface Extraction (CandidateInterfaceExtractor)
  Stage 3: Test Sequence Generation (TestSequenceGenerator)
  Stage 4: Feedback-Based Testing (FeedbackTestRunner, VulnerabilityOracle)
"""
from framework.stage1_spec_analysis.parser import OpenAPISpecParser
from framework.stage2_candidate_extraction.extractor import CandidateInterfaceExtractor
from framework.stage3_sequence_generation.sequencer import TestSequenceGenerator
from framework.stage4_feedback_testing.runner import FeedbackTestRunner
from framework.stage4_feedback_testing.oracles import VulnerabilityOracle

__all__ = [
    "OpenAPISpecParser",
    "CandidateInterfaceExtractor",
    "TestSequenceGenerator",
    "FeedbackTestRunner",
    "VulnerabilityOracle"
]
