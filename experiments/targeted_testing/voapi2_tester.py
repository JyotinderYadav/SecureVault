"""
VOAPI² Targeted Security Tester
Executes vulnerability-oriented testing based on the 4-stage methodology of VOAPI²:
  1. Specification Analysis
  2. Candidate Interface Extraction
  3. Reverse Sequence Generation
  4. Feedback-Based Oracle Verification
"""
import time
from typing import Dict, List, Any, Optional
from framework import (
    OpenAPISpecParser,
    CandidateInterfaceExtractor,
    TestSequenceGenerator,
    FeedbackTestRunner
)

class VOAPI2TargetedTester:
    def __init__(self, parser: OpenAPISpecParser, client: Any):
        self.parser = parser
        self.client = client
        self.extractor = CandidateInterfaceExtractor()
        self.sequencer = TestSequenceGenerator(parser.endpoints)
        self.runner = FeedbackTestRunner(client=client)

    def run_testing(self) -> Dict[str, Any]:
        """
        Executes targeted security inspection on all extracted candidate interfaces.
        """
        t0 = time.perf_counter()
        candidates = self.extractor.extract_candidates(self.parser.endpoints)
        
        test_results = []
        total_requests = 0
        confirmed_count = 0
        potential_count = 0
        negative_count = 0

        for cand in candidates:
            seq = self.sequencer.generate_sequence(cand)
            res = self.runner.run_candidate_test(cand, seq, self.sequencer)
            
            # Count HTTP requests in sequence
            reqs_in_test = len(res.get("execution_trace", []))
            total_requests += reqs_in_test

            verdict = res.get("verdict")
            if verdict == "CONFIRMED_VULNERABILITY":
                confirmed_count += 1
            elif verdict == "POTENTIAL_VULNERABILITY":
                potential_count += 1
            elif verdict == "NEGATIVE":
                negative_count += 1

            test_results.append(res)

        elapsed_total_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "strategy": "VOAPI2_TARGETED_TESTING",
            "total_candidates": len(candidates),
            "total_requests": total_requests,
            "total_time_ms": round(elapsed_total_ms, 2),
            "confirmed_vulnerabilities": confirmed_count,
            "potential_vulnerabilities": potential_count,
            "negative_verdicts": negative_count,
            "results": test_results
        }
