"""
Stage 3: Test Sequence Generation Module
Implements Algorithm 1 (Reverse Sequence Construction) from VOAPI² with:
  1. Producer-Consumer dependency graph resolution
  2. CRUD semantic constraints filtering
  3. Resource hierarchy pruning
  4. Multi-strategy parameter value generation (CONSUMER, SPECIFICATION, FORMAT, SUCCESS, RANDOM)
"""
import random
import re
import string
import uuid
from typing import Dict, List, Any, Optional, Tuple, Set
from framework.stage1_spec_analysis.parser import EndpointSchema

PRODUCER_METHOD_PRIORITY = {
    "POST": 4,
    "PUT": 3,
    "GET": 2,
    "PATCH": 1,
    "DELETE": 0,
    "OPTIONS": 0,
    "HEAD": 0
}

FORMAT_PRESETS = {
    "email": "tester@securevault.local",
    "password": "Password123!Safe",
    "uuid": lambda: str(uuid.uuid4()),
    "date": "2026-11-10",
    "datetime": "2026-11-10T12:00:00Z"
}


class TestSequenceStep(dict):
    """
    Dual representation of a sequence step.
    Supports both dictionary indexing (step["method"], step["path"])
    and attribute access (step.endpoint.method, step.parameter_strategies).
    """
    def __init__(
        self,
        endpoint: Any,
        parameters: Optional[Dict[str, Any]] = None,
        parameter_strategies: Optional[Dict[str, str]] = None,
        request_body: Optional[Any] = None,
        producers: Optional[List[str]] = None
    ):
        path = endpoint.path if hasattr(endpoint, "path") else endpoint["path"]
        method = endpoint.method if hasattr(endpoint, "method") else endpoint["method"]
        op_id = endpoint.operation_id if hasattr(endpoint, "operation_id") else endpoint.get("operation_id", "")
        summary = endpoint.summary if hasattr(endpoint, "summary") else endpoint.get("summary", "")
        ep_params = endpoint.parameters if hasattr(endpoint, "parameters") else endpoint.get("parameters", [])

        data = {
            "path": path,
            "method": method,
            "operation_id": op_id,
            "summary": summary,
            "parameters": parameters or {},
            "parameter_strategies": parameter_strategies or {},
            "request_body": request_body,
            "producers": producers or []
        }
        super().__init__(data)
        self._data = data
        if isinstance(endpoint, EndpointSchema):
            self._endpoint = endpoint
        else:
            self._endpoint = EndpointSchema(
                path=path,
                method=method,
                parameters=ep_params,
                operation_id=op_id,
                summary=summary
            )
        self._parameters = parameters or {}
        self._parameter_strategies = parameter_strategies or {}
        self._request_body = request_body
        self._producers = producers or []

    @property
    def endpoint(self) -> EndpointSchema:
        return self._endpoint

    @property
    def method(self) -> str:
        return self._data["method"]

    @property
    def path(self) -> str:
        return self._data["path"]

    @property
    def parameters(self) -> Dict[str, Any]:
        return self._parameters

    @property
    def parameter_strategies(self) -> Dict[str, str]:
        return self._parameter_strategies

    @property
    def request_body(self) -> Optional[Any]:
        return self._request_body

    @property
    def producers(self) -> List[str]:
        return self._producers


class TestSequence(list):
    """
    List of TestSequenceSteps representing a synthesized execution sequence.
    Exposes .steps property for UI view compatibility while remaining directly iterable/indexable.
    """
    def __init__(self, steps: List[TestSequenceStep]):
        super().__init__(steps)

    @property
    def steps(self) -> List[TestSequenceStep]:
        return list(self)


class TestSequenceGenerator:
    __test__ = False

    def __init__(self, endpoints: List[Any]):
        self.endpoints = endpoints
        self.endpoint_map: Dict[Tuple[str, str], Any] = {}
        for ep in endpoints:
            m = ep.method.upper() if hasattr(ep, "method") else ep["method"].upper()
            p = ep.path if hasattr(ep, "path") else ep["path"]
            self.endpoint_map[(m, p)] = ep

        self.successful_values: Dict[str, Any] = {}

    def _get_resource_base(self, path: str) -> str:
        """Strips path parameters to obtain canonical resource parent path."""
        clean = re.sub(r"/\{[^}]+\}", "", path).rstrip("/")
        return clean

    def _find_producers_for_param(self, param_name: str, consumer_path: str) -> List[Any]:
        """
        Searches endpoints whose responses produce param_name,
        strictly respecting Resource Hierarchy and Producer Priority.
        """
        producers = []
        consumer_base = self._get_resource_base(consumer_path)

        for (m, p), ep in self.endpoint_map.items():
            if m == "DELETE":  # CRUD constraint: DELETE cannot produce resources
                continue

            producer_base = self._get_resource_base(p)

            # Resource Hierarchy constraint (Section 3.3.1):
            if producer_base != consumer_base and not consumer_base.startswith(producer_base):
                continue

            responses = ep.responses if hasattr(ep, "responses") else ep.get("responses", {})
            matches = False
            if isinstance(responses, dict):
                for code, r_meta in responses.items():
                    if str(code).startswith("2"):
                        props = []
                        if isinstance(r_meta, dict):
                            props = [prop.lower() for prop in r_meta.get("properties", [])]
                        if param_name.lower() in props:
                            matches = True
                            break

            # Fallback heuristic: POST on parent resource base produces sub-resource identifier
            if not matches and m == "POST" and producer_base == consumer_base:
                if param_name.lower() in ["id", "item_id", "itemid", "name"]:
                    matches = True

            if matches:
                producers.append(ep)

        # Apply Priority Rule: POST > PUT > GET > PATCH
        producers.sort(
            key=lambda x: PRODUCER_METHOD_PRIORITY.get(
                x.method if hasattr(x, "method") else x["method"], 0
            ),
            reverse=True
        )
        return producers

    def generate_sequence(self, candidate_api: Any) -> TestSequence:
        """
        Algorithm 1: Reverse Sequence Construction.
        Builds a stateful dependency chain prefix for the candidate endpoint.
        Returns a TestSequence instance containing TestSequenceStep items.
        """
        raw_ops: List[Any] = [candidate_api]
        
        cand_m = candidate_api.method if hasattr(candidate_api, "method") else candidate_api["method"]
        cand_p = candidate_api.path if hasattr(candidate_api, "path") else candidate_api["path"]
        visited_keys: Set[Tuple[str, str]] = {(cand_m, cand_p)}
        
        i = -1
        max_depth = 5
        depth = 0

        while depth < max_depth:
            depth += 1
            curr_op = raw_ops[i]
            curr_path = curr_op.path if hasattr(curr_op, "path") else curr_op["path"]
            params = curr_op.parameters if hasattr(curr_op, "parameters") else curr_op.get("parameters", [])

            needed_params = []
            for p in params:
                p_name = p.name if hasattr(p, "name") else p.get("name")
                p_in = p.location if hasattr(p, "location") else p.get("in")
                p_req = p.required if hasattr(p, "required") else p.get("required")
                if p_in == "path" or p_req is True:
                    if p_name:
                        needed_params.append(p_name)

            found_new_producer = False
            for p_name in needed_params:
                producers = self._find_producers_for_param(p_name, curr_path)
                for prod in producers:
                    prod_m = prod.method if hasattr(prod, "method") else prod["method"]
                    prod_p = prod.path if hasattr(prod, "path") else prod["path"]
                    prod_key = (prod_m, prod_p)
                    if prod_key not in visited_keys:
                        visited_keys.add(prod_key)
                        raw_ops.insert(0, prod)
                        found_new_producer = True
                        break

            if not found_new_producer:
                break

            if raw_ops[i] == raw_ops[0]:
                break
            else:
                i = i - 1

        # Synthesize sequence steps with parameter values & strategies
        steps: List[TestSequenceStep] = []
        context_producers: List[str] = []

        for op in raw_ops:
            op_m = op.method if hasattr(op, "method") else op["method"]
            op_p = op.path if hasattr(op, "path") else op["path"]
            op_params = op.parameters if hasattr(op, "parameters") else op.get("parameters", [])

            step_param_values: Dict[str, Any] = {}
            step_param_strats: Dict[str, str] = {}

            for p in op_params:
                p_meta = p.to_dict() if hasattr(p, "to_dict") else (p if isinstance(p, dict) else {
                    "name": getattr(p, "name", ""),
                    "in": getattr(p, "location", "query"),
                    "type": getattr(p, "param_type", "string")
                })
                p_name = p_meta.get("name", "")
                val, strat = self.generate_parameter_value(p_meta)
                step_param_values[p_name] = val
                step_param_strats[p_name] = strat

            body_content = None
            if op_m in ("POST", "PUT", "PATCH"):
                body_content = {"name": "VoAPI_Seed_Entity", "description": "Automated State Seed"}

            step = TestSequenceStep(
                endpoint=op,
                parameters=step_param_values,
                parameter_strategies=step_param_strats,
                request_body=body_content,
                producers=list(context_producers)
            )
            steps.append(step)
            context_producers.append(f"{op_m} {op_p}")

        return TestSequence(steps)

    def generate_parameter_value(
        self,
        param_meta: Dict[str, Any],
        is_target_param: bool = False,
        injected_payload: Optional[Any] = None,
        runtime_context: Optional[Dict[str, Any]] = None
    ) -> Tuple[Any, str]:
        """
        Implements VOAPI² Parameter Values Generation strategies:
        1. TARGET_INJECTION (when this parameter is designated for vulnerability testing)
        2. CONSUMER (runtime propagation from prior request response)
        3. SPECIFICATION (default / enum / example in spec)
        4. FORMAT (email, password, UUID presets)
        5. SUCCESS (reusing successful runtime values)
        6. RANDOM (type-consistent fallback)
        """
        name = param_meta.get("name", "").lower()
        ptype = str(param_meta.get("type", "string")).lower()

        # Strategy 0: Injected Attack Payload
        if is_target_param and injected_payload is not None:
            return injected_payload, "TARGET_INJECTION"

        # Strategy 1: CONSUMER (extracted from runtime response context)
        if runtime_context and name in runtime_context:
            return runtime_context[name], "CONSUMER"

        # Strategy 2: SPECIFICATION (schema enum or default)
        if param_meta.get("default") is not None:
            return param_meta["default"], "SPECIFICATION_DEFAULT"
        if param_meta.get("enum"):
            return param_meta["enum"][0], "SPECIFICATION_ENUM"

        # Strategy 3: FORMAT (preset formatting dictionary)
        if "email" in name:
            return FORMAT_PRESETS["email"], "FORMAT_PRESET"
        if "pass" in name or "pwd" in name:
            return FORMAT_PRESETS["password"], "FORMAT_PRESET"
        if "uuid" in name or name == "guid":
            return FORMAT_PRESETS["uuid"](), "FORMAT_PRESET"
        if "date" in name:
            return FORMAT_PRESETS["date"], "FORMAT_PRESET"
        if "timeout" in name:
            return 5, "FORMAT_PRESET"

        # Strategy 4: SUCCESS (cached from prior 200 OK responses)
        if name in self.successful_values:
            return self.successful_values[name], "SUCCESS_REUSE"

        # Strategy 5: RANDOM (type-consistent random generation)
        if "int" in ptype or ptype == "integer":
            val = random.randint(1, 100)
            return val, "RANDOM_INTEGER"
        elif "bool" in ptype or ptype == "boolean":
            return True, "RANDOM_BOOLEAN"
        elif "num" in ptype or ptype == "float":
            return round(random.uniform(1.0, 50.0), 2), "RANDOM_FLOAT"
        else:
            rand_str = "VoAPI_" + "".join(random.choices(string.ascii_letters, k=6))
            return rand_str, "RANDOM_STRING"
