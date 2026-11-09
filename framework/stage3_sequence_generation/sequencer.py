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

class TestSequenceGenerator:
    __test__ = False

    def __init__(self, endpoints: List[Dict[str, Any]]):
        self.endpoints = endpoints
        self.endpoint_map: Dict[Tuple[str, str], Dict[str, Any]] = {
            (ep["method"].upper(), ep["path"]): ep for ep in endpoints
        }
        self.successful_values: Dict[str, Any] = {}

    def _get_resource_base(self, path: str) -> str:
        """Strips path parameters to obtain canonical resource parent path."""
        # e.g., /api/v1/vault/items/{id} -> /api/v1/vault/items
        clean = re.sub(r"/\{[^}]+\}", "", path).rstrip("/")
        return clean

    def _find_producers_for_param(self, param_name: str, consumer_path: str) -> List[Dict[str, Any]]:
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
            # Producer must share the same direct resource base or be an ancestor
            if producer_base != consumer_base and not consumer_base.startswith(producer_base):
                continue

            # Check if response properties explicitly produce param_name
            responses = ep.get("responses", {})
            matches = False
            for code, r_meta in responses.items():
                if str(code).startswith("2"):
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
        producers.sort(key=lambda x: PRODUCER_METHOD_PRIORITY.get(x["method"], 0), reverse=True)
        return producers

    def generate_sequence(self, candidate_api: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Algorithm 1: Reverse Sequence Construction.
        Builds a stateful dependency chain prefix for the candidate endpoint.
        """
        sequence: List[Dict[str, Any]] = [candidate_api]
        visited_keys: Set[Tuple[str, str]] = {(candidate_api["method"], candidate_api["path"])}
        i = -1

        max_depth = 5
        depth = 0

        while depth < max_depth:
            depth += 1
            curr_op = sequence[i]
            params = curr_op.get("parameters", [])

            needed_params = [
                p["name"] for p in params
                if p.get("in") == "path" or p.get("required") is True
            ]

            found_new_producer = False
            for p_name in needed_params:
                producers = self._find_producers_for_param(p_name, curr_op["path"])
                for prod in producers:
                    prod_key = (prod["method"], prod["path"])
                    if prod_key not in visited_keys:
                        visited_keys.add(prod_key)
                        sequence.insert(0, prod)
                        found_new_producer = True
                        break

            if not found_new_producer:
                break

            if sequence[i] == sequence[0]:
                break
            else:
                i = i - 1

        return sequence

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
