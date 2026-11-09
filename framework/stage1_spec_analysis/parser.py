"""
Stage 1: Specification Analysis Module
Ingests, normalizes, and extracts comprehensive schema contracts from OpenAPI (v2, v3, v3.1)
specifications in JSON and YAML formats.
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import yaml
import httpx

class OpenAPISpecParser:
    def __init__(self, spec_data: Optional[Dict[str, Any]] = None):
        self.raw_spec: Dict[str, Any] = spec_data or {}
        self.version: str = "Unknown"
        self.title: str = "Unknown"
        self.endpoints: List[Dict[str, Any]] = []

    @classmethod
    def from_file(cls, file_path: Union[str, Path]) -> "OpenAPISpecParser":
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"OpenAPI specification file not found: {path}")

        content = path.read_text(encoding="utf-8")
        if path.suffix.lower() in [".yaml", ".yml"]:
            data = yaml.safe_load(content)
        else:
            data = json.loads(content)

        parser = cls(data)
        parser.analyze()
        return parser

    @classmethod
    def from_url(cls, url: str, timeout: int = 5) -> "OpenAPISpecParser":
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()
        parser = cls(data)
        parser.analyze()
        return parser

    def analyze(self):
        """Analyzes the raw specification and populates normalized endpoints."""
        if not self.raw_spec:
            return

        # Determine spec standard version
        if "openapi" in self.raw_spec:
            self.version = f"OpenAPI {self.raw_spec['openapi']}"
        elif "swagger" in self.raw_spec:
            self.version = f"Swagger {self.raw_spec['swagger']}"
        else:
            self.version = "Custom / Unspecified"

        info = self.raw_spec.get("info", {})
        self.title = info.get("title", "Untitled API")

        self.endpoints = []
        paths = self.raw_spec.get("paths", {})

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Shared path-level parameters
            path_level_params = path_item.get("parameters", [])

            for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
                if method in path_item and isinstance(path_item[method], dict):
                    op = path_item[method]
                    endpoint_meta = self._extract_endpoint(path_str, method.upper(), op, path_level_params)
                    self.endpoints.append(endpoint_meta)

    def _resolve_ref(self, ref: str) -> Dict[str, Any]:
        """Resolves internal JSON pointers ($ref)."""
        if not ref.startswith("#/"):
            return {}
        parts = ref.lstrip("#/").split("/")
        curr = self.raw_spec
        for p in parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                return {}
        return curr if isinstance(curr, dict) else {}

    def _extract_endpoint(
        self,
        path: str,
        method: str,
        op: Dict[str, Any],
        path_level_params: List[Any]
    ) -> Dict[str, Any]:
        """Extracts normalized parameters, body schemas, and response descriptions."""
        op_id = op.get("operationId", f"{method}_{path.replace('/', '_').strip('_')}")
        summary = op.get("summary", "")
        description = op.get("description", "")
        tags = op.get("tags", [])

        # Parameters extraction
        raw_params = path_level_params + op.get("parameters", [])
        normalized_params = []

        for p in raw_params:
            if isinstance(p, dict) and "$ref" in p:
                p = self._resolve_ref(p["$ref"])
            if not isinstance(p, dict):
                continue

            param_name = p.get("name", "")
            param_in = p.get("in", "query")
            required = p.get("required", False)
            param_desc = p.get("description", "")
            
            schema = p.get("schema", {})
            if "$ref" in schema:
                schema = self._resolve_ref(schema["$ref"])
                
            schema_type = schema.get("type") or p.get("type", "string")
            default_val = schema.get("default") or p.get("default")
            enum_vals = schema.get("enum") or p.get("enum")

            normalized_params.append({
                "name": param_name,
                "in": param_in,
                "required": required,
                "type": schema_type,
                "default": default_val,
                "enum": enum_vals,
                "description": param_desc
            })

        # Request Body extraction (OpenAPI 3.x)
        request_body = op.get("requestBody", {})
        body_params = []
        content_types = []

        if isinstance(request_body, dict):
            if "$ref" in request_body:
                request_body = self._resolve_ref(request_body["$ref"])
            content = request_body.get("content", {})
            content_types = list(content.keys())

            for ctype, media_type in content.items():
                schema = media_type.get("schema", {})
                if "$ref" in schema:
                    schema = self._resolve_ref(schema["$ref"])
                
                # Extract properties
                props = schema.get("properties", {})
                req_fields = schema.get("required", [])
                for prop_name, prop_meta in props.items():
                    if "$ref" in prop_meta:
                        prop_meta = self._resolve_ref(prop_meta["$ref"])
                    
                    # Extract type, handling OpenAPI 3.1 anyOf [type, null]
                    prop_type = prop_meta.get("type")
                    if not prop_type and "anyOf" in prop_meta:
                        for sub in prop_meta["anyOf"]:
                            if isinstance(sub, dict) and sub.get("type") and sub["type"] != "null":
                                prop_type = sub["type"]
                                break
                    if not prop_type:
                        prop_type = "string"

                    body_params.append({
                        "name": prop_name,
                        "in": "body",
                        "required": prop_name in req_fields,
                        "type": prop_type,
                        "content_type": ctype,
                        "description": prop_meta.get("description", "")
                    })

        # Responses extraction (crucial for Producer-Consumer dependency graph)
        responses = {}
        for code, resp_obj in op.get("responses", {}).items():
            if isinstance(resp_obj, dict) and "$ref" in resp_obj:
                resp_obj = self._resolve_ref(resp_obj["$ref"])
            if isinstance(resp_obj, dict):
                resp_desc = resp_obj.get("description", "")
                resp_schema = {}
                # OpenAPI 3.x content schema
                content = resp_obj.get("content", {})
                if "application/json" in content:
                    resp_schema = content["application/json"].get("schema", {})
                elif "schema" in resp_obj:  # Swagger 2.0 schema
                    resp_schema = resp_obj["schema"]
                if "$ref" in resp_schema:
                    resp_schema = self._resolve_ref(resp_schema["$ref"])

                responses[str(code)] = {
                    "description": resp_desc,
                    "properties": list(resp_schema.get("properties", {}).keys())
                }

        all_parameters = normalized_params + body_params

        return {
            "path": path,
            "method": method,
            "operation_id": op_id,
            "summary": summary,
            "description": description,
            "tags": tags,
            "parameters": all_parameters,
            "content_types": content_types,
            "responses": responses
        }

    def get_summary(self) -> Dict[str, Any]:
        """Provides statistical overview of parsed specification."""
        methods_count: Dict[str, int] = {}
        for ep in self.endpoints:
            m = ep["method"]
            methods_count[m] = methods_count.get(m, 0) + 1

        return {
            "title": self.title,
            "version": self.version,
            "total_endpoints": len(self.endpoints),
            "methods_breakdown": methods_count
        }
