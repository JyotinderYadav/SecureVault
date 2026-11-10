"""
Stage 1: Specification Analysis Module
Ingests, normalizes, and extracts comprehensive schema contracts from OpenAPI (v2, v3, v3.1)
specifications in JSON and YAML formats.
Provides unified attribute and dictionary access for backward compatibility and ergonomic typing.
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import yaml
import httpx

class ParameterSchema(dict):
    """Normalized parameter representation supporting both dictionary and attribute access."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__dict__ = self

    @property
    def in_(self) -> str:
        return self.get("in", "query")

class EndpointSchema(dict):
    """Normalized endpoint representation supporting both dictionary and attribute access."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__dict__ = self

    @property
    def request_body(self) -> Dict[str, Any]:
        """Provides backward-compatible dict of body properties."""
        body_props = {}
        for p in self.get("parameters", []):
            if isinstance(p, dict) and p.get("in") == "body":
                body_props[p.get("name", "")] = p
        return body_props

class OpenAPISpecParser:
    """
    Robust specification parser supporting OpenAPI 2.0 (Swagger), OpenAPI 3.0, and OpenAPI 3.1.
    Accepts dictionaries, file paths (str/Path), URLs, raw text strings, or bytes.
    """
    def __init__(self, spec_data: Optional[Union[Dict[str, Any], str, Path, bytes]] = None):
        self.raw_spec: Dict[str, Any] = {}
        self.version: str = "Unknown"
        self.title: str = "Unknown"
        self.info: Dict[str, Any] = {}
        self.servers: List[str] = []
        self.endpoints: List[EndpointSchema] = []

        if spec_data is not None:
            self.load(spec_data)
            self.parse()

    @property
    def spec_type(self) -> str:
        return self.version

    @property
    def paths(self) -> Dict[str, Any]:
        return self.raw_spec.get("paths", {}) if isinstance(self.raw_spec, dict) else {}

    def load(self, spec_data: Union[Dict[str, Any], str, Path, bytes]):
        """Loads and parses raw specification from various input formats."""
        if isinstance(spec_data, dict):
            self.raw_spec = spec_data
            return

        # Check if bytes
        if isinstance(spec_data, bytes):
            text = spec_data.decode("utf-8", errors="replace")
            self._load_from_text(text)
            return

        # Check if Path or string
        if isinstance(spec_data, (str, Path)):
            str_path = str(spec_data).strip()
            
            # Check if URL
            if str_path.startswith("http://") or str_path.startswith("https://"):
                with httpx.Client(timeout=10) as client:
                    resp = client.get(str_path)
                    resp.raise_for_status()
                    self._load_from_text(resp.text)
                return

            # Check if file exists on disk
            path_obj = Path(spec_data)
            if path_obj.exists() and path_obj.is_file():
                content = path_obj.read_text(encoding="utf-8", errors="replace")
                self._load_from_text(content, is_yaml=(path_obj.suffix.lower() in [".yaml", ".yml"]))
                return

            # Otherwise, treat string as inline JSON or YAML text
            self._load_from_text(str_path)
            return

        raise ValueError(f"Unsupported specification source type: {type(spec_data)}")

    def _load_from_text(self, text: str, is_yaml: Optional[bool] = None):
        """Attempts to parse string text as JSON first, then YAML."""
        text = text.strip()
        if not text:
            self.raw_spec = {}
            return

        # Try JSON first if not explicitly marked as YAML
        if is_yaml is not True and (text.startswith("{") or text.startswith("[")):
            try:
                self.raw_spec = json.loads(text)
                return
            except json.JSONDecodeError:
                pass

        # Try YAML
        try:
            parsed = yaml.safe_load(text)
            if isinstance(parsed, dict):
                self.raw_spec = parsed
                return
            raise ValueError("Parsed YAML did not yield a dictionary structure.")
        except Exception as e:
            # Fallback retry JSON
            try:
                self.raw_spec = json.loads(text)
                return
            except Exception:
                raise ValueError(f"Failed to parse specification as valid JSON or YAML: {str(e)}")

    @classmethod
    def from_file(cls, file_path: Union[str, Path]) -> "OpenAPISpecParser":
        return cls(file_path)

    @classmethod
    def from_url(cls, url: str, timeout: int = 5) -> "OpenAPISpecParser":
        return cls(url)

    def parse(self, spec_data: Optional[Union[Dict[str, Any], str, Path, bytes]] = None) -> List[EndpointSchema]:
        """
        Parses the specification and returns normalized endpoints.
        Acts as the primary entrypoint for Stage 1.
        """
        if spec_data is not None:
            self.load(spec_data)

        if not self.raw_spec:
            self.endpoints = []
            return self.endpoints

        # Determine spec standard version
        if "openapi" in self.raw_spec:
            self.version = f"OpenAPI {self.raw_spec['openapi']}"
        elif "swagger" in self.raw_spec:
            self.version = f"Swagger {self.raw_spec['swagger']}"
        else:
            self.version = "OpenAPI / Custom"

        self.info = self.raw_spec.get("info", {})
        self.title = self.info.get("title", "RESTful API Specification")

        # Extract servers / host
        self.servers = []
        if "servers" in self.raw_spec:
            for s in self.raw_spec["servers"]:
                if isinstance(s, dict) and "url" in s:
                    self.servers.append(s["url"])
        elif "host" in self.raw_spec:
            schemes = self.raw_spec.get("schemes", ["http"])
            base_path = self.raw_spec.get("basePath", "")
            self.servers.append(f"{schemes[0]}://{self.raw_spec['host']}{base_path}")

        self.endpoints = []
        paths = self.raw_spec.get("paths", {})

        if isinstance(paths, dict):
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

        return self.endpoints

    def analyze(self, spec_data: Optional[Any] = None) -> List[EndpointSchema]:
        """Backward-compatible alias for parse()."""
        return self.parse(spec_data)

    def _resolve_ref(self, ref: str, visited: Optional[set] = None) -> Dict[str, Any]:
        """Resolves internal JSON pointers ($ref) with circular reference protection."""
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return {}
        
        if visited is None:
            visited = set()
        if ref in visited:
            return {}  # Prevent infinite recursion
        visited.add(ref)

        parts = ref.lstrip("#/").split("/")
        curr = self.raw_spec
        for p in parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                return {}
        
        # If resolved item has another $ref, chain resolve
        if isinstance(curr, dict) and "$ref" in curr:
            return self._resolve_ref(curr["$ref"], visited)

        return curr if isinstance(curr, dict) else {}

    def _extract_endpoint(
        self,
        path: str,
        method: str,
        op: Dict[str, Any],
        path_level_params: List[Any]
    ) -> EndpointSchema:
        """Extracts normalized parameters, body schemas, and response descriptions."""
        op_id = op.get("operationId", f"{method}_{path.replace('/', '_').strip('_')}")
        summary = op.get("summary", "")
        description = op.get("description", "")
        tags = op.get("tags", [])

        # Parameters extraction
        raw_params = (path_level_params if isinstance(path_level_params, list) else []) + (op.get("parameters", []) if isinstance(op.get("parameters"), list) else [])
        normalized_params: List[ParameterSchema] = []

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
            if isinstance(schema, dict) and "$ref" in schema:
                schema = self._resolve_ref(schema["$ref"])
                
            schema_type = "string"
            if isinstance(schema, dict) and schema.get("type"):
                schema_type = schema["type"]
            elif p.get("type"):
                schema_type = p["type"]
                
            default_val = schema.get("default") if isinstance(schema, dict) else p.get("default")
            enum_vals = schema.get("enum") if isinstance(schema, dict) else p.get("enum")

            normalized_params.append(ParameterSchema({
                "name": param_name,
                "in": param_in,
                "required": required,
                "type": schema_type,
                "default": default_val,
                "enum": enum_vals,
                "description": param_desc
            }))

        # Request Body extraction (OpenAPI 3.x and Swagger 2.0 in: body)
        body_params: List[ParameterSchema] = []
        content_types: List[str] = []

        # OpenAPI 3.x requestBody
        request_body = op.get("requestBody", {})
        if isinstance(request_body, dict):
            if "$ref" in request_body:
                request_body = self._resolve_ref(request_body["$ref"])
            content = request_body.get("content", {})
            if isinstance(content, dict):
                content_types = list(content.keys())
                for ctype, media_type in content.items():
                    schema = media_type.get("schema", {}) if isinstance(media_type, dict) else {}
                    if isinstance(schema, dict) and "$ref" in schema:
                        schema = self._resolve_ref(schema["$ref"])
                    
                    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
                    req_fields = schema.get("required", []) if isinstance(schema, dict) else []
                    
                    if isinstance(props, dict):
                        for prop_name, prop_meta in props.items():
                            if isinstance(prop_meta, dict) and "$ref" in prop_meta:
                                prop_meta = self._resolve_ref(prop_meta["$ref"])
                            
                            prop_type = prop_meta.get("type") if isinstance(prop_meta, dict) else "string"
                            if not prop_type and isinstance(prop_meta, dict) and "anyOf" in prop_meta:
                                for sub in prop_meta["anyOf"]:
                                    if isinstance(sub, dict) and sub.get("type") and sub["type"] != "null":
                                        prop_type = sub["type"]
                                        break
                            if not prop_type:
                                prop_type = "string"

                            body_params.append(ParameterSchema({
                                "name": prop_name,
                                "in": "body",
                                "required": prop_name in req_fields,
                                "type": prop_type,
                                "content_type": ctype,
                                "description": prop_meta.get("description", "") if isinstance(prop_meta, dict) else ""
                            }))

        # Swagger 2.0 in: body parameters
        for p in raw_params:
            if isinstance(p, dict) and p.get("in") == "body":
                b_schema = p.get("schema", {})
                if isinstance(b_schema, dict) and "$ref" in b_schema:
                    b_schema = self._resolve_ref(b_schema["$ref"])
                props = b_schema.get("properties", {}) if isinstance(b_schema, dict) else {}
                if isinstance(props, dict) and props:
                    for prop_name, prop_meta in props.items():
                        if isinstance(prop_meta, dict) and "$ref" in prop_meta:
                            prop_meta = self._resolve_ref(prop_meta["$ref"])
                        p_type = prop_meta.get("type", "string") if isinstance(prop_meta, dict) else "string"
                        body_params.append(ParameterSchema({
                            "name": prop_name,
                            "in": "body",
                            "required": False,
                            "type": p_type,
                            "content_type": "application/json",
                            "description": prop_meta.get("description", "") if isinstance(prop_meta, dict) else ""
                        }))

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
                if isinstance(content, dict) and "application/json" in content:
                    resp_schema = content["application/json"].get("schema", {})
                elif "schema" in resp_obj:  # Swagger 2.0 schema
                    resp_schema = resp_obj["schema"]
                if isinstance(resp_schema, dict) and "$ref" in resp_schema:
                    resp_schema = self._resolve_ref(resp_schema["$ref"])

                props = list(resp_schema.get("properties", {}).keys()) if isinstance(resp_schema, dict) else []
                responses[str(code)] = {
                    "description": resp_desc,
                    "properties": props
                }

        all_parameters = normalized_params + body_params

        return EndpointSchema({
            "path": path,
            "method": method,
            "operation_id": op_id,
            "summary": summary,
            "description": description,
            "tags": tags,
            "parameters": all_parameters,
            "content_types": content_types,
            "responses": responses
        })

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

    def get_endpoint(self, method: str, path: str) -> Optional[EndpointSchema]:
        """Look up an endpoint by method and path."""
        m_upper = method.upper()
        for ep in self.endpoints:
            if ep["method"].upper() == m_upper and ep["path"] == path:
                return ep
        return None
