"""
API Specification Analyzer View
Parses and inspects OpenAPI 2.0/3.0/3.1 and Swagger specifications,
resolving schemas, extracting endpoints, parameters, and request bodies (Stage 1).
"""
import json
import time
import streamlit as st
import pandas as pd
import plotly.express as px
from config.settings import BASE_DIR
from framework.stage1_spec_analysis.parser import OpenAPISpecParser
from ui.components.styling import render_header, render_metric_card

PRELOADED_SPECS = {
    "SecureVault Dual-Mode API (v1.0.0)": BASE_DIR / "datasets" / "api_specifications" / "raw" / "securevault_openapi.json",
    "Appwrite (v0.9.3 - 95 Endpoints)": BASE_DIR / "datasets" / "api_specifications" / "raw" / "APISpec-appwrite.json",
    "Request Baskets (v1.2.3 - 20 Endpoints)": BASE_DIR / "datasets" / "api_specifications" / "raw" / "rbaskets-openapi.yaml",
    "Gitea (v1.16.7 - 291 Endpoints)": BASE_DIR / "datasets" / "api_specifications" / "raw" / "gitea-1.16.7-swagger.json"
}

def render_spec_analyzer_view():
    render_header(
        title="API Specification Analyzer (Stage 1)",
        subtitle="Automated Parsing & Schema Normalization for OpenAPI 2.0/3.0/3.1 and Swagger Specs",
        badge="Stage 1 Engine"
    )

    col_select, col_upload = st.columns([2, 1])
    with col_select:
        spec_choice = st.selectbox("Select Target API Specification:", list(PRELOADED_SPECS.keys()) + ["Upload Custom Spec..."])

    custom_file = None
    if spec_choice == "Upload Custom Spec...":
        with col_upload:
            custom_file = st.file_uploader("Upload OpenAPI Spec (JSON or YAML):", type=["json", "yaml", "yml"])

    # Determine spec path or content
    spec_path = None
    if custom_file is not None:
        # Save temp file
        temp_path = BASE_DIR / "results" / "temp_uploaded_spec.json"
        with open(temp_path, "wb") as f:
            f.write(custom_file.getbuffer())
        spec_path = temp_path
    elif spec_choice in PRELOADED_SPECS:
        spec_path = PRELOADED_SPECS[spec_choice]

    if not spec_path or not spec_path.exists():
        st.warning("Please select or upload a valid OpenAPI specification file.")
        return

    # Parse specification
    t0 = time.perf_counter()
    parser = OpenAPISpecParser(spec_path)
    endpoints = parser.parse()
    parse_time = (time.perf_counter() - t0) * 1000

    # Metrics
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(render_metric_card("Spec Title", parser.info.get("title", "REST API")[:16], f"v{parser.info.get('version', '1.0')}", "#48CAE4"), unsafe_allow_html=True)
    with c2:
        st.markdown(render_metric_card("Total Endpoints", str(len(endpoints)), f"{len(parser.paths)} Paths", "#00B4D8"), unsafe_allow_html=True)
    with c3:
        st.markdown(render_metric_card("Parse Latency", f"{parse_time:.2f} ms", "Fast In-Memory Graph", "#10B981"), unsafe_allow_html=True)
    with c4:
        st.markdown(render_metric_card("Spec Format", parser.spec_type, "JSON / YAML", "#F59E0B"), unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # HTTP Methods Chart
    col_chart, col_meta = st.columns([1.5, 1])
    with col_chart:
        method_counts = {}
        for ep in endpoints:
            method_counts[ep.method] = method_counts.get(ep.method, 0) + 1
        df_methods = pd.DataFrame(list(method_counts.items()), columns=["HTTP Method", "Count"])
        fig = px.pie(
            df_methods,
            values="Count",
            names="HTTP Method",
            title="HTTP Method Distribution",
            color_discrete_sequence=["#48CAE4", "#00B4D8", "#0077B6", "#10B981", "#EF4444"]
        )
        fig.update_layout(paper_bgcolor="#162035", plot_bgcolor="#162035", font_color="#F8FAFC", height=280, margin=dict(l=10, r=10, t=30, b=10))
        st.plotly_chart(fig, use_container_width=True)

    with col_meta:
        st.markdown("**Specification Details:**")
        st.markdown(f"- **OpenAPI/Swagger Version:** `{parser.spec_type}`")
        st.markdown(f"- **Description:** {parser.info.get('description', 'No description provided')[:120]}...")
        st.markdown(f"- **Server URL:** `{parser.servers[0] if parser.servers else 'http://localhost:8000'}`")
        st.markdown(f"- **Total Path Items:** `{len(parser.paths)}`")
        st.markdown(f"- **Total Operations (Endpoints):** `{len(endpoints)}`")

    # Endpoints Table
    st.subheader(f"Parsed Endpoint Catalog ({len(endpoints)} Operations)")
    search_ep = st.text_input("Filter endpoints by path or parameter name:", "")
    
    records = []
    for ep in endpoints:
        param_names = [p.name for p in ep.parameters]
        records.append({
            "Method": ep.method,
            "Path": ep.path,
            "Parameters": ", ".join(param_names) if param_names else "(None)",
            "Body Fields": ", ".join(ep.request_body.keys()) if ep.request_body else "(None)",
            "Operation ID": ep.operation_id or ep.summary or ""
        })
    df_ep = pd.DataFrame(records)
    if search_ep:
        df_ep = df_ep[df_ep["Path"].str.contains(search_ep, case=False, na=False) | df_ep["Parameters"].str.contains(search_ep, case=False, na=False)]
    
    st.dataframe(df_ep, use_container_width=True, height=350)
