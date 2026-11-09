"""
API Network & Dependency Graph Component
Generates an interactive Plotly network visualization representing:
- API endpoints & HTTP methods
- Candidate interfaces & vulnerability tags
- Producer-consumer state dependencies
- Parameter relationships & entity hierarchies
"""
import math
import plotly.graph_objects as go
from typing import List, Dict, Any

METHOD_COLORS = {
    "GET": "#0284C7",      # Cyan/Blue
    "POST": "#10B981",     # Emerald
    "PUT": "#F59E0B",      # Amber
    "DELETE": "#EF4444",   # Crimson
    "PATCH": "#8B5CF6"     # Purple
}

CWE_COLORS = {
    "CWE-918": "#38BDF8",  # Sky Blue
    "CWE-434": "#F43F5E",  # Rose
    "CWE-22":  "#FB923C",  # Orange
    "CWE-78":  "#EC4899",  # Pink
    "CWE-89":  "#A855F7",  # Violet
    "CWE-79":  "#EAB308"   # Gold
}

def build_api_network_figure(endpoints: List[Any], candidates: List[Any] = None) -> go.Figure:
    """Constructs an interactive 2D circular spring-layout network graph using Plotly."""
    if not endpoints:
        return go.Figure()

    candidates_map = {}
    if candidates:
        for c in candidates:
            key = f"{c.endpoint.method} {c.endpoint.path}"
            candidates_map[key] = c

    # Create nodes
    # Central Hub
    node_x = [0.0]
    node_y = [0.0]
    node_text = ["<b>SecureVault API Hub</b><br>Root Gateway"]
    node_color = ["#0F172A"]
    node_size = [28]
    node_symbol = ["diamond"]
    node_labels = ["API Hub"]

    edge_x = []
    edge_y = []

    # Distribute endpoints in concentric radial layers
    num_endpoints = len(endpoints)
    radius = 2.5

    endpoint_coords = {}

    for i, ep in enumerate(endpoints):
        angle = (2 * math.pi * i) / num_endpoints
        # Jitter slightly by method for organic look
        r = radius + (0.3 if ep.method in ("POST", "PUT") else 0.0)
        x = r * math.cos(angle)
        y = r * math.sin(angle)

        ep_key = f"{ep.method} {ep.path}"
        endpoint_coords[ep_key] = (x, y)

        cand = candidates_map.get(ep_key)
        is_cand = cand is not None
        cwe_tag = cand.cwe_category if is_cand else "Standard Interface"
        target_param = cand.primary_parameter if is_cand else "None"

        # Hub to endpoint edge
        edge_x.extend([0.0, x, None])
        edge_y.extend([0.0, y, None])

        # Node properties
        node_x.append(x)
        node_y.append(y)
        
        # Color: if candidate, highlight by CWE, else by HTTP method
        color = CWE_COLORS.get(cwe_tag, METHOD_COLORS.get(ep.method, "#64748B"))
        node_color.append(color)
        node_size.append(22 if is_cand else 16)
        node_symbol.append("circle" if not is_cand else "hexagram")

        hover = (
            f"<b>{ep.method} {ep.path}</b><br>"
            f"Vulnerability Status: {'⚠️ CANDIDATE' if is_cand else '✔️ Benign'}<br>"
            f"Target Category: {cwe_tag}<br>"
            f"Target Parameter: {target_param}<br>"
            f"Parameters: {len(ep.parameters)}<br>"
            f"Summary: {ep.summary or 'REST Operation'}"
        )
        node_text.append(hover)
        node_labels.append(f"{ep.method} {ep.path.split('/')[-1]}")

    # Add producer-consumer dependency edges (e.g. POST /items -> GET/DELETE /items/{item_id})
    dep_edge_x = []
    dep_edge_y = []
    for ep in endpoints:
        if "{item_id}" in ep.path and ep.method in ("GET", "DELETE", "PUT"):
            prod_key = "POST /api/v1/vault/items"
            cons_key = f"{ep.method} {ep.path}"
            if prod_key in endpoint_coords and cons_key in endpoint_coords:
                x0, y0 = endpoint_coords[prod_key]
                x1, y1 = endpoint_coords[cons_key]
                dep_edge_x.extend([x0, x1, None])
                dep_edge_y.extend([y0, y1, None])

    # Plotly Traces
    traces = []

    # 1. Structural Edges (Hub to Endpoints)
    traces.append(go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line=dict(width=1, color="rgba(148, 163, 184, 0.4)"),
        hoverinfo="none",
        name="Hierarchy"
    ))

    # 2. Dependency Edges (Producer -> Consumer)
    if dep_edge_x:
        traces.append(go.Scatter(
            x=dep_edge_x, y=dep_edge_y,
            mode="lines",
            line=dict(width=2, color="#0284C7", dash="dot"),
            hoverinfo="none",
            name="Data Dependency (Algorithm 1)"
        ))

    # 3. Nodes
    traces.append(go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        marker=dict(
            size=node_size,
            color=node_color,
            line=dict(width=2, color="#FFFFFF"),
            symbol=node_symbol
        ),
        text=node_labels,
        textposition="top center",
        textfont=dict(size=10, color="#1E293B", family="Inter"),
        hovertext=node_text,
        hoverinfo="text",
        name="Endpoints & Candidates"
    ))

    fig = go.Figure(data=traces)
    fig.update_layout(
        title="<b>Interactive API State & Dependency Topology</b>",
        title_font=dict(size=16, color="#0F172A", family="Inter"),
        showlegend=True,
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#F8FAFC",
        height=520,
        margin=dict(l=20, r=20, t=50, b=20),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.1,
            xanchor="center",
            x=0.5,
            font=dict(size=11, color="#64748B")
        )
    )
    return fig
