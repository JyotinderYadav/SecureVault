"""
Project Documentation View
Interactive documentation viewer providing in-app access to all research methodology,
threat models, dataset specifications, reproduction steps, and progress logs.
"""
import streamlit as st
from config.settings import BASE_DIR
from ui.components.styling import render_header

DOCS_LIST = {
    "Research Methodology (VOAPI²)": BASE_DIR / "docs" / "research_methodology.md",
    "Dataset & Corpus Documentation": BASE_DIR / "docs" / "dataset_documentation.md",
    "Threat Model & Security Assumptions": BASE_DIR / "docs" / "threat_model.md",
    "Reproduction & Verification Plan": BASE_DIR / "docs" / "reproduction_plan.md",
    "Academic Disclosures & Limitations": BASE_DIR / "docs" / "limitations.md",
    "Development Progress Log (PROGRESS.md)": BASE_DIR / "PROGRESS.md"
}

def render_documentation_view():
    render_header(
        title="Project Documentation",
        subtitle="Complete Research Documentation, Architectural Blueprints & Development Audit Trail",
        badge="Documentation Suite"
    )

    doc_choice = st.selectbox("Select Documentation Document to Inspect:", list(DOCS_LIST.keys()))
    doc_path = DOCS_LIST[doc_choice]

    if doc_path.exists():
        with open(doc_path, "r", encoding="utf-8") as f:
            content = f.read()
        st.markdown(content)
    else:
        st.error(f"Document `{doc_path.name}` not found on disk.")
