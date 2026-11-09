"""
SQL Injection Router (CWE-89)
Endpoint: GET /api/v1/vault/records/search
Simulates search and filter operations over vault records.
"""
from typing import Optional
from fastapi import APIRouter, Query, HTTPException, status
from app.models.schemas import RecordSearchResponse, RecordItem
from app.core.database import search_vault_records_vulnerable, search_vault_records_hardened
from config.settings import system_config

router = APIRouter(prefix="/api/v1/vault", tags=["SQL Injection (CWE-89)"])

@router.get("/records/search", response_model=RecordSearchResponse, summary="Search Vault Records (CWE-89 Target)")
def search_records(
    query: str = Query(..., description="Search term for vault record title", examples=["Cloud"]),
    category: Optional[str] = Query(None, description="Optional category filter", examples=["Infrastructure"])
):
    """
    Search and filter confidential records in the vault database.
    - VULNERABLE mode: Concatenates user input directly into SQL statement (enables CWE-89).
    - HARDENED mode: Executes parameterized prepared statements with bounded variables.
    """
    try:
        if system_config.is_hardened():
            rows = search_vault_records_hardened(query, category)
            query_desc = "Parameterized Prepared Statement (?)"
        else:
            rows = search_vault_records_vulnerable(query, category)
            query_desc = f"Raw SQL: SELECT * FROM vault_records WHERE (title LIKE '%{query}%'...)"

        records = [
            RecordItem(
                id=r["id"],
                title=r["title"],
                category=r["category"],
                secret_data=r["secret_data"],
                created_by=r["created_by"]
            )
            for r in rows
        ]

        return RecordSearchResponse(
            status="SUCCESS",
            query_executed=query_desc,
            count=len(records),
            records=records
        )
    except Exception as e:
        # In VULNERABLE mode, exposing raw database error enables error-based SQLi detection
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database Query Error [SQLite]: {str(e)}"
        )
