"""
Vault Items Router (Stage 3 Producer-Consumer Demonstration)
Endpoints:
  POST   /api/v1/vault/items        (Producer: creates item, outputs id)
  GET    /api/v1/vault/items/{id}   (Consumer: consumes id to retrieve item)
  DELETE /api/v1/vault/items/{id}   (Deleter: removes item)
"""
import uuid
from fastapi import APIRouter, HTTPException, status
from app.models.schemas import VaultItemCreate, VaultItemResponse
from app.core.database import get_db_connection

router = APIRouter(prefix="/api/v1/vault/items", tags=["Stateful CRUD Items (Producer-Consumer)"])

@router.post("", response_model=VaultItemResponse, status_code=status.HTTP_201_CREATED, summary="Create Vault Item (Producer)")
def create_vault_item(payload: VaultItemCreate):
    """
    Creates a new secure vault item.
    Acts as a Producer API in VOAPI² Stage 3: its response produces the 'id' parameter.
    """
    item_id = str(uuid.uuid4())[:8]
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO vault_items (id, name, description, owner)
    VALUES (?, ?, ?, ?);
    """, (item_id, payload.name, payload.description, "admin"))
    conn.commit()
    conn.close()

    return VaultItemResponse(
        id=item_id,
        name=payload.name,
        description=payload.description,
        owner="admin"
    )

@router.get("/{id}", response_model=VaultItemResponse, summary="Get Vault Item (Consumer)")
def get_vault_item(id: str):
    """
    Retrieves a vault item by its unique identifier.
    Acts as a Consumer API in VOAPI² Stage 3: requires 'id' produced by the POST endpoint.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, description, owner FROM vault_items WHERE id = ?;", (id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault item with id '{id}' was not found"
        )

    return VaultItemResponse(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        owner=row["owner"]
    )

@router.delete("/{id}", summary="Delete Vault Item (CRUD Terminator)")
def delete_vault_item(id: str):
    """
    Deletes a vault item.
    Subject to CRUD semantic constraints in Stage 3 (cannot access resource after deletion).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault_items WHERE id = ?;", (id,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()

    if deleted == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault item with id '{id}' does not exist"
        )

    return {"status": "DELETED", "id": id}

