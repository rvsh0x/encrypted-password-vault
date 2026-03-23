"""
API FastAPI locale pour le gestionnaire de mots de passe.
Toutes les données restent sur 127.0.0.1.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from password_manager.password_generator import generate_password

from .auth import (
    get_session_status,
    lock_vault,
    unlock_vault,
    update_auto_lock,
)
from .security import VaultSession, csrf_protect, get_vault_session, require_unlocked_vault
from .vault_service import (
    add_entry,
    delete_entry,
    get_entry,
    list_entries,
    update_entry,
)


router = APIRouter()

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "frontend"))


@router.get("/", response_class=HTMLResponse)
async def index_page(request: Request) -> Any:
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request) -> Any:
    return templates.TemplateResponse("dashboard.html", {"request": request})


@router.get("/add", response_class=HTMLResponse)
async def add_entry_page(request: Request) -> Any:
    return templates.TemplateResponse("add_entry.html", {"request": request})


@router.get("/entry/{entry_id}", response_class=HTMLResponse)
async def view_entry_page(request: Request, entry_id: str) -> Any:
    return templates.TemplateResponse(
        "view_entry.html", {"request": request, "entry_id": entry_id}
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> Any:
    return templates.TemplateResponse("settings.html", {"request": request})


# --- API JSON ---


@router.get("/api/session")
async def api_session(request: Request) -> Dict[str, Any]:
    """Retourne l'état de la session + token CSRF."""
    return await get_session_status(request)


@router.post("/api/unlock", dependencies=[Depends(csrf_protect)])
async def api_unlock(
    request: Request, payload: Dict[str, str]
) -> Dict[str, Any]:
    master_password = payload.get("master_password") or ""
    vault_path = payload.get("vault_path") or None
    if not master_password:
        raise HTTPException(status_code=400, detail="Mot de passe maître requis.")
    vs = await unlock_vault(request, master_password=master_password, vault_path=vault_path)
    return {"unlocked": True, "auto_lock_minutes": vs.auto_lock_minutes}


@router.post("/api/lock", dependencies=[Depends(csrf_protect)])
async def api_lock(request: Request) -> Dict[str, Any]:
    await lock_vault(request)
    return {"unlocked": False}


@router.get("/api/entries", dependencies=[Depends(require_unlocked_vault)])
async def api_list_entries(
    vs: VaultSession = Depends(get_vault_session),
) -> List[Dict[str, Any]]:
    return list_entries(vs)


@router.get("/api/entries/{entry_id}", dependencies=[Depends(require_unlocked_vault)])
async def api_get_entry(
    entry_id: str,
    vs: VaultSession = Depends(get_vault_session),
) -> Dict[str, Any]:
    entry = get_entry(vs, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Entrée non trouvée.")
    return {
        "id": entry.id,
        "site": entry.site,
        "username": entry.username,
        "password": entry.password,
        "notes": entry.notes,
    }


@router.post("/api/entries", dependencies=[Depends(csrf_protect), Depends(require_unlocked_vault)])
async def api_add_entry(
    payload: Dict[str, Any],
    vs: VaultSession = Depends(get_vault_session),
) -> Dict[str, Any]:
    site = str(payload.get("site") or "").strip()
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    notes = payload.get("notes")
    if not site or not username or not password:
        raise HTTPException(status_code=400, detail="Champs site, username et password requis.")
    entry = add_entry(vs, site=site, username=username, password=password, notes=notes)
    return {
        "id": entry.id,
        "site": entry.site,
        "username": entry.username,
        "notes": entry.notes,
    }


@router.put(
    "/api/entries/{entry_id}",
    dependencies=[Depends(csrf_protect), Depends(require_unlocked_vault)],
)
async def api_update_entry(
    entry_id: str,
    payload: Dict[str, Any],
    vs: VaultSession = Depends(get_vault_session),
) -> Dict[str, Any]:
    site = str(payload.get("site") or "").strip()
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    notes = payload.get("notes")
    if not site or not username or not password:
        raise HTTPException(status_code=400, detail="Champs site, username et password requis.")
    entry = update_entry(
        vs,
        entry_id=entry_id,
        site=site,
        username=username,
        password=password,
        notes=notes,
    )
    if not entry:
        raise HTTPException(status_code=404, detail="Entrée non trouvée.")
    return {
        "id": entry.id,
        "site": entry.site,
        "username": entry.username,
        "notes": entry.notes,
    }


@router.delete(
    "/api/entries/{entry_id}",
    dependencies=[Depends(csrf_protect), Depends(require_unlocked_vault)],
)
async def api_delete_entry(
    entry_id: str,
    vs: VaultSession = Depends(get_vault_session),
) -> Dict[str, Any]:
    ok = delete_entry(vs, entry_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Entrée non trouvée.")
    return {"deleted": True}


@router.post("/api/generate-password", dependencies=[Depends(csrf_protect)])
async def api_generate_password(payload: Dict[str, Any]) -> Dict[str, str]:
    length = int(payload.get("length") or 20)
    use_upper = not bool(payload.get("no_upper"))
    use_lower = not bool(payload.get("no_lower"))
    use_digits = not bool(payload.get("no_digits"))
    use_special = not bool(payload.get("no_special"))
    pwd = generate_password(
        length=length,
        use_uppercase=use_upper,
        use_lowercase=use_lower,
        use_digits=use_digits,
        use_special=use_special,
    )
    return {"password": pwd}


@router.post(
    "/api/settings/auto-lock",
    dependencies=[Depends(csrf_protect), Depends(require_unlocked_vault)],
)
async def api_update_auto_lock(
    payload: Dict[str, Any],
    request: Request,
) -> Dict[str, Any]:
    minutes = int(payload.get("minutes") or 10)
    await update_auto_lock(request, minutes)
    return {"minutes": minutes}

