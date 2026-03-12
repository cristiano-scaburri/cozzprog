
import re
import uuid
import json
import hashlib
import sqlite3
import httpx
import uvicorn
from contextlib import contextmanager
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from fastapi import FastAPI, Query, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel


app = FastAPI(title="FBI Wanted Search API", version="4.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FBI_BASE = "https://api.fbi.gov/wanted/v1/list"
HEADERS  = {
    "Accept": "application/json",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
}

DB_PATH = Path(__file__).parent / "fbi_search.db"

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

@contextmanager
def db():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db() -> None:
    """Crea le tabelle se non esistono (idempotente)."""
    with db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                username_lower TEXT PRIMARY KEY,
                username       TEXT NOT NULL,
                email          TEXT NOT NULL UNIQUE,
                password_hash  TEXT NOT NULL,
                created_at     TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reports (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                username_lower TEXT NOT NULL REFERENCES users(username_lower),
                report_id      TEXT NOT NULL UNIQUE,
                submitted_at   TEXT NOT NULL,
                reporter_name  TEXT,
                suspect_name   TEXT,
                description    TEXT NOT NULL DEFAULT '{}',
                location       TEXT,
                field_office   TEXT,
                date_seen      TEXT,
                notes          TEXT,
                candidates     INTEGER NOT NULL DEFAULT 0,
                matches_found  INTEGER NOT NULL DEFAULT 0,
                top_match      TEXT,
                top_score      INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_reports_user
                ON reports(username_lower);
        """)
    print(f"✅  Database pronto: {DB_PATH}")


sessions: dict[str, str] = {}


class RegisterRequest(BaseModel):
    username: str
    email:    str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class SightingReport(BaseModel):
    reporter_name:    Optional[str] = None
    suspect_name:     Optional[str] = None
    race:             Optional[str] = None
    sex:              Optional[str] = None
    hair:             Optional[str] = None
    eyes:             Optional[str] = None
    age_approx:       Optional[int] = None
    age_tolerance:    int           = 8
    height_ft:        Optional[int] = None
    height_in:        Optional[int] = None
    weight_lbs:       Optional[int] = None
    weight_tolerance: int           = 20
    location:         Optional[str] = None
    field_office:     Optional[str] = None
    date_seen:        Optional[str] = None
    notes:            Optional[str] = None


def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def get_current_user(authorization: str | None) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    return sessions.get(authorization[7:])

def require_user(authorization: str | None) -> str:
    u = get_current_user(authorization)
    if not u:
        raise HTTPException(401, "Non autenticato. Effettua il login.")
    return u


def db_get_user(username_lower: str) -> dict | None:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username_lower = ?", (username_lower,)
        ).fetchone()
    return dict(row) if row else None

def db_get_user_by_email(email: str) -> dict | None:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email,)
        ).fetchone()
    return dict(row) if row else None

def db_create_user(username_lower, username, email, password_hash, created_at):
    with db() as conn:
        conn.execute(
            """INSERT INTO users
               (username_lower, username, email, password_hash, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (username_lower, username, email, password_hash, created_at),
        )


def db_save_report(username_lower: str, r: dict) -> None:
    with db() as conn:
        conn.execute(
            """INSERT INTO reports
               (username_lower, report_id, submitted_at, reporter_name, suspect_name,
                description, location, field_office, date_seen, notes,
                candidates, matches_found, top_match, top_score)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                username_lower,
                r["report_id"],
                r["submitted_at"],
                r.get("reporter_name"),
                r.get("suspect_name"),
                json.dumps(r.get("description", {}), ensure_ascii=False),
                r.get("location"),
                r.get("field_office"),
                r.get("date_seen"),
                r.get("notes"),
                r.get("candidates", 0),
                r.get("matches_found", 0),
                r.get("top_match"),
                r.get("top_score", 0),
            ),
        )

def db_get_reports(username_lower: str) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM reports WHERE username_lower = ? ORDER BY submitted_at DESC",
            (username_lower,),
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        try:
            d["description"] = json.loads(d["description"])
        except Exception:
            d["description"] = {}
        result.append(d)
    return result


def parse_age_range(age_range: str | None) -> tuple[int | None, int | None]:
    if not age_range:
        return None, None
    nums = re.findall(r"\d+", age_range)
    if len(nums) >= 2:
        return int(nums[0]), int(nums[1])
    if len(nums) == 1:
        v = int(nums[0]); return v, v
    return None, None

def item_matches_age(item, age_min, age_max):
    if age_min is None and age_max is None:
        return True
    lo, hi = parse_age_range(item.get("age_range"))
    if lo is None:
        return False
    r_min = age_min if age_min is not None else 0
    r_max = age_max if age_max is not None else 999
    return lo <= r_max and hi >= r_min

def clean_item(item: dict) -> dict:
    images = item.get("images") or []
    thumb  = images[0].get("thumb") if images else None
    large  = images[0].get("large") if images else None
    return {
        "uid":           item.get("uid"),
        "title":         item.get("title"),
        "description":   item.get("description"),
        "aliases":       item.get("aliases") or [],
        "race":          item.get("race"),
        "sex":           item.get("sex"),
        "hair":          item.get("hair"),
        "eyes":          item.get("eyes"),
        "age_range":     item.get("age_range"),
        "height_min":    item.get("height_min"),
        "height_max":    item.get("height_max"),
        "weight_min":    item.get("weight_min"),
        "weight_max":    item.get("weight_max"),
        "reward_text":   item.get("reward_text"),
        "warning":       item.get("warning_message"),
        "caution":       item.get("caution"),
        "subjects":      item.get("subjects") or [],
        "nationality":   item.get("nationality"),
        "field_offices": item.get("field_offices") or [],
        "publication":   item.get("publication"),
        "url":           item.get("url"),
        "thumb":         thumb,
        "large":         large,
    }

async def fetch_fbi(params: dict) -> list[dict]:
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(FBI_BASE, params=params, headers=HEADERS)
        resp.raise_for_status()
        return resp.json().get("items", [])


@app.on_event("startup")
async def startup_event():
    init_db()

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def frontend():
    path = Path(__file__).parent / "index.html"
    if not path.exists():
        raise HTTPException(404, "index.html non trovato.")
    return HTMLResponse(content=path.read_text(encoding="utf-8"))


@app.post("/auth/register")
async def register(req: RegisterRequest):
    username = req.username.strip()
    email    = req.email.strip()
    password = req.password

    if not username:
        raise HTTPException(422, "Il nome utente non può essere vuoto.")
    if len(username) < 3:
        raise HTTPException(422, "Il nome utente deve avere almeno 3 caratteri.")
    if "@" not in email:
        raise HTTPException(422, "L'email deve contenere il carattere '@'.")
    if len(password) < 6:
        raise HTTPException(422, "La password deve avere almeno 6 caratteri.")

    key = username.lower()
    if db_get_user(key):
        raise HTTPException(409, f"Il nome utente '{username}' è già in uso.")
    if db_get_user_by_email(email):
        raise HTTPException(409, f"L'email '{email}' è già registrata.")

    created_at = datetime.now(timezone.utc).isoformat()
    db_create_user(key, username, email, hash_password(password), created_at)

    token = str(uuid.uuid4())
    sessions[token] = key

    return {"token": token, "username": username, "email": email,
            "message": f"Registrazione completata. Benvenuto, {username}!"}


@app.post("/auth/login")
async def login(req: LoginRequest):
    key  = req.username.strip().lower()
    user = db_get_user(key)
    if not user or user["password_hash"] != hash_password(req.password):
        raise HTTPException(401, "Nome utente o password non corretti.")

    token = str(uuid.uuid4())
    sessions[token] = key

    return {"token": token, "username": user["username"], "email": user["email"],
            "message": f"Bentornato, {user['username']}!"}


@app.post("/auth/logout")
async def logout(authorization: str | None = Header(None)):
    token = (authorization or "").replace("Bearer ", "")
    sessions.pop(token, None)
    return {"message": "Logout effettuato."}


@app.get("/auth/me")
async def me(authorization: str | None = Header(None)):
    key  = require_user(authorization)
    user = db_get_user(key)
    if not user:
        raise HTTPException(404, "Utente non trovato.")
    return {"username": user["username"], "email": user["email"],
            "created_at": user["created_at"], "reports": len(db_get_reports(key))}


@app.get("/reports/my")
async def my_reports(authorization: str | None = Header(None)):
    key  = require_user(authorization)
    user = db_get_user(key)
    if not user:
        raise HTTPException(404, "Utente non trovato.")
    return {"username": user["username"], "reports": db_get_reports(key)}


@app.get("/search")
async def search(
    title:         Optional[str] = Query(None),
    race:          Optional[str] = Query(None),
    sex:           Optional[str] = Query(None),
    hair:          Optional[str] = Query(None),
    eyes:          Optional[str] = Query(None),
    field_offices: Optional[str] = Query(None),
    age_min:       Optional[int] = Query(None),
    age_max:       Optional[int] = Query(None),
    page:          int           = Query(1),
):
    params: dict = {"page": page}
    if title:         params["title"]         = title
    if race:          params["race"]          = race
    if sex:           params["sex"]           = sex
    if hair:          params["hair"]          = hair
    if eyes:          params["eyes"]          = eyes
    if field_offices: params["field_offices"] = field_offices

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(FBI_BASE, params=params, headers=HEADERS)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        raise HTTPException(e.response.status_code, f"Errore FBI: {e.response.text[:300]}")
    except Exception as e:
        raise HTTPException(502, f"Impossibile raggiungere api.fbi.gov: {e}")

    items = data.get("items", [])
    total = data.get("total", 0)
    if age_min is not None or age_max is not None:
        items = [i for i in items if item_matches_age(i, age_min, age_max)]

    return {"total": total, "page": page, "results": len(items),
            "items": [clean_item(i) for i in items]}


@app.post("/sighting")
async def sighting(
    report:        SightingReport,
    authorization: str | None = Header(None),
):
    physical = [report.race, report.sex, report.hair, report.eyes,
                report.age_approx, report.height_ft, report.weight_lbs]
    if all(v is None for v in physical):
        raise HTTPException(422, "Inserisci almeno una caratteristica fisica.")

    fbi_params: dict = {"page": 1}
    if report.race:         fbi_params["race"]          = report.race
    if report.sex:          fbi_params["sex"]           = report.sex
    if report.hair:         fbi_params["hair"]          = report.hair
    if report.eyes:         fbi_params["eyes"]          = report.eyes
    if report.suspect_name: fbi_params["title"]         = report.suspect_name
    if report.field_office: fbi_params["field_offices"] = report.field_office

    all_items: list[dict] = []
    try:
        for pg in range(1, 4):
            fbi_params["page"] = pg
            page_items = await fetch_fbi(fbi_params)
            all_items.extend(page_items)
            if len(page_items) < 20:
                break
    except httpx.HTTPStatusError as e:
        raise HTTPException(e.response.status_code, f"Errore FBI: {e.response.text[:300]}")
    except Exception as e:
        raise HTTPException(502, f"Impossibile raggiungere api.fbi.gov: {e}")

    report_height_in: int | None = None
    if report.height_ft is not None:
        report_height_in = (report.height_ft * 12) + (report.height_in or 0)

    def score_item(item: dict) -> tuple[int, dict, list[str]]:
        pts = 0; max_pts = 0; matched: list[str] = []
        def n(s): return (s or "").lower().strip()

        if report.race:
            max_pts += 25
            if n(item.get("race")) == n(report.race):
                pts += 25; matched.append("Race")
        if report.sex:
            max_pts += 20
            if n(item.get("sex")) == n(report.sex):
                pts += 20; matched.append("Sex")
        if report.hair:
            max_pts += 15
            ih = n(item.get("hair") or ""); rh = n(report.hair)
            if rh in ih or ih in rh:
                pts += 15; matched.append("Hair")
        if report.eyes:
            max_pts += 15
            ie = n(item.get("eyes") or ""); re_ = n(report.eyes)
            if re_ in ie or ie in re_:
                pts += 15; matched.append("Eyes")
        if report.age_approx is not None:
            max_pts += 15
            lo, hi = parse_age_range(item.get("age_range"))
            if lo is not None:
                tol = report.age_tolerance
                r_lo = report.age_approx - tol
                r_hi = report.age_approx + tol
                overlap = max(0, min(hi, r_hi) - max(lo, r_lo))
                age_score = int(15 * min(1.0, overlap / max(1, r_hi - r_lo)))
                pts += age_score
                if age_score >= 10: matched.append("Age")
        if report_height_in is not None:
            max_pts += 5
            h_min = item.get("height_min"); h_max = item.get("height_max")
            if h_min and h_max:
                if (h_min - 3) <= report_height_in <= (h_max + 3):
                    pts += 5; matched.append("Height")
        if report.weight_lbs is not None:
            max_pts += 5
            w_min = item.get("weight_min"); w_max = item.get("weight_max")
            if w_min and w_max:
                tol = report.weight_tolerance
                if (w_min - tol) <= report.weight_lbs <= (w_max + tol):
                    pts += 5; matched.append("Weight")

        pct = int((pts / max_pts) * 100) if max_pts > 0 else 0
        return pct, item, matched

    scored  = sorted([score_item(i) for i in all_items], key=lambda x: x[0], reverse=True)
    results = []
    for pct, item, matched in scored[:10]:
        if pct < 30 and len(results) >= 3: break
        c = clean_item(item)
        c["match_score"] = pct; c["matched_fields"] = matched
        results.append(c)

    report_id    = f"SR-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:4].upper()}"
    submitted_at = datetime.now(timezone.utc).isoformat()

    user_key = get_current_user(authorization)
    if user_key and db_get_user(user_key):
        db_save_report(user_key, {
            "report_id": report_id, "submitted_at": submitted_at,
            "reporter_name": report.reporter_name, "suspect_name": report.suspect_name,
            "description": {
                "race": report.race, "sex": report.sex, "hair": report.hair,
                "eyes": report.eyes, "age_approx": report.age_approx,
                "height": f"{report.height_ft}'{report.height_in or 0}\"" if report.height_ft else None,
                "weight": f"{report.weight_lbs} lbs" if report.weight_lbs else None,
            },
            "location": report.location, "field_office": report.field_office,
            "date_seen": report.date_seen, "notes": report.notes,
            "candidates": len(all_items), "matches_found": len(results),
            "top_match": results[0]["title"] if results else None,
            "top_score": results[0]["match_score"] if results else 0,
        })

    reporter_display = report.reporter_name
    if not reporter_display and user_key:
        u = db_get_user(user_key)
        reporter_display = u["username"] if u else None
    reporter_display = reporter_display or "Anonymous"

    return {
        "report_id": report_id, "submitted_at": submitted_at,
        "reporter":  reporter_display, "location": report.location,
        "date_seen": report.date_seen, "candidates": len(all_items),
        "matches":   results,
    }


if __name__ == "__main__":
    print("\n🔎  FBI Wanted Search  v4")
    print(f"    Database  → {DB_PATH}")
    print("    Frontend  → http://127.0.0.1:8000")
    print("    API docs  → http://127.0.0.1:8000/docs\n")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
