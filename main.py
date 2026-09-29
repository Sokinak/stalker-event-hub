import os, sqlite3, hashlib
from fastapi import FastAPI, HTTPException, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timedelta
import jwt

app = FastAPI(title="Stalker RP Event Hub")
DB_PATH = "events.db"
SECRET_KEY = os.environ.get("SECRET_KEY", "stalker_zone_secret_key_change_me_in_prod")
ALGORITHM = "HS256"

ROLE_DEFAULTS = {
    "admin":                {"can_approve": True, "can_edit_all": True, "can_manage_users": True},
    "senior_eventologist":  {"can_approve": True, "can_edit_all": True, "can_manage_users": False},
    "eventologist":         {"can_approve": False,"can_edit_all": False,"can_manage_users": False},
    "junior_eventologist":  {"can_approve": False,"can_edit_all": False,"can_manage_users": False},
}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def h_pw(p): return hashlib.sha256(p.encode('utf-8')).hexdigest()
def v_pw(p, h): return h_pw(p) == h

def get_perms(user):
    role = user["role"]
    defaults = ROLE_DEFAULTS.get(role, ROLE_DEFAULTS["junior_eventologist"])
    perms = {}
    for key in ("can_approve","can_edit_all","can_manage_users"):
        val = user[key]
        perms[key] = bool(val) if val is not None else defaults[key]
    return perms

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'junior_eventologist',
        can_approve INTEGER DEFAULT NULL,
        can_edit_all INTEGER DEFAULT NULL,
        can_manage_users INTEGER DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        event_type TEXT NOT NULL,
        duration TEXT NOT NULL,
        location TEXT NOT NULL,
        organizer_name TEXT NOT NULL,
        author_id INTEGER NOT NULL,
        short_desc TEXT NOT NULL,
        full_desc TEXT NOT NULL,
        rules_text TEXT,
        rewards_text TEXT,
        status TEXT DEFAULT 'pending',
        reviewed_by TEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (author_id) REFERENCES users (id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS spawn_whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_name TEXT UNIQUE NOT NULL,
        category TEXT DEFAULT '',
        added_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS spawn_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        user_name TEXT NOT NULL,
        item_name TEXT NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 1,
        note TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    # Migration: add new columns if missing
    try: c.execute("ALTER TABLE users ADD COLUMN can_approve INTEGER DEFAULT NULL")
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN can_edit_all INTEGER DEFAULT NULL")
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN can_manage_users INTEGER DEFAULT NULL")
    except: pass
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        users = [
            ("admin", h_pw("admin123"), "Главный Ивентолог Пушкин", "admin", None, None, None),
            ("senior", h_pw("senior123"), "Ст.Ивентолог", "senior_eventologist", None, None, None),
            ("eventolog", h_pw("event123"), "Ивентолог", "eventologist", None, None, None),
            ("junior", h_pw("junior123"), "Мл.Ивентолог", "junior_eventologist", None, None, None),
        ]
        c.executemany("INSERT INTO users (username,password_hash,display_name,role,can_approve,can_edit_all,can_manage_users) VALUES (?,?,?,?,?,?,?)", users)
        events = [
            ("Чёрная Посылка","Сюжетный / Поисковый","2–3 часа","Дикая территория","Мл.Ивентолог Пушкин",1,
             "Торговец получил координаты тайника с документами и артефактом. Информация утекла — за тайником гонятся все.",
             "<p>Торговец получил зашифрованные координаты тайника.</p><p><b>Фаза 1:</b> Каждый получает часть подсказки.</p><p><b>Фаза 2:</b> Гонка и засады.</p><p><b>Фаза 3:</b> Вскрытие тайника.</p>",
             "Гоп-стоп разрешён вне ЗЗ. Курьеры мастера неприкосновенны.","Артефакт + сюжет | Денежная награда","approved","Главный Ивентолог Пушкин"),
            ("Выброс Не По Расписанию","Выживание / Кооперация","1.5–2 часа","Вся карта","Мл.Ивентолог Пушкин",1,
             "Внеплановый выброс через 40 минут — укрытий не хватает. После — новые аномалии.",
             "<p>Выброс раньше времени. Ищите укрытия, торгуйте местами.</p>",
             "Запрещено нападать во время выброса.","Коллекционер артефактов: Приз","pending",None),
        ]
        c.executemany("INSERT INTO events (title,event_type,duration,location,organizer_name,author_id,short_desc,full_desc,rules_text,rewards_text,status,reviewed_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", events)
    conn.commit(); conn.close()

init_db()

def get_current_user(request):
    token = request.cookies.get("access_token")
    if not token: return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username: return None
    except: return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return user

def reorder_ids(table):
    """Reorder IDs to be sequential after deletion."""
    conn = get_db()
    rows = conn.execute(f"SELECT id FROM {table} ORDER BY id ASC").fetchall()
    for new_id, row in enumerate(rows, 1):
        old_id = row["id"]
        if old_id != new_id:
            if table == "users":
                conn.execute("UPDATE events SET author_id=? WHERE author_id=?", (new_id, old_id))
            conn.execute(f"UPDATE {table} SET id=? WHERE id=?", (new_id, old_id))
    # Reset autoincrement
    max_id = len(rows)
    conn.execute(f"DELETE FROM sqlite_sequence WHERE name=?", (table,))
    if max_id > 0:
        conn.execute(f"INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)", (table, max_id))
    conn.commit(); conn.close()

# ── AUTH ──
@app.post("/api/login")
async def login(username: str=Form(...), password: str=Form(...)):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not user or not v_pw(password, user["password_hash"]):
        return JSONResponse({"error": "Неверный логин или пароль"}, status_code=400)
    token = jwt.encode({"sub": user["username"], "role": user["role"], "exp": datetime.utcnow()+timedelta(days=7)}, SECRET_KEY, algorithm=ALGORITHM)
    resp = JSONResponse({"success": True})
    resp.set_cookie(key="access_token", value=token, httponly=True, max_age=604800)
    return resp

@app.post("/api/logout")
async def logout():
    resp = JSONResponse({"success": True}); resp.delete_cookie("access_token"); return resp

@app.get("/api/me")
async def me(request: Request):
    user = get_current_user(request)
    if not user: return JSONResponse({"authenticated": False})
    perms = get_perms(user)
    return {"authenticated":True,"id":user["id"],"username":user["username"],"display_name":user["display_name"],"role":user["role"],**perms}

# ── EVENTS ──
@app.get("/api/events")
async def list_events():
    conn = get_db()
    rows = conn.execute("SELECT events.*, users.display_name as author_name FROM events JOIN users ON events.author_id=users.id ORDER BY events.id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/events/my")
async def my_events(request: Request):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    conn = get_db()
    rows = conn.execute("SELECT events.*, users.display_name as author_name FROM events JOIN users ON events.author_id=users.id WHERE events.author_id=? ORDER BY events.id DESC", (user["id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/events/{eid}")
async def get_event(eid: int):
    conn = get_db()
    row = conn.execute("SELECT events.*, users.display_name as author_name FROM events JOIN users ON events.author_id=users.id WHERE events.id=?", (eid,)).fetchone()
    conn.close()
    if not row: raise HTTPException(status_code=404)
    return dict(row)

@app.post("/api/events")
async def create_event(request: Request, title:str=Form(...), event_type:str=Form(...), duration:str=Form(...), location:str=Form(...), organizer_name:str=Form(...), short_desc:str=Form(...), full_desc:str=Form(...), rules_text:str=Form(""), rewards_text:str=Form("")):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    conn = get_db()
    c = conn.execute("INSERT INTO events (title,event_type,duration,location,organizer_name,author_id,short_desc,full_desc,rules_text,rewards_text,status) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (title,event_type,duration,location,organizer_name,user["id"],short_desc,full_desc,rules_text,rewards_text,"pending"))
    conn.commit(); eid=c.lastrowid; conn.close()
    return {"success":True,"event_id":eid}

@app.put("/api/events/{eid}")
async def update_event(eid:int, request:Request, title:str=Form(...), event_type:str=Form(...), duration:str=Form(...), location:str=Form(...), organizer_name:str=Form(...), short_desc:str=Form(...), full_desc:str=Form(...), rules_text:str=Form(""), rewards_text:str=Form("")):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not ev: conn.close(); raise HTTPException(status_code=404)
    # Approved events: only admin can edit
    if ev["status"] == "approved" and user["role"] != "admin":
        conn.close(); raise HTTPException(status_code=403, detail="Одобренные ивенты может редактировать только Главный Ивентолог")
    # Permission check
    if not perms["can_edit_all"] and ev["author_id"] != user["id"]:
        conn.close(); raise HTTPException(status_code=403, detail="Нет прав")
    # Reset status to pending on edit (except admin)
    new_status = ev["status"] if user["role"] == "admin" else "pending"
    new_reviewed = ev["reviewed_by"] if user["role"] == "admin" else None
    conn.execute("UPDATE events SET title=?,event_type=?,duration=?,location=?,organizer_name=?,short_desc=?,full_desc=?,rules_text=?,rewards_text=?,status=?,reviewed_by=? WHERE id=?",
        (title,event_type,duration,location,organizer_name,short_desc,full_desc,rules_text,rewards_text,new_status,new_reviewed,eid))
    conn.commit(); conn.close()
    return {"success":True}

@app.delete("/api/events/{eid}")
async def delete_event(eid:int, request:Request):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not ev: conn.close(); raise HTTPException(status_code=404)
    if not perms["can_edit_all"] and ev["author_id"] != user["id"]:
        conn.close(); raise HTTPException(status_code=403)
    conn.execute("DELETE FROM events WHERE id=?", (eid,))
    conn.commit(); conn.close()
    reorder_ids("events")
    return {"success":True}

@app.post("/api/events/{eid}/approve")
async def approve_event(eid:int, request:Request):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    if not perms["can_approve"]: raise HTTPException(status_code=403, detail="Нет прав на одобрение")
    conn = get_db()
    if not conn.execute("SELECT 1 FROM events WHERE id=?", (eid,)).fetchone():
        conn.close(); raise HTTPException(status_code=404)
    conn.execute("UPDATE events SET status='approved', reviewed_by=? WHERE id=?", (user["display_name"], eid))
    conn.commit(); conn.close()
    return {"success":True}

@app.post("/api/events/{eid}/reject")
async def reject_event(eid:int, request:Request):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    if not perms["can_approve"]: raise HTTPException(status_code=403, detail="Нет прав на отклонение")
    conn = get_db()
    if not conn.execute("SELECT 1 FROM events WHERE id=?", (eid,)).fetchone():
        conn.close(); raise HTTPException(status_code=404)
    conn.execute("UPDATE events SET status='rejected', reviewed_by=? WHERE id=?", (user["display_name"], eid))
    conn.commit(); conn.close()
    return {"success":True}

# ── USERS ──
@app.get("/api/users")
async def list_users(request:Request):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    if not perms["can_manage_users"]: raise HTTPException(status_code=403)
    conn = get_db()
    rows = conn.execute("SELECT id,username,display_name,role,can_approve,can_edit_all,can_manage_users,created_at FROM users ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/users")
async def create_user(request:Request, username:str=Form(...), password:str=Form(...), display_name:str=Form(...), role:str=Form(...)):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    if not perms["can_manage_users"]: raise HTTPException(status_code=403)
    if role not in ROLE_DEFAULTS: raise HTTPException(status_code=400, detail="Некорректная роль")
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username,password_hash,display_name,role) VALUES (?,?,?,?)", (username, h_pw(password), display_name, role))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); raise HTTPException(status_code=400, detail="Логин уже занят")
    conn.close()
    return {"success":True}

@app.put("/api/users/{uid}/role")
async def update_user_role(uid:int, request:Request, role:str=Form(...)):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    if not perms["can_manage_users"]: raise HTTPException(status_code=403)
    if role not in ROLE_DEFAULTS: raise HTTPException(status_code=400, detail="Некорректная роль")
    if user["id"] == uid: raise HTTPException(status_code=400, detail="Нельзя менять свою роль")
    conn = get_db()
    conn.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    conn.commit(); conn.close()
    return {"success":True}

@app.put("/api/users/{uid}/perms")
async def update_user_perms(uid:int, request:Request, can_approve:str=Form("null"), can_edit_all:str=Form("null"), can_manage_users:str=Form("null")):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    if not perms["can_manage_users"]: raise HTTPException(status_code=403)
    if user["id"] == uid: raise HTTPException(status_code=400, detail="Нельзя менять свои права")
    def parse(v):
        if v == "null": return None
        return 1 if v == "1" else 0
    conn = get_db()
    conn.execute("UPDATE users SET can_approve=?, can_edit_all=?, can_manage_users=? WHERE id=?",
        (parse(can_approve), parse(can_edit_all), parse(can_manage_users), uid))
    conn.commit(); conn.close()
    return {"success":True}

@app.put("/api/users/{uid}/password")
async def update_user_password(uid:int, request:Request, password:str=Form(...)):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    if not perms["can_manage_users"] and user["id"] != uid: raise HTTPException(status_code=403)
    conn = get_db()
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (h_pw(password), uid))
    conn.commit(); conn.close()
    return {"success":True}

@app.delete("/api/users/{uid}")
async def delete_user(uid:int, request:Request):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    if not perms["can_manage_users"]: raise HTTPException(status_code=403)
    if user["id"] == uid: raise HTTPException(status_code=400, detail="Нельзя удалить себя")
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit(); conn.close()
    reorder_ids("users")
    return {"success":True}

# ── SPAWN WHITELIST ──
@app.get("/api/spawn-whitelist")
async def get_spawn_whitelist():
    conn = get_db()
    rows = conn.execute("SELECT * FROM spawn_whitelist ORDER BY category, item_name").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/spawn-whitelist")
async def add_spawn_item(request:Request, item_name:str=Form(...), category:str=Form("")):
    user = get_current_user(request)
    if not user or user["role"] != "admin": raise HTTPException(status_code=403, detail="Только Главный Ивентолог может управлять спавн-листом")
    conn = get_db()
    try:
        conn.execute("INSERT INTO spawn_whitelist (item_name, category, added_by) VALUES (?,?,?)", (item_name.strip(), category.strip(), user["display_name"]))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); raise HTTPException(status_code=400, detail="Предмет уже в списке")
    conn.close()
    return {"success":True}

@app.delete("/api/spawn-whitelist/{item_id}")
async def delete_spawn_item(item_id:int, request:Request):
    user = get_current_user(request)
    if not user or user["role"] != "admin": raise HTTPException(status_code=403)
    conn = get_db()
    conn.execute("DELETE FROM spawn_whitelist WHERE id=?", (item_id,))
    conn.commit(); conn.close()
    return {"success":True}

# ── SPAWN REPORTS ──
@app.get("/api/events/{eid}/spawn-reports")
async def get_spawn_reports(eid:int):
    conn = get_db()
    rows = conn.execute("SELECT * FROM spawn_reports WHERE event_id=? ORDER BY created_at DESC", (eid,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/events/{eid}/spawn-reports")
async def add_spawn_report(eid:int, request:Request, item_name:str=Form(...), quantity:int=Form(1), note:str=Form("")):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not ev: conn.close(); raise HTTPException(status_code=404)
    # Only author or admin/senior can add spawn reports
    perms = get_perms(user)
    if ev["author_id"] != user["id"] and not perms["can_edit_all"]:
        conn.close(); raise HTTPException(status_code=403, detail="Можно отчитываться только по своим ивентам")
    conn.execute("INSERT INTO spawn_reports (event_id, user_id, user_name, item_name, quantity, note) VALUES (?,?,?,?,?,?)",
        (eid, user["id"], user["display_name"], item_name.strip(), quantity, note.strip()))
    conn.commit(); conn.close()
    return {"success":True}

@app.delete("/api/spawn-reports/{rid}")
async def delete_spawn_report(rid:int, request:Request):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    conn = get_db()
    report = conn.execute("SELECT * FROM spawn_reports WHERE id=?", (rid,)).fetchone()
    if not report: conn.close(); raise HTTPException(status_code=404)
    perms = get_perms(user)
    if report["user_id"] != user["id"] and not perms["can_edit_all"]:
        conn.close(); raise HTTPException(status_code=403)
    conn.execute("DELETE FROM spawn_reports WHERE id=?", (rid,))
    conn.commit(); conn.close()
    return {"success":True}

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def index():
    with open("static/index.html","r",encoding="utf-8") as f:
        return HTMLResponse(content=f.read())
