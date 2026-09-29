import os, sqlite3, hashlib, json
from fastapi import FastAPI, HTTPException, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timedelta
import jwt

app = FastAPI(title="Stalker RP Event Hub")
DB_PATH = "events.db"
SECRET_KEY = os.environ.get("SECRET_KEY", "stalker_zone_secret_key_change_me_in_prod")
ALGORITHM = "HS256"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def h_pw(p): return hashlib.sha256(p.encode('utf-8')).hexdigest()
def v_pw(p, h): return h_pw(p) == h

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Roles table (dynamic)
    c.execute('''CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role_key TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        color TEXT DEFAULT '#4ade80',
        priority INTEGER DEFAULT 10,
        can_approve INTEGER DEFAULT 0,
        can_edit_all INTEGER DEFAULT 0,
        can_manage_users INTEGER DEFAULT 0,
        can_manage_roles INTEGER DEFAULT 0,
        is_system INTEGER DEFAULT 0
    )''')
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
        title TEXT NOT NULL, event_type TEXT NOT NULL, duration TEXT NOT NULL,
        location TEXT NOT NULL, organizer_name TEXT NOT NULL,
        author_id INTEGER NOT NULL, short_desc TEXT NOT NULL, full_desc TEXT NOT NULL,
        rules_text TEXT, rewards_text TEXT,
        status TEXT DEFAULT 'pending', reviewed_by TEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (author_id) REFERENCES users (id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS spawn_whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_name TEXT UNIQUE NOT NULL, category TEXT DEFAULT '',
        added_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS spawn_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL, user_id INTEGER NOT NULL, user_name TEXT NOT NULL,
        item_name TEXT NOT NULL, quantity INTEGER NOT NULL DEFAULT 1,
        note TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (event_id) REFERENCES events (id), FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    # Migrations
    for col in ("can_approve","can_edit_all","can_manage_users"):
        try: c.execute(f"ALTER TABLE users ADD COLUMN {col} INTEGER DEFAULT NULL")
        except: pass
    try: c.execute("ALTER TABLE roles ADD COLUMN can_manage_roles INTEGER DEFAULT 0")
    except: pass
    try: c.execute("ALTER TABLE roles ADD COLUMN is_system INTEGER DEFAULT 0")
    except: pass

    # Seed default roles if empty
    c.execute("SELECT COUNT(*) FROM roles")
    if c.fetchone()[0] == 0:
        default_roles = [
            ("head_admin",          "Head Admin",           "#ff6b6b", 100, 1,1,1,1, 1),
            ("admin",               "Главный Ивентолог",    "#f59e0b", 80,  1,1,1,1, 1),
            ("senior_eventologist", "Ст. Ивентолог",        "#a78bfa", 60,  1,1,0,0, 1),
            ("eventologist",        "Ивентолог",            "#4ade80", 40,  0,0,0,0, 1),
            ("junior_eventologist", "Мл. Ивентолог",        "#5a856a", 20,  0,0,0,0, 1),
        ]
        c.executemany("INSERT INTO roles (role_key,display_name,color,priority,can_approve,can_edit_all,can_manage_users,can_manage_roles,is_system) VALUES (?,?,?,?,?,?,?,?,?)", default_roles)

    # Seed default users if empty
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.executemany("INSERT INTO users (username,password_hash,display_name,role) VALUES (?,?,?,?)", [
            ("headadmin", h_pw("headadmin123"), "Head Admin", "head_admin"),
            ("admin",     h_pw("admin123"),     "Главный Ивентолог Пушкин", "admin"),
            ("senior",    h_pw("senior123"),    "Ст.Ивентолог", "senior_eventologist"),
            ("eventolog", h_pw("event123"),     "Ивентолог", "eventologist"),
            ("junior",    h_pw("junior123"),    "Мл.Ивентолог", "junior_eventologist"),
        ])
    conn.commit(); conn.close()

init_db()

# ── Permissions helper ──
_roles_cache = {}
def get_role_data(role_key):
    if role_key not in _roles_cache or True:  # always refresh for now
        conn = get_db()
        row = conn.execute("SELECT * FROM roles WHERE role_key=?", (role_key,)).fetchone()
        conn.close()
        _roles_cache[role_key] = dict(row) if row else None
    return _roles_cache.get(role_key)

def get_perms(user):
    rd = get_role_data(user["role"]) or {"can_approve":0,"can_edit_all":0,"can_manage_users":0,"can_manage_roles":0}
    perms = {}
    for key in ("can_approve","can_edit_all","can_manage_users"):
        uval = user[key]
        perms[key] = bool(uval) if uval is not None else bool(rd.get(key,0))
    perms["can_manage_roles"] = bool(rd.get("can_manage_roles",0))
    perms["priority"] = rd.get("priority",0)
    return perms

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
    conn = get_db()
    rows = conn.execute(f"SELECT id FROM {table} ORDER BY id ASC").fetchall()
    for new_id, row in enumerate(rows, 1):
        old_id = row["id"]
        if old_id != new_id:
            if table == "users":
                conn.execute("UPDATE events SET author_id=? WHERE author_id=?", (new_id, old_id))
                conn.execute("UPDATE spawn_reports SET user_id=? WHERE user_id=?", (new_id, old_id))
            if table == "events":
                conn.execute("UPDATE spawn_reports SET event_id=? WHERE event_id=?", (new_id, old_id))
            conn.execute(f"UPDATE {table} SET id=? WHERE id=?", (new_id, old_id))
    max_id = len(rows)
    conn.execute(f"DELETE FROM sqlite_sequence WHERE name=?", (table,))
    if max_id > 0:
        conn.execute(f"INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)", (table, max_id))
    conn.commit(); conn.close()

# ══════════════════════ AUTH ══════════════════════
@app.post("/api/login")
async def login(username:str=Form(...), password:str=Form(...)):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not user or not v_pw(password, user["password_hash"]):
        return JSONResponse({"error":"Неверный логин или пароль"}, status_code=400)
    token = jwt.encode({"sub":user["username"],"role":user["role"],"exp":datetime.utcnow()+timedelta(days=7)}, SECRET_KEY, algorithm=ALGORITHM)
    resp = JSONResponse({"success":True})
    resp.set_cookie(key="access_token", value=token, httponly=True, max_age=604800)
    return resp

@app.post("/api/logout")
async def logout():
    resp = JSONResponse({"success":True}); resp.delete_cookie("access_token"); return resp

@app.get("/api/me")
async def me(request:Request):
    user = get_current_user(request)
    if not user: return JSONResponse({"authenticated":False})
    perms = get_perms(user)
    rd = get_role_data(user["role"])
    return {"authenticated":True,"id":user["id"],"username":user["username"],"display_name":user["display_name"],"role":user["role"],
            "role_display": rd["display_name"] if rd else user["role"], "role_color": rd["color"] if rd else "#4ade80", **perms}

# ══════════════════════ ROLES ══════════════════════
@app.get("/api/roles")
async def list_roles():
    conn = get_db()
    rows = conn.execute("SELECT * FROM roles ORDER BY priority DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/roles")
async def create_role(request:Request, role_key:str=Form(...), display_name:str=Form(...), color:str=Form("#4ade80"),
                      priority:int=Form(10), can_approve:int=Form(0), can_edit_all:int=Form(0),
                      can_manage_users:int=Form(0), can_manage_roles:int=Form(0)):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    if not perms["can_manage_roles"]: raise HTTPException(status_code=403, detail="Нет прав на управление ролями")
    conn = get_db()
    try:
        conn.execute("INSERT INTO roles (role_key,display_name,color,priority,can_approve,can_edit_all,can_manage_users,can_manage_roles,is_system) VALUES (?,?,?,?,?,?,?,?,0)",
            (role_key.strip().lower().replace(" ","_"), display_name.strip(), color.strip(), priority, can_approve, can_edit_all, can_manage_users, can_manage_roles))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); raise HTTPException(status_code=400, detail="Роль с таким ключом уже существует")
    conn.close()
    return {"success":True}

@app.put("/api/roles/{role_id}")
async def update_role(role_id:int, request:Request, display_name:str=Form(...), color:str=Form("#4ade80"),
                      priority:int=Form(10), can_approve:int=Form(0), can_edit_all:int=Form(0),
                      can_manage_users:int=Form(0), can_manage_roles:int=Form(0)):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    if not perms["can_manage_roles"]: raise HTTPException(status_code=403)
    conn = get_db()
    conn.execute("UPDATE roles SET display_name=?,color=?,priority=?,can_approve=?,can_edit_all=?,can_manage_users=?,can_manage_roles=? WHERE id=?",
        (display_name.strip(), color.strip(), priority, can_approve, can_edit_all, can_manage_users, can_manage_roles, role_id))
    conn.commit(); conn.close()
    return {"success":True}

@app.delete("/api/roles/{role_id}")
async def delete_role(role_id:int, request:Request):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    if not perms["can_manage_roles"]: raise HTTPException(status_code=403)
    conn = get_db()
    role = conn.execute("SELECT * FROM roles WHERE id=?", (role_id,)).fetchone()
    if not role: conn.close(); raise HTTPException(status_code=404)
    if role["is_system"]: conn.close(); raise HTTPException(status_code=400, detail="Системные роли нельзя удалить")
    # Check if anyone uses this role
    count = conn.execute("SELECT COUNT(*) FROM users WHERE role=?", (role["role_key"],)).fetchone()[0]
    if count > 0: conn.close(); raise HTTPException(status_code=400, detail=f"Роль используется ({count} пользователей). Сначала смените им роль.")
    conn.execute("DELETE FROM roles WHERE id=?", (role_id,))
    conn.commit(); conn.close()
    return {"success":True}

# ══════════════════════ EVENTS ══════════════════════
@app.get("/api/events")
async def list_events():
    conn = get_db()
    rows = conn.execute("SELECT events.*, users.display_name as author_name FROM events JOIN users ON events.author_id=users.id ORDER BY events.id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/events/my")
async def my_events(request:Request):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    conn = get_db()
    rows = conn.execute("SELECT events.*, users.display_name as author_name FROM events JOIN users ON events.author_id=users.id WHERE events.author_id=? ORDER BY events.id DESC", (user["id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/events/{eid}")
async def get_event(eid:int):
    conn = get_db()
    row = conn.execute("SELECT events.*, users.display_name as author_name FROM events JOIN users ON events.author_id=users.id WHERE events.id=?", (eid,)).fetchone()
    conn.close()
    if not row: raise HTTPException(status_code=404)
    return dict(row)

@app.post("/api/events")
async def create_event(request:Request, title:str=Form(...), event_type:str=Form(...), duration:str=Form(...), location:str=Form(...), organizer_name:str=Form(...), short_desc:str=Form(...), full_desc:str=Form(...), rules_text:str=Form(""), rewards_text:str=Form("")):
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
    is_top = user["role"] in ("head_admin","admin")
    if ev["status"] == "approved" and not is_top:
        conn.close(); raise HTTPException(status_code=403, detail="Одобренные ивенты может редактировать только Главный Ивентолог или Head Admin")
    if not perms["can_edit_all"] and ev["author_id"] != user["id"]:
        conn.close(); raise HTTPException(status_code=403, detail="Нет прав")
    new_status = ev["status"] if is_top else "pending"
    new_reviewed = ev["reviewed_by"] if is_top else None
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
    conn.execute("DELETE FROM spawn_reports WHERE event_id=?", (eid,))
    conn.execute("DELETE FROM events WHERE id=?", (eid,))
    conn.commit(); conn.close()
    reorder_ids("events")
    return {"success":True}

@app.post("/api/events/{eid}/approve")
async def approve_event(eid:int, request:Request):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    if not perms["can_approve"]: raise HTTPException(status_code=403)
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
    if not perms["can_approve"]: raise HTTPException(status_code=403)
    conn = get_db()
    if not conn.execute("SELECT 1 FROM events WHERE id=?", (eid,)).fetchone():
        conn.close(); raise HTTPException(status_code=404)
    conn.execute("UPDATE events SET status='rejected', reviewed_by=? WHERE id=?", (user["display_name"], eid))
    conn.commit(); conn.close()
    return {"success":True}

# ══════════════════════ SPAWN ══════════════════════
@app.get("/api/spawn-whitelist")
async def get_spawn_whitelist():
    conn = get_db()
    rows = conn.execute("SELECT * FROM spawn_whitelist ORDER BY category, item_name").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/spawn-whitelist")
async def add_spawn_item(request:Request, item_name:str=Form(...), category:str=Form("")):
    user = get_current_user(request)
    if not user: raise HTTPException(status_code=401)
    perms = get_perms(user)
    if user["role"] not in ("head_admin","admin"): raise HTTPException(status_code=403, detail="Только Head Admin или Главный Ивентолог")
    conn = get_db()
    try:
        conn.execute("INSERT INTO spawn_whitelist (item_name,category,added_by) VALUES (?,?,?)", (item_name.strip(), category.strip(), user["display_name"]))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); raise HTTPException(status_code=400, detail="Предмет уже в списке")
    conn.close()
    return {"success":True}

@app.delete("/api/spawn-whitelist/{item_id}")
async def delete_spawn_item(item_id:int, request:Request):
    user = get_current_user(request)
    if not user or user["role"] not in ("head_admin","admin"): raise HTTPException(status_code=403)
    conn = get_db()
    conn.execute("DELETE FROM spawn_whitelist WHERE id=?", (item_id,))
    conn.commit(); conn.close()
    return {"success":True}

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
    perms = get_perms(user)
    if ev["author_id"] != user["id"] and not perms["can_edit_all"]:
        conn.close(); raise HTTPException(status_code=403, detail="Можно отчитываться только по своим ивентам")
    conn.execute("INSERT INTO spawn_reports (event_id,user_id,user_name,item_name,quantity,note) VALUES (?,?,?,?,?,?)",
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

# ══════════════════════ USERS ══════════════════════
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
    conn = get_db()
    if not conn.execute("SELECT 1 FROM roles WHERE role_key=?", (role,)).fetchone():
        conn.close(); raise HTTPException(status_code=400, detail="Роль не существует")
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
    if user["id"] == uid: raise HTTPException(status_code=400, detail="Нельзя менять свою роль")
    conn = get_db()
    if not conn.execute("SELECT 1 FROM roles WHERE role_key=?", (role,)).fetchone():
        conn.close(); raise HTTPException(status_code=400, detail="Роль не существует")
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

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def index():
    with open("static/index.html","r",encoding="utf-8") as f:
        return HTMLResponse(content=f.read())
