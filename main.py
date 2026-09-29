import os, sqlite3, hashlib, json
from fastapi import FastAPI, HTTPException, Form, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timedelta
import jwt

app = FastAPI(title="Stalker RP Event Hub")
DB_PATH = "events.db"
SECRET_KEY = os.environ.get("SECRET_KEY", "stalker_zone_secret_key_change_me_in_prod")
ALGORITHM = "HS256"

STATUSES = {
    "draft":     {"label":"Черновик",     "icon":"📝","color":"#6b7280"},
    "pending":   {"label":"На проверке",  "icon":"⏳","color":"#eab308"},
    "approved":  {"label":"Одобрен",      "icon":"✅","color":"#22c55e"},
    "scheduled": {"label":"Запланирован", "icon":"📅","color":"#3b82f6"},
    "active":    {"label":"Проводится",   "icon":"🔥","color":"#f97316"},
    "completed": {"label":"Завершён",     "icon":"🏁","color":"#8b5cf6"},
    "archived":  {"label":"Архив",        "icon":"📦","color":"#6b7280"},
}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
def h_pw(p): return hashlib.sha256(p.encode('utf-8')).hexdigest()
def v_pw(p, h): return h_pw(p) == h

def init_db():
    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT, role_key TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
        color TEXT DEFAULT '#4ade80', priority INTEGER DEFAULT 10,
        can_approve INTEGER DEFAULT 0, can_edit_all INTEGER DEFAULT 0,
        can_manage_users INTEGER DEFAULT 0, can_manage_roles INTEGER DEFAULT 0, is_system INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'junior_eventologist',
        can_approve INTEGER DEFAULT NULL, can_edit_all INTEGER DEFAULT NULL, can_manage_users INTEGER DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, event_type TEXT NOT NULL,
        duration TEXT NOT NULL, location TEXT NOT NULL, organizer_name TEXT NOT NULL,
        author_id INTEGER NOT NULL, short_desc TEXT NOT NULL, full_desc TEXT NOT NULL,
        rules_text TEXT, rewards_text TEXT, status TEXT DEFAULT 'pending',
        reviewed_by TEXT DEFAULT NULL, event_date TEXT DEFAULT NULL, event_time TEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (author_id) REFERENCES users (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS spawn_whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT, item_name TEXT UNIQUE NOT NULL, category TEXT DEFAULT '',
        added_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS spawn_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        user_name TEXT NOT NULL, item_name TEXT NOT NULL, quantity INTEGER NOT NULL DEFAULT 1,
        note TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (event_id) REFERENCES events (id), FOREIGN KEY (user_id) REFERENCES users (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        user_name TEXT NOT NULL, user_role TEXT NOT NULL, text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (event_id) REFERENCES events (id), FOREIGN KEY (user_id) REFERENCES users (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL,
        message TEXT NOT NULL, event_id INTEGER DEFAULT NULL, is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users (id))''')
    # Migrations
    for col in ("can_approve","can_edit_all","can_manage_users"):
        try: c.execute(f"ALTER TABLE users ADD COLUMN {col} INTEGER DEFAULT NULL")
        except: pass
    for col in ("can_manage_roles","is_system"):
        try: c.execute(f"ALTER TABLE roles ADD COLUMN {col} INTEGER DEFAULT 0")
        except: pass
    for col in ("event_date","event_time"):
        try: c.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT DEFAULT NULL")
        except: pass
    # Seed roles
    c.execute("SELECT COUNT(*) FROM roles")
    if c.fetchone()[0] == 0:
        c.executemany("INSERT INTO roles (role_key,display_name,color,priority,can_approve,can_edit_all,can_manage_users,can_manage_roles,is_system) VALUES (?,?,?,?,?,?,?,?,?)", [
            ("head_admin","Head Admin","#ff6b6b",100,1,1,1,1,1),
            ("admin","Главный Ивентолог","#f59e0b",80,1,1,1,1,1),
            ("senior_eventologist","Ст. Ивентолог","#a78bfa",60,1,1,0,0,1),
            ("eventologist","Ивентолог","#4ade80",40,0,0,0,0,1),
            ("junior_eventologist","Мл. Ивентолог","#5a856a",20,0,0,0,0,1),
        ])
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.executemany("INSERT INTO users (username,password_hash,display_name,role) VALUES (?,?,?,?)", [
            ("headadmin",h_pw("headadmin123"),"Head Admin","head_admin"),
            ("admin",h_pw("admin123"),"Главный Ивентолог Пушкин","admin"),
            ("senior",h_pw("senior123"),"Ст.Ивентолог","senior_eventologist"),
            ("eventolog",h_pw("event123"),"Ивентолог","eventologist"),
            ("junior",h_pw("junior123"),"Мл.Ивентолог","junior_eventologist"),
        ])
    conn.commit(); conn.close()

init_db()

def get_role_data(rk):
    conn = get_db(); r = conn.execute("SELECT * FROM roles WHERE role_key=?", (rk,)).fetchone(); conn.close()
    return dict(r) if r else None

def get_perms(user):
    rd = get_role_data(user["role"]) or {"can_approve":0,"can_edit_all":0,"can_manage_users":0,"can_manage_roles":0}
    p = {}
    for k in ("can_approve","can_edit_all","can_manage_users"):
        v = user[k]; p[k] = bool(v) if v is not None else bool(rd.get(k,0))
    p["can_manage_roles"] = bool(rd.get("can_manage_roles",0))
    return p

def get_current_user(req):
    token = req.cookies.get("access_token")
    if not token: return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        un = payload.get("sub")
        if not un: return None
    except: return None
    conn = get_db(); u = conn.execute("SELECT * FROM users WHERE username=?", (un,)).fetchone(); conn.close()
    return u

def notify(user_id, type, message, event_id=None):
    conn = get_db()
    conn.execute("INSERT INTO notifications (user_id,type,message,event_id) VALUES (?,?,?,?)", (user_id,type,message,event_id))
    conn.commit(); conn.close()

def reorder_ids(table):
    conn = get_db(); rows = conn.execute(f"SELECT id FROM {table} ORDER BY id ASC").fetchall()
    for ni, row in enumerate(rows, 1):
        oi = row["id"]
        if oi != ni:
            if table == "users":
                conn.execute("UPDATE events SET author_id=? WHERE author_id=?", (ni,oi))
                conn.execute("UPDATE spawn_reports SET user_id=? WHERE user_id=?", (ni,oi))
                conn.execute("UPDATE comments SET user_id=? WHERE user_id=?", (ni,oi))
                conn.execute("UPDATE notifications SET user_id=? WHERE user_id=?", (ni,oi))
            if table == "events":
                conn.execute("UPDATE spawn_reports SET event_id=? WHERE event_id=?", (ni,oi))
                conn.execute("UPDATE comments SET event_id=? WHERE event_id=?", (ni,oi))
            conn.execute(f"UPDATE {table} SET id=? WHERE id=?", (ni,oi))
    mx = len(rows)
    conn.execute(f"DELETE FROM sqlite_sequence WHERE name=?", (table,))
    if mx > 0: conn.execute(f"INSERT INTO sqlite_sequence (name,seq) VALUES (?,?)", (table,mx))
    conn.commit(); conn.close()

# ═══ AUTH ═══
@app.post("/api/login")
async def login(username:str=Form(...), password:str=Form(...)):
    conn = get_db(); u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone(); conn.close()
    if not u or not v_pw(password, u["password_hash"]): return JSONResponse({"error":"Неверный логин или пароль"}, status_code=400)
    token = jwt.encode({"sub":u["username"],"exp":datetime.utcnow()+timedelta(days=7)}, SECRET_KEY, algorithm=ALGORITHM)
    resp = JSONResponse({"success":True}); resp.set_cookie(key="access_token",value=token,httponly=True,max_age=604800); return resp

@app.post("/api/logout")
async def logout():
    resp = JSONResponse({"success":True}); resp.delete_cookie("access_token"); return resp

@app.get("/api/me")
async def me(req:Request):
    u = get_current_user(req)
    if not u: return {"authenticated":False}
    p = get_perms(u); rd = get_role_data(u["role"])
    return {"authenticated":True,"id":u["id"],"username":u["username"],"display_name":u["display_name"],"role":u["role"],
            "role_display":rd["display_name"] if rd else u["role"],"role_color":rd["color"] if rd else "#4ade80",**p}

@app.get("/api/statuses")
async def get_statuses():
    return STATUSES

# ═══ ROLES ═══
@app.get("/api/roles")
async def list_roles():
    conn = get_db(); rows = conn.execute("SELECT * FROM roles ORDER BY priority DESC").fetchall(); conn.close()
    return [dict(r) for r in rows]

@app.post("/api/roles")
async def create_role(req:Request, role_key:str=Form(...), display_name:str=Form(...), color:str=Form("#4ade80"),
                      priority:int=Form(10), can_approve:int=Form(0), can_edit_all:int=Form(0),
                      can_manage_users:int=Form(0), can_manage_roles:int=Form(0)):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_roles"]: raise HTTPException(403)
    conn = get_db()
    try:
        conn.execute("INSERT INTO roles (role_key,display_name,color,priority,can_approve,can_edit_all,can_manage_users,can_manage_roles,is_system) VALUES (?,?,?,?,?,?,?,?,0)",
            (role_key.strip().lower().replace(" ","_"),display_name.strip(),color.strip(),priority,can_approve,can_edit_all,can_manage_users,can_manage_roles))
        conn.commit()
    except sqlite3.IntegrityError: conn.close(); raise HTTPException(400, detail="Ключ роли уже занят")
    conn.close(); return {"success":True}

@app.put("/api/roles/{rid}")
async def update_role(rid:int, req:Request, display_name:str=Form(...), color:str=Form("#4ade80"),
                      priority:int=Form(10), can_approve:int=Form(0), can_edit_all:int=Form(0),
                      can_manage_users:int=Form(0), can_manage_roles:int=Form(0)):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_roles"]: raise HTTPException(403)
    conn = get_db()
    conn.execute("UPDATE roles SET display_name=?,color=?,priority=?,can_approve=?,can_edit_all=?,can_manage_users=?,can_manage_roles=? WHERE id=?",
        (display_name.strip(),color.strip(),priority,can_approve,can_edit_all,can_manage_users,can_manage_roles,rid))
    conn.commit(); conn.close(); return {"success":True}

@app.delete("/api/roles/{rid}")
async def delete_role(rid:int, req:Request):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_roles"]: raise HTTPException(403)
    conn = get_db(); role = conn.execute("SELECT * FROM roles WHERE id=?", (rid,)).fetchone()
    if not role: conn.close(); raise HTTPException(404)
    if role["is_system"]: conn.close(); raise HTTPException(400, detail="Системную роль нельзя удалить")
    cnt = conn.execute("SELECT COUNT(*) FROM users WHERE role=?", (role["role_key"],)).fetchone()[0]
    if cnt > 0: conn.close(); raise HTTPException(400, detail=f"Роль используется ({cnt} чел.)")
    conn.execute("DELETE FROM roles WHERE id=?", (rid,)); conn.commit(); conn.close(); return {"success":True}

# ═══ EVENTS ═══
@app.get("/api/events")
async def list_events(status:str=Query(None)):
    conn = get_db()
    q = "SELECT events.*, users.display_name as author_name FROM events JOIN users ON events.author_id=users.id"
    if status: q += f" WHERE events.status='{status}'"
    q += " ORDER BY events.id DESC"
    rows = conn.execute(q).fetchall(); conn.close(); return [dict(r) for r in rows]

@app.get("/api/events/my")
async def my_events(req:Request):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    conn = get_db()
    rows = conn.execute("SELECT events.*, users.display_name as author_name FROM events JOIN users ON events.author_id=users.id WHERE events.author_id=? ORDER BY events.id DESC", (u["id"],)).fetchall()
    conn.close(); return [dict(r) for r in rows]

@app.get("/api/events/calendar")
async def calendar_events():
    conn = get_db()
    rows = conn.execute("SELECT id,title,event_type,event_date,event_time,status,location,duration FROM events WHERE event_date IS NOT NULL AND event_date != '' ORDER BY event_date ASC").fetchall()
    conn.close(); return [dict(r) for r in rows]

@app.get("/api/events/{eid}")
async def get_event(eid:int):
    conn = get_db()
    row = conn.execute("SELECT events.*, users.display_name as author_name FROM events JOIN users ON events.author_id=users.id WHERE events.id=?", (eid,)).fetchone()
    conn.close()
    if not row: raise HTTPException(404); return dict(row)

@app.post("/api/events")
async def create_event(req:Request, title:str=Form(...), event_type:str=Form(...), duration:str=Form(...), location:str=Form(...), organizer_name:str=Form(...), short_desc:str=Form(...), full_desc:str=Form(...), rules_text:str=Form(""), rewards_text:str=Form(""), event_date:str=Form(""), event_time:str=Form(""), status:str=Form("pending")):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    if status not in ("draft","pending"): status = "pending"
    conn = get_db()
    c = conn.execute("INSERT INTO events (title,event_type,duration,location,organizer_name,author_id,short_desc,full_desc,rules_text,rewards_text,status,event_date,event_time) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (title,event_type,duration,location,organizer_name,u["id"],short_desc,full_desc,rules_text,rewards_text,status,event_date or None,event_time or None))
    conn.commit(); eid=c.lastrowid; conn.close(); return {"success":True,"event_id":eid}

@app.put("/api/events/{eid}")
async def update_event(eid:int, req:Request, title:str=Form(...), event_type:str=Form(...), duration:str=Form(...), location:str=Form(...), organizer_name:str=Form(...), short_desc:str=Form(...), full_desc:str=Form(...), rules_text:str=Form(""), rewards_text:str=Form(""), event_date:str=Form(""), event_time:str=Form("")):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    p = get_perms(u); conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not ev: conn.close(); raise HTTPException(404)
    isTop = u["role"] in ("head_admin","admin")
    if ev["status"] in ("approved","scheduled","active","completed") and not isTop:
        conn.close(); raise HTTPException(403, detail="Одобренные/активные ивенты может редактировать только Head Admin или Главный Ивентолог")
    if not p["can_edit_all"] and ev["author_id"] != u["id"]: conn.close(); raise HTTPException(403)
    ns = ev["status"] if isTop else "pending"
    nr = ev["reviewed_by"] if isTop else None
    conn.execute("UPDATE events SET title=?,event_type=?,duration=?,location=?,organizer_name=?,short_desc=?,full_desc=?,rules_text=?,rewards_text=?,status=?,reviewed_by=?,event_date=?,event_time=? WHERE id=?",
        (title,event_type,duration,location,organizer_name,short_desc,full_desc,rules_text,rewards_text,ns,nr,event_date or None,event_time or None,eid))
    conn.commit(); conn.close(); return {"success":True}

@app.put("/api/events/{eid}/status")
async def change_event_status(eid:int, req:Request, status:str=Form(...)):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    if status not in STATUSES: raise HTTPException(400, detail="Неизвестный статус")
    p = get_perms(u); conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not ev: conn.close(); raise HTTPException(404)
    need_approve = status in ("approved","scheduled","active","completed","archived")
    if need_approve and not p["can_approve"] and u["role"] not in ("head_admin","admin"):
        conn.close(); raise HTTPException(403, detail="Нет прав менять на этот статус")
    rb = u["display_name"] if need_approve else ev["reviewed_by"]
    conn.execute("UPDATE events SET status=?, reviewed_by=? WHERE id=?", (status, rb, eid))
    conn.commit(); conn.close()
    # Notify author
    if ev["author_id"] != u["id"]:
        sl = STATUSES.get(status,{})
        notify(ev["author_id"], "status_change", f'{sl.get("icon","")} Ивент «{ev["title"]}» — {sl.get("label",status)} (от {u["display_name"]})', eid)
    return {"success":True}

@app.delete("/api/events/{eid}")
async def delete_event(eid:int, req:Request):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    p = get_perms(u); conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not ev: conn.close(); raise HTTPException(404)
    if not p["can_edit_all"] and ev["author_id"] != u["id"]: conn.close(); raise HTTPException(403)
    for t in ("spawn_reports","comments"): conn.execute(f"DELETE FROM {t} WHERE event_id=?", (eid,))
    conn.execute("DELETE FROM notifications WHERE event_id=?", (eid,))
    conn.execute("DELETE FROM events WHERE id=?", (eid,)); conn.commit(); conn.close()
    reorder_ids("events"); return {"success":True}

@app.post("/api/events/{eid}/approve")
async def approve_event(eid:int, req:Request):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_approve"]: raise HTTPException(403)
    conn = get_db(); ev = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not ev: conn.close(); raise HTTPException(404)
    conn.execute("UPDATE events SET status='approved',reviewed_by=? WHERE id=?", (u["display_name"],eid)); conn.commit(); conn.close()
    if ev["author_id"] != u["id"]: notify(ev["author_id"],"approved",f'✅ Ивент «{ev["title"]}» одобрен ({u["display_name"]})',eid)
    return {"success":True}

@app.post("/api/events/{eid}/reject")
async def reject_event(eid:int, req:Request):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_approve"]: raise HTTPException(403)
    conn = get_db(); ev = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not ev: conn.close(); raise HTTPException(404)
    conn.execute("UPDATE events SET status='pending',reviewed_by=? WHERE id=?", (u["display_name"],eid)); conn.commit(); conn.close()
    if ev["author_id"] != u["id"]: notify(ev["author_id"],"rejected",f'❌ Ивент «{ev["title"]}» отклонён ({u["display_name"]})',eid)
    return {"success":True}

# ═══ COMMENTS ═══
@app.get("/api/events/{eid}/comments")
async def get_comments(eid:int):
    conn = get_db(); rows = conn.execute("SELECT * FROM comments WHERE event_id=? ORDER BY created_at ASC", (eid,)).fetchall(); conn.close()
    return [dict(r) for r in rows]

@app.post("/api/events/{eid}/comments")
async def add_comment(eid:int, req:Request, text:str=Form(...)):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    rd = get_role_data(u["role"])
    conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not ev: conn.close(); raise HTTPException(404)
    conn.execute("INSERT INTO comments (event_id,user_id,user_name,user_role,text) VALUES (?,?,?,?,?)",
        (eid,u["id"],u["display_name"],rd["display_name"] if rd else u["role"],text.strip()))
    conn.commit(); conn.close()
    if ev["author_id"] != u["id"]:
        notify(ev["author_id"],"comment",f'💬 {u["display_name"]} прокомментировал «{ev["title"]}»',eid)
    return {"success":True}

@app.delete("/api/comments/{cid}")
async def delete_comment(cid:int, req:Request):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    conn = get_db(); c = conn.execute("SELECT * FROM comments WHERE id=?", (cid,)).fetchone()
    if not c: conn.close(); raise HTTPException(404)
    if c["user_id"] != u["id"] and not get_perms(u)["can_edit_all"]: conn.close(); raise HTTPException(403)
    conn.execute("DELETE FROM comments WHERE id=?", (cid,)); conn.commit(); conn.close(); return {"success":True}

# ═══ NOTIFICATIONS ═══
@app.get("/api/notifications")
async def get_notifications(req:Request):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    conn = get_db()
    rows = conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50", (u["id"],)).fetchall()
    unread = conn.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0", (u["id"],)).fetchone()[0]
    conn.close(); return {"notifications":[dict(r) for r in rows],"unread":unread}

@app.post("/api/notifications/read-all")
async def read_all_notifications(req:Request):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    conn = get_db(); conn.execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (u["id"],)); conn.commit(); conn.close()
    return {"success":True}

@app.get("/api/notifications/count")
async def notification_count(req:Request):
    u = get_current_user(req)
    if not u: return {"count":0}
    conn = get_db(); cnt = conn.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0", (u["id"],)).fetchone()[0]; conn.close()
    return {"count":cnt}

# ═══ STATS ═══
@app.get("/api/stats")
async def get_stats():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    by_status = {}
    for s in STATUSES:
        by_status[s] = conn.execute("SELECT COUNT(*) FROM events WHERE status=?", (s,)).fetchone()[0]
    top_authors = conn.execute("SELECT users.display_name, COUNT(*) as cnt FROM events JOIN users ON events.author_id=users.id GROUP BY author_id ORDER BY cnt DESC LIMIT 5").fetchall()
    top_spawn = conn.execute("SELECT item_name, SUM(quantity) as total FROM spawn_reports GROUP BY item_name ORDER BY total DESC LIMIT 5").fetchall()
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_comments = conn.execute("SELECT COUNT(*) FROM comments").fetchone()[0]
    total_spawned = conn.execute("SELECT COALESCE(SUM(quantity),0) FROM spawn_reports").fetchone()[0]
    conn.close()
    return {"total_events":total,"by_status":by_status,"total_users":total_users,"total_comments":total_comments,
            "total_spawned":total_spawned,
            "top_authors":[{"name":r[0],"count":r[1]} for r in top_authors],
            "top_spawn":[{"item":r[0],"total":r[1]} for r in top_spawn]}

# ═══ SPAWN ═══
@app.get("/api/spawn-whitelist")
async def get_spawn_whitelist():
    conn = get_db(); rows = conn.execute("SELECT * FROM spawn_whitelist ORDER BY category, item_name").fetchall(); conn.close()
    return [dict(r) for r in rows]

@app.post("/api/spawn-whitelist")
async def add_spawn_item(req:Request, item_name:str=Form(...), category:str=Form("")):
    u = get_current_user(req)
    if not u or u["role"] not in ("head_admin","admin"): raise HTTPException(403)
    conn = get_db()
    try: conn.execute("INSERT INTO spawn_whitelist (item_name,category,added_by) VALUES (?,?,?)", (item_name.strip(),category.strip(),u["display_name"])); conn.commit()
    except sqlite3.IntegrityError: conn.close(); raise HTTPException(400, detail="Уже в списке")
    conn.close(); return {"success":True}

@app.delete("/api/spawn-whitelist/{iid}")
async def delete_spawn_item(iid:int, req:Request):
    u = get_current_user(req)
    if not u or u["role"] not in ("head_admin","admin"): raise HTTPException(403)
    conn = get_db(); conn.execute("DELETE FROM spawn_whitelist WHERE id=?", (iid,)); conn.commit(); conn.close(); return {"success":True}

@app.get("/api/events/{eid}/spawn-reports")
async def get_spawn_reports(eid:int):
    conn = get_db(); rows = conn.execute("SELECT * FROM spawn_reports WHERE event_id=? ORDER BY created_at DESC", (eid,)).fetchall(); conn.close()
    return [dict(r) for r in rows]

@app.post("/api/events/{eid}/spawn-reports")
async def add_spawn_report(eid:int, req:Request, item_name:str=Form(...), quantity:int=Form(1), note:str=Form("")):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    conn = get_db(); ev = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not ev: conn.close(); raise HTTPException(404)
    p = get_perms(u)
    if ev["author_id"] != u["id"] and not p["can_edit_all"]: conn.close(); raise HTTPException(403)
    conn.execute("INSERT INTO spawn_reports (event_id,user_id,user_name,item_name,quantity,note) VALUES (?,?,?,?,?,?)",
        (eid,u["id"],u["display_name"],item_name.strip(),quantity,note.strip())); conn.commit(); conn.close(); return {"success":True}

@app.delete("/api/spawn-reports/{rid}")
async def delete_spawn_report(rid:int, req:Request):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    conn = get_db(); rpt = conn.execute("SELECT * FROM spawn_reports WHERE id=?", (rid,)).fetchone()
    if not rpt: conn.close(); raise HTTPException(404)
    if rpt["user_id"] != u["id"] and not get_perms(u)["can_edit_all"]: conn.close(); raise HTTPException(403)
    conn.execute("DELETE FROM spawn_reports WHERE id=?", (rid,)); conn.commit(); conn.close(); return {"success":True}

# ═══ USERS ═══
@app.get("/api/users")
async def list_users(req:Request):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_users"]: raise HTTPException(403)
    conn = get_db(); rows = conn.execute("SELECT id,username,display_name,role,can_approve,can_edit_all,can_manage_users,created_at FROM users ORDER BY id").fetchall(); conn.close()
    return [dict(r) for r in rows]

@app.post("/api/users")
async def create_user(req:Request, username:str=Form(...), password:str=Form(...), display_name:str=Form(...), role:str=Form(...)):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_users"]: raise HTTPException(403)
    conn = get_db()
    if not conn.execute("SELECT 1 FROM roles WHERE role_key=?", (role,)).fetchone(): conn.close(); raise HTTPException(400, detail="Роль не существует")
    try: conn.execute("INSERT INTO users (username,password_hash,display_name,role) VALUES (?,?,?,?)", (username,h_pw(password),display_name,role)); conn.commit()
    except sqlite3.IntegrityError: conn.close(); raise HTTPException(400, detail="Логин занят")
    conn.close(); return {"success":True}

@app.put("/api/users/{uid}/role")
async def update_user_role(uid:int, req:Request, role:str=Form(...)):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_users"]: raise HTTPException(403)
    if u["id"] == uid: raise HTTPException(400, detail="Нельзя менять свою роль")
    conn = get_db()
    if not conn.execute("SELECT 1 FROM roles WHERE role_key=?", (role,)).fetchone(): conn.close(); raise HTTPException(400)
    old_role = conn.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()
    conn.execute("UPDATE users SET role=? WHERE id=?", (role,uid)); conn.commit(); conn.close()
    rd = get_role_data(role)
    notify(uid,"role_change",f'🎭 Ваша роль изменена на «{rd["display_name"] if rd else role}» ({u["display_name"]})')
    return {"success":True}

@app.put("/api/users/{uid}/perms")
async def update_user_perms(uid:int, req:Request, can_approve:str=Form("null"), can_edit_all:str=Form("null"), can_manage_users:str=Form("null")):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_users"]: raise HTTPException(403)
    if u["id"] == uid: raise HTTPException(400)
    def parse(v): return None if v == "null" else (1 if v == "1" else 0)
    conn = get_db(); conn.execute("UPDATE users SET can_approve=?,can_edit_all=?,can_manage_users=? WHERE id=?", (parse(can_approve),parse(can_edit_all),parse(can_manage_users),uid)); conn.commit(); conn.close()
    return {"success":True}

@app.put("/api/users/{uid}/password")
async def update_user_password(uid:int, req:Request, password:str=Form(...)):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    if not get_perms(u)["can_manage_users"] and u["id"] != uid: raise HTTPException(403)
    conn = get_db(); conn.execute("UPDATE users SET password_hash=? WHERE id=?", (h_pw(password),uid)); conn.commit(); conn.close()
    return {"success":True}

@app.delete("/api/users/{uid}")
async def delete_user(uid:int, req:Request):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_users"]: raise HTTPException(403)
    if u["id"] == uid: raise HTTPException(400)
    conn = get_db(); conn.execute("DELETE FROM users WHERE id=?", (uid,)); conn.commit(); conn.close()
    reorder_ids("users"); return {"success":True}

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def index():
    with open("static/index.html","r",encoding="utf-8") as f: return HTMLResponse(content=f.read())
