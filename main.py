import os, hashlib
from fastapi import FastAPI, HTTPException, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timedelta
import jwt

app = FastAPI(title="Stalker RP Event Hub")
SECRET_KEY = os.environ.get("SECRET_KEY", "stalker_zone_secret_key_change_me_in_prod")
ALGORITHM = "HS256"
DATABASE_URL = os.environ.get("DATABASE_URL")

# ═══ DATABASE ABSTRACTION ═══
if DATABASE_URL:
    import psycopg2, psycopg2.extras
    USE_PG = True
else:
    import sqlite3
    USE_PG = False

def get_db():
    if USE_PG:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    else:
        conn = sqlite3.connect("events.db")
        conn.row_factory = sqlite3.Row
        return conn

def q(sql):
    if USE_PG: return sql.replace('?','%s')
    return sql

def db_fetchone(conn, sql, params=()):
    if USE_PG:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        cur = conn.cursor()
    cur.execute(q(sql), params)
    row = cur.fetchone()
    cur.close()
    return dict(row) if row else None

def db_fetchall(conn, sql, params=()):
    if USE_PG:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        cur = conn.cursor()
    cur.execute(q(sql), params)
    rows = cur.fetchall()
    cur.close()
    return [dict(r) for r in rows]

def db_execute(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(q(sql), params)
    return cur

def db_scalar(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(q(sql), params)
    val = cur.fetchone()[0]
    cur.close()
    return val

def h_pw(p): return hashlib.sha256(p.encode('utf-8')).hexdigest()
def v_pw(p, h): return h_pw(p) == h

STATUSES = [
    {"key":"draft","label":"Черновик","icon":"📝","color":"#6b7280"},
    {"key":"pending","label":"На проверке","icon":"⏳","color":"#eab308"},
    {"key":"rejected","label":"Отклонён","icon":"❌","color":"#ef4444"},
    {"key":"approved","label":"Одобрен","icon":"✅","color":"#22c55e"},
    {"key":"scheduled","label":"Запланирован","icon":"📅","color":"#3b82f6"},
    {"key":"active","label":"Проводится","icon":"🔥","color":"#f97316"},
    {"key":"completed","label":"Завершён","icon":"🏁","color":"#8b5cf6"},
    {"key":"archived","label":"Архив","icon":"📦","color":"#6b7280"},
]
STATUS_MAP = {s["key"]:s for s in STATUSES}

MUTANT_ITEMS = [
    "NH_leTushkano_Head","Mutant_XZ_Boar_leg","NH_DogTail","NH_CatTail","NH_PseudoDog_tail",
    "Mutant_XZ_Fresh_Eye","NH_PsiDog_tail","Mutant_AoD_Zombi_Hand","Mutant_XZ_Izlom_Hand",
    "NH_krovosos_jaw","NH_SnorkFoot","NH_BurerHand","NH_Controller_Brain","Mutant_AoD_Himera_Kogot",
    "Mutant_AoD_Forester_Kogot","NH_GiantEye","Mutant_AoD_Tark_Horn","Mutant_XZ_Zombi_Hand",
    "tomato","KARP_Pdog_leg","KARP_Boar_Leg","KARP_Tushkano_Head","KARP_controller_brain",
    "KARP_Plot_eye","KARP_Izlom_Hand","KARP_blinddog2_head","KARP_Blinddog1_Tail",
    "KARP_polter_eye","KARP_Burer_hand","KARP_Cat_head","KARP_chimera_claw",
]

def init_db():
    conn = get_db()
    if USE_PG:
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS roles (
            id SERIAL PRIMARY KEY, role_key TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
            color TEXT DEFAULT '#4ade80', priority INTEGER DEFAULT 10,
            can_approve INTEGER DEFAULT 0, can_edit_all INTEGER DEFAULT 0,
            can_manage_users INTEGER DEFAULT 0, can_manage_roles INTEGER DEFAULT 0, is_system INTEGER DEFAULT 0)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'junior_eventologist',
            can_approve INTEGER DEFAULT NULL, can_edit_all INTEGER DEFAULT NULL, can_manage_users INTEGER DEFAULT NULL,
            created_at TIMESTAMP DEFAULT NOW())''')
        cur.execute('''CREATE TABLE IF NOT EXISTS events (
            id SERIAL PRIMARY KEY, title TEXT NOT NULL, event_type TEXT NOT NULL,
            duration TEXT NOT NULL, location TEXT NOT NULL, organizer_name TEXT NOT NULL,
            author_id INTEGER NOT NULL, short_desc TEXT NOT NULL, full_desc TEXT NOT NULL,
            rules_text TEXT, rewards_text TEXT, status TEXT DEFAULT 'pending',
            reviewed_by TEXT DEFAULT NULL, event_date TEXT DEFAULT NULL, event_time TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT NOW())''')
        cur.execute('''CREATE TABLE IF NOT EXISTS spawn_whitelist (
            id SERIAL PRIMARY KEY, item_name TEXT UNIQUE NOT NULL, category TEXT DEFAULT '',
            added_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT NOW())''')
        cur.execute('''CREATE TABLE IF NOT EXISTS spawn_reports (
            id SERIAL PRIMARY KEY, event_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            user_name TEXT NOT NULL, item_name TEXT NOT NULL, quantity INTEGER NOT NULL DEFAULT 1,
            note TEXT DEFAULT '', created_at TIMESTAMP DEFAULT NOW())''')
        cur.execute('''CREATE TABLE IF NOT EXISTS comments (
            id SERIAL PRIMARY KEY, event_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            user_name TEXT NOT NULL, user_role TEXT NOT NULL, text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT NOW())''')
        cur.execute('''CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, type TEXT NOT NULL,
            message TEXT NOT NULL, event_id INTEGER DEFAULT NULL, is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT NOW())''')
        cur.close()
    else:
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT, role_key TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
            color TEXT DEFAULT '#4ade80', priority INTEGER DEFAULT 10,
            can_approve INTEGER DEFAULT 0, can_edit_all INTEGER DEFAULT 0,
            can_manage_users INTEGER DEFAULT 0, can_manage_roles INTEGER DEFAULT 0, is_system INTEGER DEFAULT 0)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'junior_eventologist',
            can_approve INTEGER DEFAULT NULL, can_edit_all INTEGER DEFAULT NULL, can_manage_users INTEGER DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, event_type TEXT NOT NULL,
            duration TEXT NOT NULL, location TEXT NOT NULL, organizer_name TEXT NOT NULL,
            author_id INTEGER NOT NULL, short_desc TEXT NOT NULL, full_desc TEXT NOT NULL,
            rules_text TEXT, rewards_text TEXT, status TEXT DEFAULT 'pending',
            reviewed_by TEXT DEFAULT NULL, event_date TEXT DEFAULT NULL, event_time TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS spawn_whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT, item_name TEXT UNIQUE NOT NULL, category TEXT DEFAULT '',
            added_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS spawn_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            user_name TEXT NOT NULL, item_name TEXT NOT NULL, quantity INTEGER NOT NULL DEFAULT 1,
            note TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            user_name TEXT NOT NULL, user_role TEXT NOT NULL, text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL,
            message TEXT NOT NULL, event_id INTEGER DEFAULT NULL, is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        # SQLite migrations
        for col in ("can_approve","can_edit_all","can_manage_users"):
            try: cur.execute(f"ALTER TABLE users ADD COLUMN {col} INTEGER DEFAULT NULL")
            except: pass
        for col in ("can_manage_roles","is_system"):
            try: cur.execute(f"ALTER TABLE roles ADD COLUMN {col} INTEGER DEFAULT 0")
            except: pass
        for col in ("event_date","event_time"):
            try: cur.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT DEFAULT NULL")
            except: pass
    # Seed roles
    cnt = db_scalar(conn, "SELECT COUNT(*) FROM roles")
    if cnt == 0:
        for r in [("head_admin","Head Admin","#ff6b6b",100,1,1,1,1,1),
                   ("admin","Главный Ивентолог","#f59e0b",80,1,1,1,1,1),
                   ("senior_eventologist","Ст. Ивентолог","#a78bfa",60,1,1,0,0,1),
                   ("eventologist","Ивентолог","#4ade80",40,0,0,0,0,1),
                   ("junior_eventologist","Мл. Ивентолог","#5a856a",20,0,0,0,0,1)]:
            db_execute(conn,"INSERT INTO roles (role_key,display_name,color,priority,can_approve,can_edit_all,can_manage_users,can_manage_roles,is_system) VALUES (?,?,?,?,?,?,?,?,?)",r)
    # Seed users
    cnt = db_scalar(conn, "SELECT COUNT(*) FROM users")
    if cnt == 0:
        for u in [("headadmin",h_pw("headadmin123"),"Head Admin","head_admin"),
                   ("admin",h_pw("admin123"),"Главный Ивентолог Пушкин","admin")]:
            db_execute(conn,"INSERT INTO users (username,password_hash,display_name,role) VALUES (?,?,?,?)",u)
    # Seed mutants in spawn whitelist
    cnt = db_scalar(conn, "SELECT COUNT(*) FROM spawn_whitelist")
    if cnt == 0:
        for item in MUTANT_ITEMS:
            try: db_execute(conn,"INSERT INTO spawn_whitelist (item_name,category,added_by) VALUES (?,?,?)",(item,"Мутанты","System"))
            except: pass
    conn.commit()
    conn.close()

init_db()

# ═══ HELPERS ═══
def get_role_data(rk):
    conn = get_db(); r = db_fetchone(conn,"SELECT * FROM roles WHERE role_key=?",(rk,)); conn.close()
    return r

def get_perms(user):
    rd = get_role_data(user["role"]) or {}
    p = {}
    for k in ("can_approve","can_edit_all","can_manage_users"):
        v = user[k]; p[k] = bool(v) if v is not None else bool(rd.get(k,0))
    p["can_manage_roles"] = bool(rd.get("can_manage_roles",0))
    return p

def get_current_user(req):
    token = req.cookies.get("access_token")
    if not token: return None
    try:
        un = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]).get("sub")
        if not un: return None
    except: return None
    conn = get_db(); u = db_fetchone(conn,"SELECT * FROM users WHERE username=?",(un,)); conn.close()
    return u

def notify(user_id, ntype, message, event_id=None):
    conn = get_db()
    db_execute(conn,"INSERT INTO notifications (user_id,type,message,event_id) VALUES (?,?,?,?)",(user_id,ntype,message,event_id))
    conn.commit(); conn.close()

# ═══ AUTH ═══
@app.post("/api/login")
async def login(username:str=Form(...), password:str=Form(...)):
    conn = get_db(); u = db_fetchone(conn,"SELECT * FROM users WHERE username=?",(username,)); conn.close()
    if not u or not v_pw(password, u["password_hash"]): return JSONResponse({"error":"Неверный логин или пароль"},status_code=400)
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
    return {"authenticated":True,"id":u["id"],"username":u["username"],"display_name":u["display_name"],
            "role":u["role"],"role_display":rd["display_name"] if rd else u["role"],"role_color":rd["color"] if rd else "#4ade80",**p}

@app.get("/api/statuses")
async def get_statuses(): return STATUSES

# ═══ STATS ═══
@app.get("/api/stats")
async def get_stats():
    conn = get_db()
    total = db_scalar(conn,"SELECT COUNT(*) FROM events")
    by_status = []
    for s in STATUSES:
        cnt = db_scalar(conn,"SELECT COUNT(*) FROM events WHERE status=?",(s["key"],))
        by_status.append({"key":s["key"],"label":s["label"],"icon":s["icon"],"color":s["color"],"count":cnt})
    top_authors = db_fetchall(conn,"SELECT users.display_name as name, COUNT(*) as count FROM events JOIN users ON events.author_id=users.id GROUP BY events.author_id, users.display_name ORDER BY count DESC LIMIT 5")
    top_spawn = db_fetchall(conn,"SELECT item_name as item, COALESCE(SUM(quantity),0) as total FROM spawn_reports GROUP BY item_name ORDER BY total DESC LIMIT 5")
    total_users = db_scalar(conn,"SELECT COUNT(*) FROM users")
    total_comments = db_scalar(conn,"SELECT COUNT(*) FROM comments")
    total_spawned = db_scalar(conn,"SELECT COALESCE(SUM(quantity),0) FROM spawn_reports")
    # Per-user stats
    user_stats = db_fetchall(conn,"""
        SELECT u.id, u.display_name as name, u.role,
            (SELECT COUNT(*) FROM events WHERE author_id=u.id) as events_count,
            (SELECT COUNT(*) FROM events WHERE author_id=u.id AND status='approved') as approved_count,
            (SELECT COUNT(*) FROM events WHERE author_id=u.id AND status='rejected') as rejected_count,
            (SELECT COUNT(*) FROM comments WHERE user_id=u.id) as comments_count,
            (SELECT COALESCE(SUM(quantity),0) FROM spawn_reports WHERE user_id=u.id) as spawn_count
        FROM users u ORDER BY events_count DESC
    """)
    conn.close()
    return {"total_events":total,"by_status":by_status,"total_users":total_users,"total_comments":total_comments,
            "total_spawned":total_spawned,"top_authors":top_authors,"top_spawn":top_spawn,"user_stats":user_stats}

# ═══ ROLES ═══
@app.get("/api/roles")
async def list_roles():
    conn = get_db(); rows = db_fetchall(conn,"SELECT * FROM roles ORDER BY priority DESC"); conn.close()
    return rows

@app.post("/api/roles")
async def create_role(req:Request, role_key:str=Form(...), display_name:str=Form(...), color:str=Form("#4ade80"),
                      priority:int=Form(10), can_approve:int=Form(0), can_edit_all:int=Form(0),
                      can_manage_users:int=Form(0), can_manage_roles:int=Form(0)):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_roles"]: raise HTTPException(403)
    conn = get_db()
    try:
        db_execute(conn,"INSERT INTO roles (role_key,display_name,color,priority,can_approve,can_edit_all,can_manage_users,can_manage_roles,is_system) VALUES (?,?,?,?,?,?,?,?,0)",
            (role_key.strip().lower().replace(" ","_"),display_name.strip(),color.strip(),priority,can_approve,can_edit_all,can_manage_users,can_manage_roles))
        conn.commit()
    except: conn.close(); raise HTTPException(400, detail="Ключ уже занят")
    conn.close(); return {"success":True}

@app.put("/api/roles/{rid}")
async def update_role(rid:int, req:Request, display_name:str=Form(...), color:str=Form("#4ade80"),
                      priority:int=Form(10), can_approve:int=Form(0), can_edit_all:int=Form(0),
                      can_manage_users:int=Form(0), can_manage_roles:int=Form(0)):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_roles"]: raise HTTPException(403)
    conn = get_db()
    db_execute(conn,"UPDATE roles SET display_name=?,color=?,priority=?,can_approve=?,can_edit_all=?,can_manage_users=?,can_manage_roles=? WHERE id=?",
        (display_name.strip(),color.strip(),priority,can_approve,can_edit_all,can_manage_users,can_manage_roles,rid))
    conn.commit(); conn.close(); return {"success":True}

@app.delete("/api/roles/{rid}")
async def delete_role(rid:int, req:Request):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_roles"]: raise HTTPException(403)
    conn = get_db(); role = db_fetchone(conn,"SELECT * FROM roles WHERE id=?",(rid,))
    if not role: conn.close(); raise HTTPException(404)
    if role["is_system"]: conn.close(); raise HTTPException(400, detail="Системную роль нельзя удалить")
    cnt = db_scalar(conn,"SELECT COUNT(*) FROM users WHERE role=?",(role["role_key"],))
    if cnt > 0: conn.close(); raise HTTPException(400, detail="Роль используется ("+str(cnt)+" чел.)")
    db_execute(conn,"DELETE FROM roles WHERE id=?",(rid,)); conn.commit(); conn.close(); return {"success":True}

# ═══ EVENTS ═══
@app.get("/api/events")
async def list_events():
    conn = get_db()
    rows = db_fetchall(conn,"SELECT events.*, users.display_name as author_name FROM events JOIN users ON events.author_id=users.id ORDER BY events.id DESC")
    conn.close(); return rows

@app.get("/api/events/my")
async def my_events(req:Request):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    conn = get_db()
    rows = db_fetchall(conn,"SELECT events.*, users.display_name as author_name FROM events JOIN users ON events.author_id=users.id WHERE events.author_id=? ORDER BY events.id DESC",(u["id"],))
    conn.close(); return rows

@app.get("/api/events/calendar")
async def calendar_events():
    conn = get_db()
    rows = db_fetchall(conn,"SELECT id,title,event_type,event_date,event_time,status,location FROM events WHERE event_date IS NOT NULL AND event_date != '' ORDER BY event_date ASC")
    conn.close(); return rows

@app.get("/api/events/{eid}")
async def get_event(eid:int):
    conn = get_db()
    row = db_fetchone(conn,"SELECT events.*, users.display_name as author_name FROM events JOIN users ON events.author_id=users.id WHERE events.id=?",(eid,))
    conn.close()
    if not row: raise HTTPException(404)
    return row

@app.post("/api/events")
async def create_event(req:Request, title:str=Form(...), event_type:str=Form(...), duration:str=Form(...), location:str=Form(...), organizer_name:str=Form(...), short_desc:str=Form(...), full_desc:str=Form(...), rules_text:str=Form(""), rewards_text:str=Form(""), event_date:str=Form(""), event_time:str=Form("")):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    conn = get_db()
    if USE_PG:
        cur = db_execute(conn,"INSERT INTO events (title,event_type,duration,location,organizer_name,author_id,short_desc,full_desc,rules_text,rewards_text,event_date,event_time) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id",
            (title,event_type,duration,location,organizer_name,u["id"],short_desc,full_desc,rules_text,rewards_text,event_date or None,event_time or None))
        eid = cur.fetchone()[0]
    else:
        cur = db_execute(conn,"INSERT INTO events (title,event_type,duration,location,organizer_name,author_id,short_desc,full_desc,rules_text,rewards_text,event_date,event_time) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (title,event_type,duration,location,organizer_name,u["id"],short_desc,full_desc,rules_text,rewards_text,event_date or None,event_time or None))
        eid = cur.lastrowid
    conn.commit(); conn.close(); return {"success":True,"event_id":eid}

@app.put("/api/events/{eid}")
async def update_event(eid:int, req:Request, title:str=Form(...), event_type:str=Form(...), duration:str=Form(...), location:str=Form(...), organizer_name:str=Form(...), short_desc:str=Form(...), full_desc:str=Form(...), rules_text:str=Form(""), rewards_text:str=Form(""), event_date:str=Form(""), event_time:str=Form("")):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    p = get_perms(u); conn = get_db()
    ev = db_fetchone(conn,"SELECT * FROM events WHERE id=?",(eid,))
    if not ev: conn.close(); raise HTTPException(404)
    isTop = u["role"] in ("head_admin","admin")
    locked = ev["status"] in ("approved","scheduled","active","completed")
    if locked and not isTop: conn.close(); raise HTTPException(403, detail="Ивент заблокирован для редактирования")
    if not p["can_edit_all"] and ev["author_id"] != u["id"]: conn.close(); raise HTTPException(403)
    ns = ev["status"] if isTop else "pending"
    nr = ev["reviewed_by"] if isTop else None
    db_execute(conn,"UPDATE events SET title=?,event_type=?,duration=?,location=?,organizer_name=?,short_desc=?,full_desc=?,rules_text=?,rewards_text=?,status=?,reviewed_by=?,event_date=?,event_time=? WHERE id=?",
        (title,event_type,duration,location,organizer_name,short_desc,full_desc,rules_text,rewards_text,ns,nr,event_date or None,event_time or None,eid))
    conn.commit(); conn.close(); return {"success":True}

@app.put("/api/events/{eid}/status")
async def change_status(eid:int, req:Request, status:str=Form(...)):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    if status not in STATUS_MAP: raise HTTPException(400, detail="Неизвестный статус")
    p = get_perms(u); conn = get_db()
    ev = db_fetchone(conn,"SELECT * FROM events WHERE id=?",(eid,))
    if not ev: conn.close(); raise HTTPException(404)
    need_perm = status in ("approved","scheduled","active","completed","archived","rejected")
    if need_perm and not p["can_approve"] and u["role"] not in ("head_admin","admin"):
        conn.close(); raise HTTPException(403, detail="Нет прав")
    rb = u["display_name"] if need_perm else ev["reviewed_by"]
    db_execute(conn,"UPDATE events SET status=?, reviewed_by=? WHERE id=?",(status, rb, eid))
    conn.commit(); conn.close()
    if ev["author_id"] != u["id"]:
        sl = STATUS_MAP.get(status,{})
        notify(ev["author_id"],"status_change",sl.get("icon","")+" Ивент «"+ev["title"]+"» — "+sl.get("label",status)+" ("+u["display_name"]+")",eid)
    return {"success":True}

@app.delete("/api/events/{eid}")
async def delete_event(eid:int, req:Request):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    p = get_perms(u); conn = get_db()
    ev = db_fetchone(conn,"SELECT * FROM events WHERE id=?",(eid,))
    if not ev: conn.close(); raise HTTPException(404)
    if not p["can_edit_all"] and ev["author_id"] != u["id"]: conn.close(); raise HTTPException(403)
    for t in ("spawn_reports","comments","notifications"):
        db_execute(conn,"DELETE FROM "+t+" WHERE event_id=?",(eid,))
    db_execute(conn,"DELETE FROM events WHERE id=?",(eid,)); conn.commit(); conn.close()
    return {"success":True}

@app.post("/api/events/{eid}/approve")
async def approve_event(eid:int, req:Request):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_approve"]: raise HTTPException(403)
    conn = get_db(); ev = db_fetchone(conn,"SELECT * FROM events WHERE id=?",(eid,))
    if not ev: conn.close(); raise HTTPException(404)
    db_execute(conn,"UPDATE events SET status='approved',reviewed_by=? WHERE id=?",(u["display_name"],eid)); conn.commit(); conn.close()
    if ev["author_id"] != u["id"]: notify(ev["author_id"],"approved","✅ Ивент «"+ev["title"]+"» одобрен ("+u["display_name"]+")",eid)
    return {"success":True}

@app.post("/api/events/{eid}/reject")
async def reject_event(eid:int, req:Request):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_approve"]: raise HTTPException(403)
    conn = get_db(); ev = db_fetchone(conn,"SELECT * FROM events WHERE id=?",(eid,))
    if not ev: conn.close(); raise HTTPException(404)
    db_execute(conn,"UPDATE events SET status='rejected',reviewed_by=? WHERE id=?",(u["display_name"],eid)); conn.commit(); conn.close()
    if ev["author_id"] != u["id"]: notify(ev["author_id"],"rejected","❌ Ивент «"+ev["title"]+"» отклонён ("+u["display_name"]+")",eid)
    return {"success":True}

# ═══ COMMENTS ═══
@app.get("/api/events/{eid}/comments")
async def get_comments(eid:int):
    conn = get_db(); rows = db_fetchall(conn,"SELECT * FROM comments WHERE event_id=? ORDER BY created_at ASC",(eid,)); conn.close()
    return rows

@app.post("/api/events/{eid}/comments")
async def add_comment(eid:int, req:Request, text:str=Form(...)):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    rd = get_role_data(u["role"])
    conn = get_db(); ev = db_fetchone(conn,"SELECT * FROM events WHERE id=?",(eid,))
    if not ev: conn.close(); raise HTTPException(404)
    db_execute(conn,"INSERT INTO comments (event_id,user_id,user_name,user_role,text) VALUES (?,?,?,?,?)",
        (eid,u["id"],u["display_name"],rd["display_name"] if rd else u["role"],text.strip()))
    conn.commit(); conn.close()
    if ev["author_id"] != u["id"]: notify(ev["author_id"],"comment","💬 "+u["display_name"]+" прокомментировал «"+ev["title"]+"»",eid)
    return {"success":True}

@app.delete("/api/comments/{cid}")
async def delete_comment(cid:int, req:Request):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    conn = get_db(); c = db_fetchone(conn,"SELECT * FROM comments WHERE id=?",(cid,))
    if not c: conn.close(); raise HTTPException(404)
    if c["user_id"] != u["id"] and not get_perms(u)["can_edit_all"]: conn.close(); raise HTTPException(403)
    db_execute(conn,"DELETE FROM comments WHERE id=?",(cid,)); conn.commit(); conn.close(); return {"success":True}

# ═══ NOTIFICATIONS ═══
@app.get("/api/notifications")
async def get_notifications(req:Request):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    conn = get_db()
    rows = db_fetchall(conn,"SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50",(u["id"],))
    unread = db_scalar(conn,"SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0",(u["id"],))
    conn.close(); return {"notifications":rows,"unread":unread}

@app.post("/api/notifications/read-all")
async def read_all(req:Request):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    conn = get_db(); db_execute(conn,"UPDATE notifications SET is_read=1 WHERE user_id=?",(u["id"],)); conn.commit(); conn.close()
    return {"success":True}

@app.get("/api/notifications/count")
async def notif_count(req:Request):
    u = get_current_user(req)
    if not u: return {"count":0}
    conn = get_db(); cnt = db_scalar(conn,"SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0",(u["id"],)); conn.close()
    return {"count":cnt}

# ═══ SPAWN ═══
@app.get("/api/spawn-whitelist")
async def get_spawn_whitelist():
    conn = get_db(); rows = db_fetchall(conn,"SELECT * FROM spawn_whitelist ORDER BY category, item_name"); conn.close()
    return rows

@app.post("/api/spawn-whitelist")
async def add_spawn_item(req:Request, item_name:str=Form(...), category:str=Form("")):
    u = get_current_user(req)
    if not u or u["role"] not in ("head_admin","admin"): raise HTTPException(403)
    conn = get_db()
    try: db_execute(conn,"INSERT INTO spawn_whitelist (item_name,category,added_by) VALUES (?,?,?)",(item_name.strip(),category.strip(),u["display_name"])); conn.commit()
    except: conn.close(); raise HTTPException(400, detail="Уже в списке")
    conn.close(); return {"success":True}

@app.delete("/api/spawn-whitelist/{iid}")
async def delete_spawn_item(iid:int, req:Request):
    u = get_current_user(req)
    if not u or u["role"] not in ("head_admin","admin"): raise HTTPException(403)
    conn = get_db(); db_execute(conn,"DELETE FROM spawn_whitelist WHERE id=?",(iid,)); conn.commit(); conn.close(); return {"success":True}

@app.get("/api/events/{eid}/spawn-reports")
async def get_spawn_reports(eid:int):
    conn = get_db(); rows = db_fetchall(conn,"SELECT * FROM spawn_reports WHERE event_id=? ORDER BY created_at DESC",(eid,)); conn.close()
    return rows

@app.post("/api/events/{eid}/spawn-reports")
async def add_spawn_report(eid:int, req:Request, item_name:str=Form(...), quantity:int=Form(1), note:str=Form("")):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    conn = get_db(); ev = db_fetchone(conn,"SELECT * FROM events WHERE id=?",(eid,))
    if not ev: conn.close(); raise HTTPException(404)
    p = get_perms(u)
    if ev["author_id"] != u["id"] and not p["can_edit_all"]: conn.close(); raise HTTPException(403)
    db_execute(conn,"INSERT INTO spawn_reports (event_id,user_id,user_name,item_name,quantity,note) VALUES (?,?,?,?,?,?)",
        (eid,u["id"],u["display_name"],item_name.strip(),quantity,note.strip())); conn.commit(); conn.close(); return {"success":True}

@app.delete("/api/spawn-reports/{rid}")
async def delete_spawn_report(rid:int, req:Request):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    conn = get_db(); rpt = db_fetchone(conn,"SELECT * FROM spawn_reports WHERE id=?",(rid,))
    if not rpt: conn.close(); raise HTTPException(404)
    if rpt["user_id"] != u["id"] and not get_perms(u)["can_edit_all"]: conn.close(); raise HTTPException(403)
    db_execute(conn,"DELETE FROM spawn_reports WHERE id=?",(rid,)); conn.commit(); conn.close(); return {"success":True}

# ═══ USERS ═══
@app.get("/api/users")
async def list_users(req:Request):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_users"]: raise HTTPException(403)
    conn = get_db(); rows = db_fetchall(conn,"SELECT id,username,display_name,role,can_approve,can_edit_all,can_manage_users,created_at FROM users ORDER BY id"); conn.close()
    return rows

@app.post("/api/users")
async def create_user(req:Request, username:str=Form(...), password:str=Form(...), display_name:str=Form(...), role:str=Form(...)):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_users"]: raise HTTPException(403)
    conn = get_db()
    try: db_execute(conn,"INSERT INTO users (username,password_hash,display_name,role) VALUES (?,?,?,?)",(username,h_pw(password),display_name,role)); conn.commit()
    except: conn.close(); raise HTTPException(400, detail="Логин занят")
    conn.close(); return {"success":True}

@app.put("/api/users/{uid}/role")
async def update_user_role(uid:int, req:Request, role:str=Form(...)):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_users"]: raise HTTPException(403)
    if u["id"] == uid: raise HTTPException(400, detail="Нельзя менять свою роль")
    conn = get_db(); db_execute(conn,"UPDATE users SET role=? WHERE id=?",(role,uid)); conn.commit(); conn.close()
    rd = get_role_data(role)
    notify(uid,"role_change","🎭 Роль изменена на «"+(rd["display_name"] if rd else role)+"» ("+u["display_name"]+")")
    return {"success":True}

@app.put("/api/users/{uid}/perms")
async def update_user_perms(uid:int, req:Request, can_approve:str=Form("null"), can_edit_all:str=Form("null"), can_manage_users:str=Form("null")):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_users"]: raise HTTPException(403)
    if u["id"] == uid: raise HTTPException(400)
    def parse(v): return None if v == "null" else (1 if v == "1" else 0)
    conn = get_db(); db_execute(conn,"UPDATE users SET can_approve=?,can_edit_all=?,can_manage_users=? WHERE id=?",(parse(can_approve),parse(can_edit_all),parse(can_manage_users),uid)); conn.commit(); conn.close()
    return {"success":True}

@app.put("/api/users/{uid}/password")
async def update_user_password(uid:int, req:Request, password:str=Form(...)):
    u = get_current_user(req)
    if not u: raise HTTPException(401)
    if not get_perms(u)["can_manage_users"] and u["id"] != uid: raise HTTPException(403)
    conn = get_db(); db_execute(conn,"UPDATE users SET password_hash=? WHERE id=?",(h_pw(password),uid)); conn.commit(); conn.close()
    return {"success":True}

@app.delete("/api/users/{uid}")
async def delete_user(uid:int, req:Request):
    u = get_current_user(req)
    if not u or not get_perms(u)["can_manage_users"]: raise HTTPException(403)
    if u["id"] == uid: raise HTTPException(400)
    conn = get_db(); db_execute(conn,"DELETE FROM users WHERE id=?",(uid,)); conn.commit(); conn.close()
    return {"success":True}

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def index():
    with open("static/index.html","r",encoding="utf-8") as f: return HTMLResponse(content=f.read())
