import os
import sqlite3
import hashlib
from fastapi import FastAPI, HTTPException, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timedelta
import jwt

app = FastAPI(title="Stalker RP Event Hub")
DB_PATH = "events.db"
SECRET_KEY = os.environ.get("SECRET_KEY", "stalker_zone_secret_key_change_me_in_prod")
ALGORITHM = "HS256"

# Roles hierarchy: admin > senior_eventologist > eventologist > junior_eventologist
ROLES_CAN_APPROVE = ("admin", "senior_eventologist")
ROLES_ALL = ("admin", "senior_eventologist", "eventologist", "junior_eventologist")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'junior_eventologist',
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
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        users = [
            ("admin",     hash_password("admin123"),   "Главный Ивентолог Пушкин", "admin"),
            ("senior",    hash_password("senior123"),  "Ст.Ивентолог",             "senior_eventologist"),
            ("eventolog", hash_password("event123"),   "Ивентолог",                "eventologist"),
            ("junior",    hash_password("junior123"),  "Мл.Ивентолог",             "junior_eventologist"),
        ]
        c.executemany("INSERT INTO users (username, password_hash, display_name, role) VALUES (?,?,?,?)", users)
        events = [
            ("Чёрная Посылка","Сюжетный / Поисковый","2–3 часа","Дикая территория, Тёмная Долина","Мл.Ивентолог Пушкин",1,
             "Торговец получил анонимные координаты тайника с документами, артефактом и наличными. Информация утекла — за тайником гонятся все.",
             "<p>Один из торговцев получил зашифрованные координаты тайника. Внутри — ящик с документами, артефактом и наличными.</p><h3>Ход:</h3><p><b>Фаза 1 (0:00–0:30):</b> Бармен объявляет по рации. Каждый получает часть подсказки.</p><p><b>Фаза 2 (0:30–1:30):</b> Гонка, переговоры, засады.</p><p><b>Фаза 3 (1:30–2:00):</b> Вскрытие тайника.</p><p><b>Финал (2:00–3:00):</b> Документы дают старт расследованию.</p>",
             "Гоп-стоп разрешён вне ЗЗ. Запрещено убивать курьеров мастера.","1 место: Артефакт + сюжет | Лучший одиночка: Денежная награда","approved","Главный Ивентолог Пушкин"),
            ("Выброс Не По Расписанию","Выживание / Кооперация","1.5–2 часа","Вся карта","Мл.Ивентолог Пушкин",1,
             "Внеплановый выброс через 40 минут — укрытий на всех не хватает. После выброса — новые аномалии с артефактами.",
             "<p>Аппаратура на Янове зафиксировала аномальную активность. Выброс произойдёт раньше.</p><p><b>До выброса (0:00–0:40):</b> Игроки ищут укрытия, торгуют местами.</p><p><b>Выброс (0:40–0:50):</b> Все вне укрытий — тяжёлое ранение.</p><p><b>После (0:50–2:00):</b> Охота за артефактами.</p>",
             "Запрещено нападать во время выброса (NonRP).","Коллекционер артефактов: Приз | Гостеприимная фракция: RP-репутация","approved","Главный Ивентолог Пушкин"),
            ("Груз 200","Эскорт / Противостояние","2–2.5 часа","Янов → КПП периметра","Мл.Ивентолог Пушкин",1,
             "Военная колонна разбита. Выжившие тащат секретный ящик до периметра. Остальные пытаются перехватить.",
             "<p>Военные тащат секретный ящик до КПП.</p><p><b>Эскорт:</b> 3-5 бойцов + учёный с ящиком (не может бежать).</p><p><b>Перехватчики:</b> Все остальные. Цель — забрать ящик.</p>",
             "Запрещено убивать учёного без переговоров.","Доставка/перехват: содержимое ящика","pending",None),
            ("Чёрный Рынок","Аукцион / Торговый","1.5–2 часа","Бар «100 Рентген» (ЗЗ)","Мл.Ивентолог Пушкин",1,
             "Аукцион редких лотов в Баре: оружие, карты тайников, нейтралитет ГП и секретный тёмный лот.",
             "<p>Бармен устраивает ночной аукцион. Правила ЗЗ действуют.</p><p>Программа: аукцион лотов, свободный рынок, Тёмный Лот в конце.</p>",
             "Правила ЗЗ строго. RP-обман словом разрешён.","Победители торгов получают лоты","pending",None),
            ("Трибунал","Судебный / Политический","2–3 часа","Нейтральная территория","Мл.Ивентолог Пушкин",1,
             "Суд всех группировок над персонажем. Судебный процесс без единого выстрела.",
             "<p>Суд над обвиняемым. Представители ГП — судьи.</p><p><b>Этапы:</b> Обвинение → Слушания → Вопросы → Голосование.</p>",
             "Территория трибунала — нейтральная (де-факто ЗЗ).","Оправдание / Изгнание (РПК) / Штраф / Условный","rejected","Ст.Ивентолог"),
        ]
        c.executemany("INSERT INTO events (title,event_type,duration,location,organizer_name,author_id,short_desc,full_desc,rules_text,rewards_text,status,reviewed_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", events)
    conn.commit()
    conn.close()

init_db()

def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            return None
    except Exception:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user

# ── AUTH ──
@app.post("/api/login")
async def login(username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not user or not verify_password(password, user["password_hash"]):
        return JSONResponse({"error": "Неверный логин или пароль"}, status_code=400)
    token = jwt.encode({"sub": user["username"], "role": user["role"], "exp": datetime.utcnow() + timedelta(days=7)}, SECRET_KEY, algorithm=ALGORITHM)
    resp = JSONResponse({"success": True})
    resp.set_cookie(key="access_token", value=token, httponly=True, max_age=604800)
    return resp

@app.post("/api/logout")
async def logout():
    resp = JSONResponse({"success": True})
    resp.delete_cookie("access_token")
    return resp

@app.get("/api/me")
async def me(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"authenticated": False})
    return {"authenticated": True, "id": user["id"], "username": user["username"], "display_name": user["display_name"], "role": user["role"]}

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
    if not user:
        raise HTTPException(status_code=401)
    conn = get_db()
    rows = conn.execute("SELECT events.*, users.display_name as author_name FROM events JOIN users ON events.author_id=users.id WHERE events.author_id=? ORDER BY events.id DESC", (user["id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/events/{event_id}")
async def get_event(event_id: int):
    conn = get_db()
    row = conn.execute("SELECT events.*, users.display_name as author_name FROM events JOIN users ON events.author_id=users.id WHERE events.id=?", (event_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Ивент не найден")
    return dict(row)

@app.post("/api/events")
async def create_event(request: Request, title: str=Form(...), event_type: str=Form(...), duration: str=Form(...), location: str=Form(...), organizer_name: str=Form(...), short_desc: str=Form(...), full_desc: str=Form(...), rules_text: str=Form(""), rewards_text: str=Form("")):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)
    conn = get_db()
    c = conn.execute("INSERT INTO events (title,event_type,duration,location,organizer_name,author_id,short_desc,full_desc,rules_text,rewards_text,status) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (title,event_type,duration,location,organizer_name,user["id"],short_desc,full_desc,rules_text,rewards_text,"pending"))
    conn.commit()
    eid = c.lastrowid
    conn.close()
    return {"success": True, "event_id": eid}

@app.put("/api/events/{event_id}")
async def update_event(event_id: int, request: Request, title: str=Form(...), event_type: str=Form(...), duration: str=Form(...), location: str=Form(...), organizer_name: str=Form(...), short_desc: str=Form(...), full_desc: str=Form(...), rules_text: str=Form(""), rewards_text: str=Form("")):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)
    conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if not ev:
        conn.close(); raise HTTPException(status_code=404)
    if user["role"] not in ("admin","senior_eventologist") and ev["author_id"] != user["id"]:
        conn.close(); raise HTTPException(status_code=403, detail="Нет прав")
    conn.execute("UPDATE events SET title=?,event_type=?,duration=?,location=?,organizer_name=?,short_desc=?,full_desc=?,rules_text=?,rewards_text=?,status='pending',reviewed_by=NULL WHERE id=?",
        (title,event_type,duration,location,organizer_name,short_desc,full_desc,rules_text,rewards_text,event_id))
    conn.commit(); conn.close()
    return {"success": True}

@app.delete("/api/events/{event_id}")
async def delete_event(event_id: int, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)
    conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if not ev:
        conn.close(); raise HTTPException(status_code=404)
    if user["role"] not in ("admin","senior_eventologist") and ev["author_id"] != user["id"]:
        conn.close(); raise HTTPException(status_code=403)
    conn.execute("DELETE FROM events WHERE id=?", (event_id,))
    conn.commit(); conn.close()
    return {"success": True}

# ── APPROVE / REJECT ──
@app.post("/api/events/{event_id}/approve")
async def approve_event(event_id: int, request: Request):
    user = get_current_user(request)
    if not user or user["role"] not in ROLES_CAN_APPROVE:
        raise HTTPException(status_code=403, detail="Только Старший или Главный Ивентолог может одобрять")
    conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if not ev:
        conn.close(); raise HTTPException(status_code=404)
    conn.execute("UPDATE events SET status='approved', reviewed_by=? WHERE id=?", (user["display_name"], event_id))
    conn.commit(); conn.close()
    return {"success": True}

@app.post("/api/events/{event_id}/reject")
async def reject_event(event_id: int, request: Request):
    user = get_current_user(request)
    if not user or user["role"] not in ROLES_CAN_APPROVE:
        raise HTTPException(status_code=403, detail="Только Старший или Главный Ивентолог может отклонять")
    conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if not ev:
        conn.close(); raise HTTPException(status_code=404)
    conn.execute("UPDATE events SET status='rejected', reviewed_by=? WHERE id=?", (user["display_name"], event_id))
    conn.commit(); conn.close()
    return {"success": True}

# ── USERS (admin only) ──
@app.get("/api/users")
async def list_users(request: Request):
    user = get_current_user(request)
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403)
    conn = get_db()
    rows = conn.execute("SELECT id,username,display_name,role,created_at FROM users ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/users")
async def create_user(request: Request, username: str=Form(...), password: str=Form(...), display_name: str=Form(...), role: str=Form(...)):
    user = get_current_user(request)
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403)
    if role not in ROLES_ALL:
        raise HTTPException(status_code=400, detail="Некорректная роль")
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username,password_hash,display_name,role) VALUES (?,?,?,?)", (username, hash_password(password), display_name, role))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); raise HTTPException(status_code=400, detail="Логин уже занят")
    conn.close()
    return {"success": True}

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, request: Request):
    user = get_current_user(request)
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403)
    if user["id"] == user_id:
        raise HTTPException(status_code=400, detail="Нельзя удалить себя")
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit(); conn.close()
    return {"success": True}

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def index():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())
