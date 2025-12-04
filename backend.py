# backend.py
# Requirements: pip install fastapi uvicorn sqlalchemy databases aiosqlite pydantic passlib
# Run command: uvicorn backend:app --reload

import asyncio
import json
import hashlib
import uuid
import random
from datetime import datetime
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlalchemy
from databases import Database

# --- DATABASE CONFIGURATION ---
DATABASE_URL = "sqlite:///./smart_home.db"

# --- DATABASE SCHEMA ---
metadata = sqlalchemy.MetaData()

# 1. Users Table (Authentication)
users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String, unique=True, nullable=False),
    sqlalchemy.Column("password_hash", sqlalchemy.String, nullable=False),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

# 2. Sensors Table (Device Status)
# is_triggered: 0=Safe, 1=Standard (Blue), 2=Warning (Orange), 3=Critical (Red)
sensors = sqlalchemy.Table(
    "sensors",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String, nullable=False),
    sqlalchemy.Column("type", sqlalchemy.String, nullable=False),
    sqlalchemy.Column("is_triggered", sqlalchemy.Integer, nullable=False, default=0),
    sqlalchemy.Column("sensitivity", sqlalchemy.Float, nullable=False, default=1.0),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

# 3. Events Table (Logs)
events = sqlalchemy.Table(
    "events",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, primary_key=True),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime, nullable=False),
    sqlalchemy.Column("level", sqlalchemy.String, nullable=False),
    sqlalchemy.Column("source", sqlalchemy.String, nullable=False),
    sqlalchemy.Column("payload", sqlalchemy.String, nullable=True),
)

# 4. Risk Assessments Table (Quiz Results)
risk_assessments = sqlalchemy.Table(
    "risk_assessments",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, primary_key=True),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime, default=datetime.utcnow),
    sqlalchemy.Column("score", sqlalchemy.Integer, nullable=False),
    sqlalchemy.Column("risk_level", sqlalchemy.String, nullable=False),
    sqlalchemy.Column("details", sqlalchemy.String, nullable=True),
)

engine = sqlalchemy.create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
metadata.create_all(engine)
db = Database(DATABASE_URL)

# --- PYDANTIC MODELS ---
class UserAuth(BaseModel):
    username: str
    password: str

class SensorOut(BaseModel):
    id: str
    name: str
    type: str
    is_triggered: int
    sensitivity: float

class EventOut(BaseModel):
    id: str
    timestamp: datetime
    level: str
    source: str
    payload: Optional[Dict[str, Any]]

class RiskAssessmentIn(BaseModel):
    score: int
    details: Dict[str, Any]

class RiskAssessmentOut(BaseModel):
    score: int
    risk_level: str
    timestamp: datetime

# --- APP & MIDDLEWARE ---
app = FastAPI(title="Smart Home Security Hub")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow HTML file to connect
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- WEBSOCKET MANAGER ---
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []
    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
    def disconnect(self, ws: WebSocket):
        if ws in self.active: self.active.remove(ws)
    async def broadcast(self, message: dict):
        for conn in list(self.active):
            try: await conn.send_text(json.dumps(message, default=str))
            except: self.disconnect(conn)

manager = ConnectionManager()

# --- HELPERS ---
async def log_event(level: str, source: str, payload: Optional[dict] = None):
    ev_id = str(uuid.uuid4())
    now = datetime.utcnow()
    await db.execute(events.insert().values(
        id=ev_id, timestamp=now, level=level, source=source, 
        payload=json.dumps(payload) if payload else None
    ))
    await manager.broadcast({"type": "event", "event": {"level": level, "source": source, "payload": payload}})

# --- LIFECYCLE ---
@app.on_event("startup")
async def startup():
    await db.connect()
    # Seed Sensors if empty
    if await db.fetch_val(sqlalchemy.select([sqlalchemy.func.count()]).select_from(sensors)) == 0:
        seed = [
            ("Front Door", "door"), 
            ("Kitchen Window", "window"), 
            ("Living Room Motion", "motion"), 
            ("Backyard Camera", "camera")
        ]
        for name, type_ in seed:
            await db.execute(sensors.insert().values(
                id=str(uuid.uuid4()), name=name, type=type_, is_triggered=0
            ))

@app.on_event("shutdown")
async def shutdown():
    await db.disconnect()

# ================= ENDPOINTS =================

@app.get("/")
async def root():
    return {"status": "Smart Home Backend Online"}

# --- AUTH ---
@app.post("/register")
async def register(user: UserAuth):
    # Check existing
    query = sqlalchemy.select([users]).where(users.c.username == user.username)
    if await db.fetch_one(query):
        raise HTTPException(status_code=400, detail="Username already exists")

    # Hash Password (SHA256 for demo simplicity)
    hashed = hashlib.sha256(user.password.encode()).hexdigest()
    
    await db.execute(users.insert().values(
        id=str(uuid.uuid4()),
        username=user.username,
        password_hash=hashed,
        created_at=datetime.utcnow()
    ))
    return {"status": "success"}

@app.post("/login")
async def login(user: UserAuth):
    query = sqlalchemy.select([users]).where(users.c.username == user.username)
    record = await db.fetch_one(query)
    
    if not record:
        raise HTTPException(status_code=401, detail="User not found")
        
    hashed_input = hashlib.sha256(user.password.encode()).hexdigest()
    if hashed_input != record["password_hash"]:
        raise HTTPException(status_code=401, detail="Incorrect password")
        
    return {"status": "success", "username": record["username"]}

# --- SENSORS & SIMULATOR ---
@app.get("/sensors", response_model=List[SensorOut])
async def get_sensors():
    return await db.fetch_all(sqlalchemy.select([sensors]))

@app.post("/sensors/{sensor_id}/trigger")
async def manual_trigger(sensor_id: str, active: bool = True, event_text: str = "Manual Trigger"):
    trigger_level = 0
    if active:
        # Determine Severity Level based on text from frontend
        txt = event_text.lower()
        if "break" in txt or "force" in txt or "critical" in txt:
            trigger_level = 3 # Critical
        elif "tamper" in txt or "warn" in txt:
            trigger_level = 2 # Warning
        else:
            trigger_level = 1 # Standard

    await db.execute(sensors.update().where(sensors.c.id == sensor_id).values(is_triggered=trigger_level))
    
    if active:
        s = await db.fetch_one(sqlalchemy.select([sensors]).where(sensors.c.id == sensor_id))
        severity = "critical" if trigger_level == 3 else ("warn" if trigger_level == 2 else "info")
        await log_event(severity, "manual.trigger", {"sensor": s["name"], "msg": event_text})

    return {"status": "updated", "level": trigger_level}

@app.post("/sensors/{sensor_id}/reset")
async def reset_sensor(sensor_id: str):
    await db.execute(sensors.update().where(sensors.c.id == sensor_id).values(is_triggered=0))
    return {"status": "reset"}

# --- DATA ---
@app.get("/events", response_model=List[EventOut])
async def get_events(limit: int = 20):
    return await db.fetch_all(sqlalchemy.select([events]).order_by(events.c.timestamp.desc()).limit(limit))

@app.post("/assessment")
async def save_assessment(data: RiskAssessmentIn):
    risk = "Safe" if data.score >= 80 else "Risk"
    await db.execute(risk_assessments.insert().values(
        id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        score=data.score,
        risk_level=risk,
        details=json.dumps(data.details)
    ))
    return {"status": "saved"}

@app.get("/assessment/latest", response_model=Optional[RiskAssessmentOut])
async def get_latest_assessment():
    return await db.fetch_one(sqlalchemy.select([risk_assessments]).order_by(risk_assessments.c.timestamp.desc()).limit(1))

