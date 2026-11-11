#!/usr/bin/env python3
# ============================================================
#  SW MONARCH - OTP SERVER + RATE-LIMIT DEFENSE LAB
#  Dev        : SW MONARCH
#  Platform   : Termux / Linux / any Python 3.7+
#  Deps       : pip install fastapi uvicorn
#  Disclaimer : Educational lab. Run locally against your own
#               instance only.
# ============================================================

import time, random, hashlib, threading
from collections import defaultdict, deque
from typing import Deque, Dict
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="SW MONARCH OTP Lab")

# ---------- CONFIG ----------
OTP_TTL           = 300     # seconds a code stays valid
OTP_LENGTH        = 6
PER_NUMBER_COOLDOWN = 60    # seconds between sends to same number
PER_NUMBER_WINDOW = 3600    # rolling window for number
PER_NUMBER_MAX    = 5       # max sends per number per window
PER_IP_WINDOW     = 600     # rolling window for IP
PER_IP_MAX        = 10      # max sends per IP per window
HONEYPOT_FIELD    = "website"   # bots fill this, humans don't
LOCKOUT_TIME      = 900     # 15 min lockout after abuse

# ---------- STORAGE (in-memory, thread-safe) ----------
LOCK = threading.Lock()
otp_store: Dict[str, dict] = {}                    # number -> {code, expires, attempts}
number_hits: Dict[str, Deque[float]] = defaultdict(deque)
ip_hits:     Dict[str, Deque[float]] = defaultdict(deque)
lockouts:    Dict[str, float] = {}                 # number/ip -> until_ts
stats = {"sent": 0, "verified": 0, "blocked_cooldown": 0,
         "blocked_number": 0, "blocked_ip": 0, "blocked_honeypot": 0,
         "failed_verify": 0, "lockout": 0}

# ---------- HELPERS ----------
def now() -> float:
    return time.time()

def prune(dq: Deque[float], window: int) -> None:
    cutoff = now() - window
    while dq and dq[0] < cutoff:
        dq.popleft()

def is_locked(key: str) -> bool:
    until = lockouts.get(key, 0)
    if until > now():
        return True
    if key in lockouts:
        del lockouts[key]
    return False

def add_lockout(key: str) -> None:
    lockouts[key] = now() + LOCKOUT_TIME
    stats["lockout"] += 1

def gen_otp() -> str:
    return "".join(random.choices("0123456789", k=OTP_LENGTH))

def hash_otp(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()

def bump(counter: str) -> None:
    with LOCK:
        stats[counter] += 1

# ---------- MODELS ----------
class SendReq(BaseModel):
    number: str
    website: str = ""      # honeypot

class VerifyReq(BaseModel):
    number: str
    code: str

# ---------- MIDDLEWARE: capture client IP ----------
@app.middleware("http")
async def log_ip(request: Request, call_next):
    request.state.ip = request.client.host if request.client else "unknown"
    return await call_next(request)

# ---------- ENDPOINTS ----------
@app.post("/otp/send")
async def send_otp(req: SendReq, request: Request):
    ip = request.state.ip
    number = req.number.strip()

    # honeypot first — bots give themselves away
    if req.website.strip():
        bump("blocked_honeypot")
        add_lockout(ip)
        return JSONResponse({"ok": False, "reason": "bot_detected"}, status_code=403)

    if not number.isdigit() or not (10 <= len(number) <= 15):
        raise HTTPException(400, "invalid_number")

    with LOCK:
        if is_locked(number) or is_locked(ip):
            bump("lockout")
            raise HTTPException(429, "locked_out")

        # per-number cooldown
        entry = otp_store.get(number)
        if entry and (now() - entry.get("last_sent", 0)) < PER_NUMBER_COOLDOWN:
            bump("blocked_cooldown")
            remaining = int(PER_NUMBER_COOLDOWN - (now() - entry["last_sent"]))
            raise HTTPException(429, f"cooldown_{remaining}s")

        # per-number rolling window
        dq_n = number_hits[number]
        prune(dq_n, PER_NUMBER_WINDOW)
        if len(dq_n) >= PER_NUMBER_MAX:
            bump("blocked_number")
            add_lockout(number)
            raise HTTPException(429, "number_rate_limited")

        # per-IP rolling window
        dq_ip = ip_hits[ip]
        prune(dq_ip, PER_IP_WINDOW)
        if len(dq_ip) >= PER_IP_MAX:
            bump("blocked_ip")
            add_lockout(ip)
            raise HTTPException(429, "ip_rate_limited")

        # issue OTP
        code = gen_otp()
        otp_store[number] = {
            "hash": hash_otp(code),
            "expires": now() + OTP_TTL,
            "attempts": 0,
            "last_sent": now(),
        }
        dq_n.append(now())
        dq_ip.append(now())
        stats["sent"] += 1

    # in production: send via SMS gateway here
    # this lab returns the code in the response so you can test the flow
    return {"ok": True, "dev_code": code, "expires_in": OTP_TTL}

@app.post("/otp/verify")
async def verify_otp(req: VerifyReq):
    number = req.number.strip()
    code = req.code.strip()

    with LOCK:
        entry = otp_store.get(number)
        if not entry:
            bump("failed_verify")
            raise HTTPException(404, "no_active_otp")
        if now() > entry["expires"]:
            del otp_store[number]
            bump("failed_verify")
            raise HTTPException(410, "expired")
        if entry["attempts"] >= 5:
            del otp_store[number]
            add_lockout(number)
            raise HTTPException(429, "too_many_attempts")

        entry["attempts"] += 1
        if hash_otp(code) != entry["hash"]:
            bump("failed_verify")
            raise HTTPException(401, "wrong_code")

        del otp_store[number]
        stats["verified"] += 1
        return {"ok": True, "verified": True}

@app.get("/stats")
async def get_stats():
    with LOCK:
        return {
            **stats,
            "active_otps": len(otp_store),
            "numbers_tracked": len(number_hits),
            "ips_tracked": len(ip_hits),
            "active_lockouts": sum(1 for t in lockouts.values() if t > now()),
        }

@app.get("/health")
async def health():
    return {"ok": True, "ts": int(now())}

# ---------- ENTRY ----------
if __name__ == "__main__":
    import uvicorn
    print("SW MONARCH OTP Lab -> http://127.0.0.1:8000")
    print("Endpoints: POST /otp/send | POST /otp/verify | GET /stats")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
