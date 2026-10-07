"""
Panel clinico unificado (CardioBaus · Dr. Julio Cascante).
Un mismo codigo para ambos consultorios; cada uno corre su propio servicio en Render
con su propia base de datos y su marca (variables de entorno).
"""
from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import os
import re
import json
import uuid
import hmac
import secrets
import asyncio
import logging
import smtplib
import ipaddress
import urllib.request
from html import escape
from html.parser import HTMLParser
from email.message import EmailMessage
from urllib.parse import urlparse, quote
from datetime import datetime, timezone, timedelta, date
from typing import List, Optional

import bcrypt
import jwt
from bson import ObjectId
from fastapi import (FastAPI, APIRouter, Request, Response, HTTPException, Depends, UploadFile,
                     File, Form, Query, BackgroundTasks)
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorGridFSBucket
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("panel")

client = AsyncIOMotorClient(os.environ["MONGO_URL"])
db = client[os.environ["DB_NAME"]]

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
TOKEN_DAYS = 7

EXTRA_ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip() and o.strip() != "*"]

# Valores por defecto de cada consultorio (se pueden sobreescribir con variables de entorno)
_DEFAULTS = {
    "cardiobaus": {"BRAND_NAME": "CardioBaus", "DOCTOR_NAME": "Dr. Bolívar Baus", "BRAND_TAGLINE": "Cardiología Integral",
                   "BRAND_COLOR": "#E11D48", "FRONTEND_URL": "https://cardiobaus.com"},
    "jccardio": {"BRAND_NAME": "Dr. Julio Cascante", "DOCTOR_NAME": "Dr. Julio Cascante", "BRAND_TAGLINE": "Cardiología Preventiva",
                 "BRAND_COLOR": "#E23B2E", "FRONTEND_URL": "https://drjuliocascante.com"},
}.get(os.environ.get("DB_NAME", ""), {})


def _cfg(key: str, default: str = "") -> str:
    return os.environ.get(key) or _DEFAULTS.get(key) or default


EMAIL_FROM_NAME = os.environ.get("EMAIL_FROM_NAME", "Consultorio")
BRAND_NAME = _cfg("BRAND_NAME", EMAIL_FROM_NAME)
DOCTOR_NAME = _cfg("DOCTOR_NAME", EMAIL_FROM_NAME)
BRAND_TAGLINE = _cfg("BRAND_TAGLINE", "Cardiología")
BRAND_COLOR = _cfg("BRAND_COLOR", "#E11D48")
FRONTEND_URL = (_cfg("FRONTEND_URL") or (EXTRA_ORIGINS[0] if EXTRA_ORIGINS else "http://localhost:3000")).rstrip("/")
CLINIC_WHATSAPP = re.sub(r"\D", "", os.environ.get("CLINIC_WHATSAPP", ""))

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
# Render (plan gratis) bloquea SMTP: por defecto el correo sale por el puente HTTPS del hosting.
# Poner MAIL_RELAY_URL=off para usar SMTP directo (por ejemplo en un plan pago).
MAIL_RELAY_URL = os.environ.get("MAIL_RELAY_URL", "https://cardiobaus.com/mailrelay/send.php")
if MAIL_RELAY_URL.lower() in ("off", "none", "smtp"):
    MAIL_RELAY_URL = ""
CONTACT_RECIPIENT_EMAIL = os.environ.get("CONTACT_RECIPIENT_EMAIL", "") or SMTP_USER

CRON_SECRET = os.environ.get("WEBHOOK_CRON_SECRET", "")
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "25"))
APP_NAME = os.environ.get("DB_NAME", "panel")

ACTIVE_STATUSES = ("pendiente", "confirmada", "reprogramar")
VALID_STATUSES = ("pendiente", "confirmada", "reprogramar", "cancelada", "atendida")

app = FastAPI()
api = APIRouter(prefix="/api")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def today() -> date:
    return datetime.now(timezone.utc).date()


def _parse_date(s) -> Optional[date]:
    if not s:
        return None
    try:
        return datetime.strptime(str(s)[:10], "%Y-%m-%d").date()
    except Exception:
        return None


def _clean(doc: Optional[dict]) -> Optional[dict]:
    if doc is not None:
        doc.pop("_id", None)
    return doc


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def hash_password(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()


def verify_password(p: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(p.encode(), h.encode())
    except Exception:
        return False


def _uid(u: dict) -> str:
    return u.get("id") or str(u.get("_id"))


def public_user(u: dict) -> dict:
    uname = u.get("username") or u.get("email") or ""
    return {"id": _uid(u), "username": uname, "name": u.get("name", uname), "role": u.get("role", "doctor")}


def _token_from(request: Request, auth_q: Optional[str] = None) -> Optional[str]:
    h = request.headers.get("Authorization", "")
    if h.startswith("Bearer "):
        return h[7:]
    return request.cookies.get("access_token") or auth_q


def _decode(token: str) -> Optional[dict]:
    try:
        p = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return p if p.get("type", "access") == "access" else None
    except jwt.PyJWTError:
        return None


async def _find_user_by_id(uid: str) -> Optional[dict]:
    u = await db.users.find_one({"id": uid})
    if not u and ObjectId.is_valid(uid):
        u = await db.users.find_one({"_id": ObjectId(uid)})
    return u


async def get_current_user(request: Request) -> dict:
    token = _token_from(request)
    payload = _decode(token) if token else None
    if not payload:
        raise HTTPException(status_code=401, detail="Sesión expirada, vuelve a ingresar")
    u = await _find_user_by_id(payload.get("sub", ""))
    if not u:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return public_user(u)


class LoginIn(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: str


@api.post("/auth/login")
async def login(body: LoginIn):
    uname = (body.username or body.email or "").strip().lower()
    u = await db.users.find_one({"$or": [{"username": uname}, {"email": uname}]}) if uname else None
    if not u or not verify_password(body.password, u.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
    pu = public_user(u)
    token = jwt.encode({"sub": pu["id"], "username": pu["username"], "type": "access",
                        "exp": datetime.now(timezone.utc) + timedelta(days=TOKEN_DAYS)}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"token": token, "user": pu, **pu}


@api.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"ok": True}


@api.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return user


# ---------------------------------------------------------------------------
# Email (relay HTTPS en el hosting, o SMTP directo si el plan lo permite)
# ---------------------------------------------------------------------------
_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "goo.gl", "rebrand.ly")
_CRED_ASK = ("reply with your password", "send your password", "cvv", "seed phrase", "recovery phrase",
             "verify your card", "confirm your bank details", "envie su contraseña", "numero de tarjeta")
_HOSTISH = re.compile(r"\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)


class _EmailScan(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.urls, self.anchors = set(), [], []
        self._href, self._text = None, []

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag.lower())
        self.urls += [v for k, v in attrs if k.lower() in ("href", "src") and v]
        if tag.lower() == "a":
            self._href = dict((k.lower(), v) for k, v in attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._text)))
            self._href, self._text = None, []


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _assert_safe_email(subject: str, html: str) -> None:
    scan = _EmailScan()
    scan.feed(html)
    if scan.tags & {"form", "input", "textarea", "select"}:
        raise ValueError("Email sin formularios")
    body = f"{subject}\n{html}".lower()
    if any(p in body for p in _CRED_ASK):
        raise ValueError("Email no puede pedir credenciales")
    for url in scan.urls:
        low = url.strip().lower()
        if low.startswith(("mailto:", "tel:", "#")):
            continue
        host = urlparse(low).hostname or ""
        if not low.startswith("https://") or not host or "xn--" in host or urlparse(low).username:
            raise ValueError(f"Enlace no permitido: {url}")
        if _is_ip(host):
            raise ValueError("Enlace a IP no permitido")
        if any(host == s or host.endswith("." + s) for s in _SHORTENERS):
            raise ValueError("Acortadores no permitidos")
    for href, text in scan.anchors:
        real = urlparse(href.strip().lower()).hostname or ""
        for m in _HOSTISH.finditer(text):
            shown = m.group(1).lower()
            if real and not (shown == real or real.endswith("." + shown) or shown.endswith("." + real)):
                raise ValueError("Texto del enlace no coincide con su destino")


def _relay_send(to: List[str], subject: str, html: str, reply_to: str = ""):
    payload = json.dumps({"user": SMTP_USER, "password": SMTP_PASSWORD, "from_name": EMAIL_FROM_NAME,
                          "to": to, "subject": subject, "html": html, "reply_to": reply_to}).encode()
    req = urllib.request.Request(MAIL_RELAY_URL, data=payload, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "panel-clinico/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            res = json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            res = json.loads(e.read().decode() or "{}")
        except Exception:
            res = {}
        raise RuntimeError(f"relay {e.code}: {res.get('error', '')} {res.get('detail', '')}".strip())
    if not res.get("ok"):
        raise RuntimeError(f"relay: {res}")


def _smtp_send(to: List[str], subject: str, html: str, reply_to: str = ""):
    msg = EmailMessage()
    msg["Subject"] = subject.replace("\n", " ").replace("\r", " ")
    msg["From"] = f"{EMAIL_FROM_NAME} <{SMTP_USER}>"
    msg["To"] = ", ".join(to)
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content(re.sub(r"<[^>]+>", " ", html))
    msg.add_alternative(html, subtype="html")
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            s.login(SMTP_USER, SMTP_PASSWORD)
            s.send_message(msg)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASSWORD)
            s.send_message(msg)


async def send_mail(to, subject: str, html: str, reply_to: str = "", check: bool = True):
    """Envia un correo. Lanza excepcion si falla."""
    to = [to] if isinstance(to, str) else list(to)
    if not (SMTP_USER and SMTP_PASSWORD):
        raise RuntimeError("Correo no configurado (SMTP_USER / SMTP_PASSWORD)")
    if check:
        _assert_safe_email(subject, html)
    fn = _relay_send if MAIL_RELAY_URL else _smtp_send
    await asyncio.to_thread(fn, to, subject, html, reply_to)


def _email_frame(inner: str) -> str:
    return (
        '<table role="presentation" width="100%" style="background:#0A0F1D;margin:0;padding:0"><tr><td align="center" style="padding:28px 12px">'
        '<table role="presentation" width="560" style="max-width:560px;background:#0F172A;border-radius:16px;font-family:Arial,Helvetica,sans-serif;color:#E2E8F0">'
        f'<tr><td style="padding:26px 30px;border-bottom:1px solid #1E293B"><span style="color:{BRAND_COLOR};font-size:12px;letter-spacing:2px;text-transform:uppercase">{escape(BRAND_NAME)}</span>'
        f'<div style="color:#F8FAFC;font-size:19px;font-weight:bold;margin-top:4px">{escape(DOCTOR_NAME)} · {escape(BRAND_TAGLINE)}</div></td></tr>'
        f'<tr><td style="padding:26px 30px">{inner}</td></tr>'
        f'<tr><td style="padding:16px 30px;border-top:1px solid #1E293B"><p style="font-size:12px;color:#64748B;margin:0">Enviado por {escape(BRAND_NAME)}. '
        'Nunca le pediremos contraseñas ni datos de tarjeta por correo.</p></td></tr></table></td></tr></table>'
    )


def _appt_email_html(nombre: str, when: str, nota: str, confirm_url: str, chronic: bool, reminder: bool) -> str:
    intro = ("Le recordamos su próxima consulta cardiológica, agendada para:" if reminder
             else "Su próxima consulta cardiológica quedó agendada para:")
    chronic_note = ('<p style="font-size:14px;color:#94A3B8">Por tratarse de un control de enfermedad crónica, '
                    'recuerde mantener sus controles cada 3 meses.</p>') if chronic else ""
    return _email_frame(
        f'<p style="font-size:16px;color:#F8FAFC;margin-top:0">Estimado(a) <strong>{escape(nombre)}</strong>,</p>'
        f'<p style="font-size:15px;line-height:1.6">{intro}</p>'
        f'<div style="background:#0A0F1D;border:1px solid {BRAND_COLOR};border-radius:12px;padding:16px 20px;margin:16px 0">'
        f'<div style="font-size:19px;color:#ffffff;font-weight:bold">{escape(when)}</div>'
        + (f'<div style="font-size:14px;color:#94A3B8;margin-top:6px">{escape(nota)}</div>' if nota else "")
        + "</div>" + chronic_note +
        f'<a href="{confirm_url}" style="display:inline-block;background:{BRAND_COLOR};color:#ffffff;text-decoration:none;'
        'font-weight:bold;padding:12px 22px;border-radius:10px;margin:6px 0 14px">Confirmar o reprogramar mi cita</a>'
        '<p style="font-size:13px;color:#94A3B8">Si no puede asistir, use el botón para pedir otra fecha.</p>'
    )


def _when(fecha: str, hora: str) -> str:
    d = _parse_date(fecha)
    meses = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre",
             "octubre", "noviembre", "diciembre"]
    dias = ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"]
    txt = f"{dias[d.weekday()]} {d.day} de {meses[d.month - 1]} de {d.year}" if d else (fecha or "")
    return txt + (f" a las {hora}" if hora else "")


# ---------------------------------------------------------------------------
# Archivos (GridFS privado)
# ---------------------------------------------------------------------------
fs_bucket = AsyncIOMotorGridFSBucket(db, bucket_name="uploads")


def _kind(ctype: str, filename: str = "") -> str:
    ctype = (ctype or "").lower()
    if ctype.startswith("video"):
        return "video"
    if ctype.startswith("image"):
        return "image"
    if ctype == "application/pdf" or filename.lower().endswith(".pdf"):
        return "pdf"
    return "file"


async def _store(upload: UploadFile) -> dict:
    fname = upload.filename or "archivo"
    ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else "bin"
    data = await upload.read()
    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"El archivo supera {MAX_UPLOAD_MB} MB")
    ctype = upload.content_type or "application/octet-stream"
    path = f"{APP_NAME}/uploads/{uuid.uuid4()}.{ext}"
    await fs_bucket.upload_from_stream(path, data, metadata={"content_type": ctype})
    await db.files.insert_one({"id": str(uuid.uuid4()), "storage_path": path, "original_filename": fname,
                               "content_type": ctype, "size": len(data), "is_deleted": False, "created_at": now_iso()})
    return {"path": path, "type": _kind(ctype, fname), "filename": fname, "content_type": ctype}


@api.post("/upload")
async def upload(file: UploadFile = File(...), user=Depends(get_current_user)):
    return await _store(file)


@api.get("/files/{path:path}")
async def serve_file(path: str, request: Request, auth: Optional[str] = Query(None)):
    token = _token_from(request, auth)
    if not token or not _decode(token):
        raise HTTPException(status_code=401, detail="No autenticado")
    rec = await db.files.find_one({"storage_path": path, "is_deleted": {"$ne": True}})
    if not rec:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    docs = await fs_bucket.find({"filename": path}).sort("uploadDate", -1).limit(1).to_list(1)
    if not docs:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    stream = await fs_bucket.open_download_stream(docs[0]["_id"])
    data = await stream.read()
    fname = rec.get("original_filename") or "archivo"
    return Response(content=data, media_type=rec.get("content_type") or "application/octet-stream",
                    headers={"Cache-Control": "private, max-age=3600",
                             "Content-Disposition": f"inline; filename*=UTF-8''{quote(fname)}"})


# ---------------------------------------------------------------------------
# Pacientes
# ---------------------------------------------------------------------------
class MediaRef(BaseModel):
    path: str
    type: str = "image"
    filename: Optional[str] = ""
    content_type: Optional[str] = ""


TEXT_FIELDS = [
    # Datos generales
    "edad", "sexo", "fecha_nacimiento", "tipo_sangre", "cedula", "telefono", "email", "ciudad",
    "direccion", "estado_civil", "ocupacion", "seguro", "contacto_emergencia", "telefono_emergencia",
    "fecha_consulta", "consulta_lugar",
    # Antecedentes y habitos
    "motivo_control", "factores_riesgo", "alergias", "habitos", "app", "apqx", "medicacion",
    "actividad_fisica", "vacuna_covid",
    # Examen fisico y signos
    "cuadro_clinico", "ex_fisico_respiratorio", "ex_fisico_cardiovascular", "igy", "sv", "imc", "ecg_reposo",
    # Visor clinico
    "titulo_diagnostico", "laboratorios", "eco_descripcion", "notas",
]
MEDIA_FIELDS = ["ekg_media", "eco_media", "lab_media"]
FOLLOWUP_FIELDS = ["motivo_control", "factores_riesgo", "alergias", "habitos", "app", "apqx", "medicacion",
                   "actividad_fisica", "vacuna_covid", "cuadro_clinico", "ex_fisico_respiratorio",
                   "ex_fisico_cardiovascular", "igy", "sv", "imc", "ecg_reposo"]


class PatientIn(BaseModel):
    nombre: str
    enfermedades_cronicas: bool = False
    ekg_media: List[MediaRef] = []
    eco_media: List[MediaRef] = []
    lab_media: List[MediaRef] = []

    model_config = {"extra": "allow"}

    def data(self) -> dict:
        raw = self.model_dump()
        out = {"nombre": (raw.get("nombre") or "").strip(),
               "enfermedades_cronicas": bool(raw.get("enfermedades_cronicas"))}
        for f in TEXT_FIELDS:
            v = raw.get(f)
            out[f] = "" if v is None else str(v)[:5000]
        for f in MEDIA_FIELDS:
            out[f] = raw.get(f) or []
        return out


async def _patient_or_404(pid: str) -> dict:
    p = await db.patients.find_one({"id": pid, "is_deleted": {"$ne": True}})
    if not p:
        raise HTTPException(status_code=404, detail="Paciente no encontrado")
    return p


async def _cedula_taken(cedula: str, exclude_id: str = "") -> bool:
    cedula = (cedula or "").strip()
    if not cedula:
        return False
    q = {"cedula": cedula, "is_deleted": {"$ne": True}}
    if exclude_id:
        q["id"] = {"$ne": exclude_id}
    return await db.patients.find_one(q) is not None


async def _next_appt_for(pid: str) -> Optional[dict]:
    t = today().isoformat()
    docs = await db.appointments.find({"patient_id": pid, "is_deleted": {"$ne": True},
                                       "status": {"$in": list(ACTIVE_STATUSES)}, "fecha": {"$gte": t}}
                                      ).sort([("fecha", 1), ("hora", 1)]).limit(1).to_list(1)
    return _clean(docs[0]) if docs else None


@api.get("/patients")
async def list_patients(q: Optional[str] = None, user=Depends(get_current_user)):
    query = {"is_deleted": {"$ne": True}}
    if q:
        rx = {"$regex": re.escape(q), "$options": "i"}
        query["$or"] = [{"nombre": rx}, {"cedula": rx}, {"telefono": rx}]
    docs = await db.patients.find(query, {"_id": 0}).sort("created_at", -1).to_list(2000)
    # proxima cita de cada paciente
    t = today().isoformat()
    upcoming = {}
    async for a in db.appointments.find({"is_deleted": {"$ne": True}, "status": {"$in": list(ACTIVE_STATUSES)},
                                         "fecha": {"$gte": t}, "patient_id": {"$nin": ["", None]}},
                                        {"_id": 0}).sort([("fecha", 1), ("hora", 1)]):
        upcoming.setdefault(a["patient_id"], a)
    for d in docs:
        d["next_appointment"] = upcoming.get(d["id"])
    return docs


@api.post("/patients")
async def create_patient(body: PatientIn, user=Depends(get_current_user)):
    data = body.data()
    if not data["nombre"]:
        raise HTTPException(status_code=400, detail="El nombre es obligatorio")
    if await _cedula_taken(data["cedula"]):
        raise HTTPException(status_code=400, detail="Ya existe un paciente con esa cédula")
    doc = {"id": str(uuid.uuid4()), **data, "updates": [], "schema": 2, "is_deleted": False,
           "created_by": user["id"], "created_at": now_iso(), "updated_at": now_iso()}
    await db.patients.insert_one(doc)
    return _clean(doc)


@api.get("/patients/{pid}")
async def get_patient(pid: str, user=Depends(get_current_user)):
    p = _clean(await _patient_or_404(pid))
    p["next_appointment"] = await _next_appt_for(pid)
    return p


@api.put("/patients/{pid}")
async def update_patient(pid: str, body: PatientIn, user=Depends(get_current_user)):
    await _patient_or_404(pid)
    data = body.data()
    if not data["nombre"]:
        raise HTTPException(status_code=400, detail="El nombre es obligatorio")
    if await _cedula_taken(data["cedula"], pid):
        raise HTTPException(status_code=400, detail="Ya existe un paciente con esa cédula")
    data["updated_at"] = now_iso()
    await db.patients.update_one({"id": pid}, {"$set": data})
    await db.appointments.update_many({"patient_id": pid}, {"$set": {"nombre": data["nombre"]}})
    return await get_patient(pid, user)


class PatientPatch(BaseModel):
    ekg_media: Optional[List[MediaRef]] = None
    eco_media: Optional[List[MediaRef]] = None
    lab_media: Optional[List[MediaRef]] = None


@api.patch("/patients/{pid}")
async def patch_patient_media(pid: str, body: PatientPatch, user=Depends(get_current_user)):
    await _patient_or_404(pid)
    upd = {k: [m.model_dump() for m in v] for k, v in body if v is not None}
    if upd:
        upd["updated_at"] = now_iso()
        await db.patients.update_one({"id": pid}, {"$set": upd})
    return await get_patient(pid, user)


@api.delete("/patients/{pid}")
async def delete_patient(pid: str, user=Depends(get_current_user)):
    await db.patients.update_one({"id": pid}, {"$set": {"is_deleted": True, "updated_at": now_iso()}})
    await db.appointments.update_many({"patient_id": pid, "status": {"$in": list(ACTIVE_STATUSES)}},
                                      {"$set": {"status": "cancelada"}})
    return {"ok": True}


# Seguimientos (actualizaciones con los mismos campos clinicos, para comparar evolucion)
class UpdateIn(BaseModel):
    fecha: Optional[str] = ""
    nota: Optional[str] = ""
    model_config = {"extra": "allow"}


@api.post("/patients/{pid}/updates")
async def add_update(pid: str, body: UpdateIn, user=Depends(get_current_user)):
    await _patient_or_404(pid)
    raw = body.model_dump()
    upd = {"id": str(uuid.uuid4()), "fecha": raw.get("fecha") or today().isoformat(),
           "nota": (raw.get("nota") or "")[:2000], "created_at": now_iso()}
    for f in FOLLOWUP_FIELDS:
        upd[f] = str(raw.get(f) or "")[:5000]
    await db.patients.update_one({"id": pid}, {"$push": {"updates": upd}})
    return upd


@api.delete("/patients/{pid}/updates/{uid}")
async def delete_update(pid: str, uid: str, user=Depends(get_current_user)):
    await db.patients.update_one({"id": pid}, {"$pull": {"updates": {"id": uid}}})
    return {"ok": True}


# ---------------------------------------------------------------------------
# Citas
# ---------------------------------------------------------------------------
class AppointmentIn(BaseModel):
    patient_id: Optional[str] = ""
    nombre: Optional[str] = ""
    telefono: Optional[str] = ""
    email: Optional[str] = ""
    cedula: Optional[str] = ""
    servicio: Optional[str] = ""
    fecha: str
    hora: Optional[str] = ""
    nota: Optional[str] = ""
    status: Optional[str] = "pendiente"
    notify: Optional[str] = "none"   # none | email | whatsapp | both


class StatusIn(BaseModel):
    status: str


class NotifyIn(BaseModel):
    channel: str = "both"


def confirm_url(token: str) -> str:
    return f"{FRONTEND_URL}/cita/{token}"


async def log_event(appt: dict, kind: str, channel: str, status: str, detail: str = ""):
    await db.reminder_logs.insert_one({
        "id": str(uuid.uuid4()), "patient_id": appt.get("patient_id", ""), "appointment_id": appt.get("id", ""),
        "nombre": appt.get("nombre", ""), "kind": kind, "channel": channel, "status": status,
        "fecha_cita": appt.get("fecha", ""), "detail": detail[:300], "created_at": now_iso()})


def _whatsapp_link(appt: dict, reminder: bool = False) -> str:
    when = _when(appt.get("fecha", ""), appt.get("hora", ""))
    msg = (f"Hola {appt.get('nombre', '')}, le saludamos de {BRAND_NAME} - {DOCTOR_NAME}. "
           + ("Le recordamos su próxima consulta: " if reminder else "Su próxima consulta quedó agendada para el ")
           + f"{when}." + (f" Nota: {appt['nota']}." if appt.get("nota") else "")
           + f" Confirme o reprograme su cita aquí: {confirm_url(appt['confirm_token'])} . Gracias.")
    phone = re.sub(r"\D", "", appt.get("telefono") or "")
    if phone.startswith("0") and len(phone) == 10:      # celular ecuatoriano 09XXXXXXXX
        phone = "593" + phone[1:]
    return f"https://wa.me/{phone}?text={quote(msg)}" if phone else f"https://wa.me/?text={quote(msg)}"


async def _chronic(patient_id: str) -> bool:
    if not patient_id:
        return False
    p = await db.patients.find_one({"id": patient_id}, {"enfermedades_cronicas": 1})
    return bool(p and p.get("enfermedades_cronicas"))


async def notify_appointment(appt: dict, channel: str, kind: str = "manual", reminder: bool = False) -> dict:
    """Envia la cita al paciente (email automatico; WhatsApp como enlace listo para enviar)."""
    res = {"email_sent": False, "email_error": "", "whatsapp_link": None, "confirm_url": confirm_url(appt["confirm_token"])}
    if channel in ("whatsapp", "both"):
        res["whatsapp_link"] = _whatsapp_link(appt, reminder)
        await log_event(appt, kind, "whatsapp", "enlace_generado")
    if channel in ("email", "both"):
        to = (appt.get("email") or "").strip()
        if not to:
            res["email_error"] = "El paciente no tiene email registrado"
            await log_event(appt, kind, "email", "omitido", "sin email")
        else:
            subject = (f"Recordatorio de su consulta - {BRAND_NAME}" if reminder else f"Su próxima consulta - {BRAND_NAME}")
            html = _appt_email_html(appt.get("nombre", ""), _when(appt["fecha"], appt.get("hora", "")),
                                    appt.get("nota", ""), confirm_url(appt["confirm_token"]),
                                    await _chronic(appt.get("patient_id", "")), reminder)
            try:
                await send_mail(to, subject, html, reply_to=CONTACT_RECIPIENT_EMAIL)
                res["email_sent"] = True
                await log_event(appt, kind, "email", "enviado")
                await db.appointments.update_one({"id": appt["id"]}, {"$set": {"email_sent": True}})
            except Exception as e:
                logger.error(f"email cita fallido: {e}")
                res["email_error"] = "No se pudo enviar el correo"
                await log_event(appt, kind, "email", "fallido", str(e))
    return res


async def _fill_from_patient(data: dict) -> dict:
    if data.get("patient_id"):
        p = await db.patients.find_one({"id": data["patient_id"], "is_deleted": {"$ne": True}})
        if not p:
            raise HTTPException(status_code=404, detail="Paciente no encontrado")
        for k in ("nombre", "telefono", "email", "cedula"):
            if not (data.get(k) or "").strip():
                data[k] = p.get(k, "")
    if not (data.get("nombre") or "").strip():
        raise HTTPException(status_code=400, detail="Indica el paciente o su nombre")
    if not _parse_date(data.get("fecha")):
        raise HTTPException(status_code=400, detail="Fecha inválida")
    return data


@api.get("/appointments")
async def list_appointments(patient_id: Optional[str] = None, user=Depends(get_current_user)):
    q = {"is_deleted": {"$ne": True}}
    if patient_id:
        q["patient_id"] = patient_id
    docs = await db.appointments.find(q, {"_id": 0}).sort([("fecha", 1), ("hora", 1)]).to_list(5000)
    return docs


@api.post("/appointments")
async def create_appointment(body: AppointmentIn, user=Depends(get_current_user)):
    data = await _fill_from_patient(body.model_dump())
    notify = data.pop("notify", "none") or "none"
    status = data.get("status") if data.get("status") in VALID_STATUSES else "pendiente"
    if data.get("hora"):
        clash = await db.appointments.find_one({"fecha": data["fecha"], "hora": data["hora"], "is_deleted": {"$ne": True},
                                                "status": {"$in": list(ACTIVE_STATUSES)}})
        if clash:
            raise HTTPException(status_code=400, detail=f"Ya hay una cita a esa hora ({clash.get('nombre', '')})")
    doc = {**data, "id": str(uuid.uuid4()), "status": status, "confirm_token": secrets.token_urlsafe(16),
           "requested_fecha": "", "nota_paciente": "", "responded_at": None, "source": "panel",
           "email_sent": False, "reminder_key": None, "is_deleted": False, "schema": 2,
           "created_by": user["id"], "created_at": now_iso()}
    await db.appointments.insert_one(doc)
    _clean(doc)
    result = {"appointment": doc, "email_sent": False, "whatsapp_link": None, "confirm_url": confirm_url(doc["confirm_token"])}
    if notify in ("email", "whatsapp", "both"):
        result.update(await notify_appointment(doc, notify))
    return result


@api.put("/appointments/{aid}")
async def update_appointment(aid: str, body: AppointmentIn, user=Depends(get_current_user)):
    old = await db.appointments.find_one({"id": aid, "is_deleted": {"$ne": True}})
    if not old:
        raise HTTPException(status_code=404, detail="Cita no encontrada")
    data = await _fill_from_patient(body.model_dump())
    data.pop("notify", None)
    if data.get("status") not in VALID_STATUSES:
        data["status"] = old.get("status", "pendiente")
    if data["fecha"] != old.get("fecha") or data.get("hora") != old.get("hora"):
        data["reminder_key"] = None   # nueva fecha: vuelve a recordarse
        if data["status"] == "reprogramar":
            data["status"] = "pendiente"
    await db.appointments.update_one({"id": aid}, {"$set": data})
    return _clean(await db.appointments.find_one({"id": aid}))


@api.put("/appointments/{aid}/status")
async def set_appointment_status(aid: str, body: StatusIn, user=Depends(get_current_user)):
    if body.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail="Estado inválido")
    res = await db.appointments.update_one({"id": aid, "is_deleted": {"$ne": True}}, {"$set": {"status": body.status}})
    if not res.matched_count:
        raise HTTPException(status_code=404, detail="Cita no encontrada")
    return _clean(await db.appointments.find_one({"id": aid}))


@api.post("/appointments/{aid}/notify")
async def renotify_appointment(aid: str, body: NotifyIn, user=Depends(get_current_user)):
    appt = _clean(await db.appointments.find_one({"id": aid, "is_deleted": {"$ne": True}}))
    if not appt:
        raise HTTPException(status_code=404, detail="Cita no encontrada")
    return await notify_appointment(appt, body.channel)


@api.delete("/appointments/{aid}")
async def delete_appointment(aid: str, user=Depends(get_current_user)):
    await db.appointments.update_one({"id": aid}, {"$set": {"is_deleted": True}})
    return {"ok": True}


class NextAppointmentIn(BaseModel):
    fecha: str
    hora: Optional[str] = ""
    nota: Optional[str] = ""
    servicio: Optional[str] = ""
    channel: str = "both"


@api.post("/patients/{pid}/next-appointment")
async def next_appointment(pid: str, body: NextAppointmentIn, user=Depends(get_current_user)):
    """'¿Cuándo será la próxima consulta?': agenda (o mueve) la proxima cita del paciente y se la envia."""
    p = await _patient_or_404(pid)
    if not _parse_date(body.fecha):
        raise HTTPException(status_code=400, detail="Fecha inválida")
    current = await _next_appt_for(pid)
    fields = {"fecha": body.fecha, "hora": body.hora or "", "nota": body.nota or "",
              "nombre": p.get("nombre", ""), "telefono": p.get("telefono", ""), "email": p.get("email", ""),
              "cedula": p.get("cedula", "")}
    if body.servicio:
        fields["servicio"] = body.servicio
    if current:
        fields.update({"status": "pendiente", "requested_fecha": "", "reminder_key": None})
        await db.appointments.update_one({"id": current["id"]}, {"$set": fields})
        appt = _clean(await db.appointments.find_one({"id": current["id"]}))
    else:
        appt = {"id": str(uuid.uuid4()), "patient_id": pid, "servicio": body.servicio or "Control / seguimiento",
                **fields, "status": "pendiente", "confirm_token": secrets.token_urlsafe(16), "requested_fecha": "",
                "nota_paciente": "", "responded_at": None, "source": "panel", "email_sent": False,
                "reminder_key": None, "is_deleted": False, "schema": 2, "created_by": user["id"], "created_at": now_iso()}
        await db.appointments.insert_one(appt)
        _clean(appt)
    res = await notify_appointment(appt, body.channel)
    if body.channel == "email" and res.get("email_error"):
        raise HTTPException(status_code=400, detail=res["email_error"] + ". La cita sí quedó agendada.")
    return {"appointment": appt, **res}


# ---------------------------------------------------------------------------
# Agenda, recordatorios automaticos e historial
# ---------------------------------------------------------------------------
def _lead(chronic: bool) -> int:
    return 7 if chronic else 5


async def _agenda_rows() -> list:
    t = today()
    patients = {p["id"]: p async for p in db.patients.find({"is_deleted": {"$ne": True}}, {"_id": 0, "updates": 0})}
    rows, with_appt = [], set()
    async for a in db.appointments.find({"is_deleted": {"$ne": True}, "fecha": {"$gte": (t - timedelta(days=1)).isoformat()}},
                                        {"_id": 0}).sort([("fecha", 1), ("hora", 1)]):
        d = _parse_date(a.get("fecha"))
        if not d:
            continue
        p = patients.get(a.get("patient_id") or "", {})
        chronic = bool(p.get("enfermedades_cronicas"))
        consulta = _parse_date(p.get("fecha_consulta"))
        lead = _lead(chronic)
        rdate = d - timedelta(days=lead)
        eligible = a.get("status") in ACTIVE_STATUSES and (chronic or not consulta or (d - consulta).days >= 30)
        if a.get("status") in ACTIVE_STATUSES and a.get("patient_id"):
            with_appt.add(a["patient_id"])
        rows.append({**a, "chronic": chronic, "virtual": False, "lead_days": lead, "reminder_date": rdate.isoformat(),
                     "reminder_eligible": bool(eligible), "reminder_sent": bool(a.get("reminder_key")),
                     "reminder_due_this_week": bool(eligible and not a.get("reminder_key") and t <= rdate <= t + timedelta(days=7)),
                     "dias_para_cita": (d - t).days})
    # Controles trimestrales previstos para pacientes cronicos sin cita agendada
    for pid, p in patients.items():
        if pid in with_appt or not p.get("enfermedades_cronicas"):
            continue
        consulta = _parse_date(p.get("fecha_consulta"))
        if not consulta:
            continue
        d = consulta + timedelta(days=90)
        if d < t:
            continue
        rdate = d - timedelta(days=7)
        rows.append({"id": f"control-{pid}", "virtual": True, "patient_id": pid, "nombre": p.get("nombre", ""),
                     "telefono": p.get("telefono", ""), "email": p.get("email", ""), "fecha": d.isoformat(), "hora": "",
                     "servicio": "Control trimestral (crónico)", "status": "previsto", "chronic": True, "lead_days": 7,
                     "reminder_date": rdate.isoformat(), "reminder_eligible": True, "reminder_sent": False,
                     "reminder_due_this_week": t <= rdate <= t + timedelta(days=7), "dias_para_cita": (d - t).days})
    rows.sort(key=lambda r: (r["fecha"], r.get("hora") or ""))
    return rows


@api.get("/agenda")
async def agenda(user=Depends(get_current_user)):
    return await _agenda_rows()


@api.get("/reminders/history")
async def reminders_history(patient_id: Optional[str] = None, user=Depends(get_current_user)):
    q = {"patient_id": patient_id} if patient_id else {}
    return await db.reminder_logs.find(q, {"_id": 0}).sort("created_at", -1).to_list(500)


async def process_reminders() -> dict:
    t = today()
    sent = 0
    for row in await _agenda_rows():
        try:
            if not row["reminder_eligible"] or row["reminder_sent"] or row["reminder_date"] != t.isoformat():
                continue
            if row["virtual"]:
                p = await db.patients.find_one({"id": row["patient_id"]}, {"_id": 0})
                appt = {"id": str(uuid.uuid4()), "patient_id": row["patient_id"], "nombre": p.get("nombre", ""),
                        "telefono": p.get("telefono", ""), "email": p.get("email", ""), "cedula": p.get("cedula", ""),
                        "servicio": "Control trimestral (crónico)", "fecha": row["fecha"], "hora": "",
                        "nota": "Control periódico", "status": "pendiente", "confirm_token": secrets.token_urlsafe(16),
                        "requested_fecha": "", "nota_paciente": "", "responded_at": None, "source": "auto",
                        "email_sent": False, "reminder_key": None, "is_deleted": False, "schema": 2, "created_at": now_iso()}
                await db.appointments.insert_one(appt)
                _clean(appt)
            else:
                appt = {k: v for k, v in row.items() if k not in ("chronic", "virtual", "lead_days", "reminder_date",
                        "reminder_eligible", "reminder_sent", "reminder_due_this_week", "dias_para_cita")}
            await notify_appointment(appt, "email", kind="automatico", reminder=True)
            await db.appointments.update_one({"id": appt["id"]}, {"$set": {"reminder_key": f"{appt['fecha']}|{appt.get('hora', '')}"}})
            sent += 1
        except Exception as e:
            logger.error(f"recordatorio fallido: {e}")
    logger.info(f"process_reminders: {sent} enviados")
    return {"sent": sent}


_last_cron = None


@api.post("/cron/reminders")
async def cron_reminders(request: Request, background_tasks: BackgroundTasks):
    global _last_cron
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    if CRON_SECRET:
        if not token or not hmac.compare_digest(token, CRON_SECRET):
            raise HTTPException(status_code=401, detail="No autorizado")
    else:
        # Sin clave configurada: se permite el disparo, pero como maximo una vez cada 30 min.
        # Es inofensivo: solo envia los recordatorios que tocan hoy y nunca repite uno ya enviado.
        if _last_cron and (datetime.now(timezone.utc) - _last_cron) < timedelta(minutes=30):
            return {"ok": True, "queued": False, "detail": "ya se ejecuto hace poco"}
    _last_cron = datetime.now(timezone.utc)
    background_tasks.add_task(process_reminders)
    return {"ok": True, "queued": True}


# Pagina publica del paciente (confirmar / pedir otra fecha)
class RespondIn(BaseModel):
    action: str
    requested_fecha: Optional[str] = ""
    nota: Optional[str] = ""


@api.get("/public/appointment/{token}")
async def public_appointment(token: str):
    a = await db.appointments.find_one({"confirm_token": token, "is_deleted": {"$ne": True}})
    if not a:
        raise HTTPException(status_code=404, detail="Cita no encontrada")
    p = await db.patients.find_one({"id": a.get("patient_id") or "-"}, {"consulta_lugar": 1}) or {}
    return {"nombre": a.get("nombre", ""), "fecha": a.get("fecha", ""), "hora": a.get("hora", ""),
            "servicio": a.get("servicio", ""), "consulta_lugar": p.get("consulta_lugar", ""),
            "status": a.get("status", "pendiente"), "requested_fecha": a.get("requested_fecha", ""),
            "brand": BRAND_NAME, "doctor": DOCTOR_NAME}


@api.post("/public/appointment/{token}/respond")
async def public_respond(token: str, body: RespondIn):
    a = await db.appointments.find_one({"confirm_token": token, "is_deleted": {"$ne": True}})
    if not a:
        raise HTTPException(status_code=404, detail="Cita no encontrada")
    if a.get("status") in ("cancelada", "atendida"):
        raise HTTPException(status_code=400, detail="Esta cita ya no está activa. Comuníquese con el consultorio.")
    if body.action == "confirm":
        upd, new_status = {"status": "confirmada", "responded_at": now_iso()}, "confirmada"
    elif body.action == "reschedule":
        upd = {"status": "reprogramar", "requested_fecha": (body.requested_fecha or "")[:40],
               "nota_paciente": (body.nota or "")[:500], "responded_at": now_iso()}
        new_status = "reprogramar"
    else:
        raise HTTPException(status_code=400, detail="Acción inválida")
    await db.appointments.update_one({"id": a["id"]}, {"$set": upd})
    a.update(upd)
    await log_event(a, "paciente", "web", new_status, body.requested_fecha or "")
    if CONTACT_RECIPIENT_EMAIL:
        e = {k: escape(str(a.get(k) or "-")) for k in ("nombre", "fecha", "hora", "requested_fecha", "nota_paciente", "telefono")}
        txt = ("confirmó su cita" if new_status == "confirmada" else "pide reprogramar su cita")
        html = _email_frame(f'<p style="font-size:16px;color:#F8FAFC;margin-top:0"><b>{e["nombre"]}</b> {txt}.</p>'
                            f'<p>Cita: <b>{e["fecha"]} {e["hora"]}</b></p>'
                            + (f'<p>Fecha que solicita: <b>{e["requested_fecha"]}</b><br>Nota: {e["nota_paciente"]}</p>'
                               if new_status == "reprogramar" else "")
                            + f'<p>Teléfono: {e["telefono"]}</p>')
        try:
            await send_mail(CONTACT_RECIPIENT_EMAIL, f"{a.get('nombre', '')} {txt}", html)
        except Exception as ex:
            logger.error(f"aviso al consultorio fallido: {ex}")
    return {"ok": True, "status": new_status}


# ---------------------------------------------------------------------------
# Casos (presentacion de casos clinicos) y Diapositivas
# ---------------------------------------------------------------------------
class CaseIn(BaseModel):
    patient_id: str
    title: Optional[str] = ""
    consulta: Optional[str] = ""
    fecha: Optional[str] = ""
    cuadro_clinico: Optional[str] = ""
    laboratorios: Optional[str] = ""
    eco_text: Optional[str] = ""
    diagnostico: Optional[str] = ""
    ekg_media: List[MediaRef] = []
    eco_media: List[MediaRef] = []
    lab_media: List[MediaRef] = []


@api.get("/cases")
async def list_cases(user=Depends(get_current_user)):
    return await db.cases.find({"is_deleted": {"$ne": True}}, {"_id": 0}).sort("created_at", -1).to_list(2000)


@api.get("/cases/{cid}")
async def get_case(cid: str, user=Depends(get_current_user)):
    c = await db.cases.find_one({"id": cid, "is_deleted": {"$ne": True}}, {"_id": 0})
    if not c:
        raise HTTPException(status_code=404, detail="Caso no encontrado")
    return c


@api.post("/cases")
async def create_case(body: CaseIn, user=Depends(get_current_user)):
    p = await _patient_or_404(body.patient_id)
    doc = {"id": str(uuid.uuid4()), **body.model_dump(), "patient_name": p.get("nombre", ""), "is_deleted": False,
           "schema": 2, "created_by": user["id"], "created_at": now_iso()}
    await db.cases.insert_one(doc)
    return _clean(doc)


@api.put("/cases/{cid}")
async def update_case(cid: str, body: CaseIn, user=Depends(get_current_user)):
    p = await _patient_or_404(body.patient_id)
    res = await db.cases.update_one({"id": cid, "is_deleted": {"$ne": True}},
                                    {"$set": {**body.model_dump(), "patient_name": p.get("nombre", "")}})
    if not res.matched_count:
        raise HTTPException(status_code=404, detail="Caso no encontrado")
    return await get_case(cid, user)


@api.delete("/cases/{cid}")
async def delete_case(cid: str, user=Depends(get_current_user)):
    await db.cases.update_one({"id": cid}, {"$set": {"is_deleted": True}})
    return {"ok": True}


@api.get("/presentations")
async def list_presentations(user=Depends(get_current_user)):
    return await db.presentations.find({"is_deleted": {"$ne": True}}, {"_id": 0}).sort("created_at", -1).to_list(1000)


@api.post("/presentations")
async def create_presentation(title: str = Form(...), file: UploadFile = File(...), user=Depends(get_current_user)):
    ext = (file.filename or "").rsplit(".", 1)[-1].lower()
    if ext not in ("pdf", "pptx", "ppt"):
        raise HTTPException(status_code=400, detail="Solo se permiten archivos PDF o PPTX")
    ref = await _store(file)
    doc = {"id": str(uuid.uuid4()), "title": title.strip()[:200] or ref["filename"], "kind": "pdf" if ext == "pdf" else "pptx",
           "file": ref, "is_deleted": False, "schema": 2, "created_by": user["id"], "created_at": now_iso()}
    await db.presentations.insert_one(doc)
    return _clean(doc)


@api.delete("/presentations/{pid}")
async def delete_presentation(pid: str, user=Depends(get_current_user)):
    await db.presentations.update_one({"id": pid}, {"$set": {"is_deleted": True}})
    return {"ok": True}


# ---------------------------------------------------------------------------
# Formulario de contacto de la web publica
# ---------------------------------------------------------------------------
class ContactIn(BaseModel):
    name: Optional[str] = ""
    nombre: Optional[str] = ""
    email: Optional[str] = ""
    phone: Optional[str] = ""
    telefono: Optional[str] = ""
    service: Optional[str] = ""
    motivo: Optional[str] = ""
    message: Optional[str] = ""
    mensaje: Optional[str] = ""


@api.post("/contact")
async def contact(body: ContactIn):
    d = {"nombre": (body.nombre or body.name or "").strip()[:200], "email": (body.email or "").strip()[:200],
         "telefono": (body.telefono or body.phone or "").strip()[:60], "motivo": (body.motivo or body.service or "")[:200],
         "mensaje": (body.mensaje or body.message or "")[:3000], "created_at": now_iso()}
    if not d["nombre"] or not (d["telefono"] or d["email"]):
        raise HTTPException(status_code=400, detail="Indica tu nombre y un teléfono o correo")
    await db.contact_submissions.insert_one(dict(d))
    e = {k: escape(v or "-") for k, v in d.items()}
    html = _email_frame(f'<h2 style="color:{BRAND_COLOR};margin-top:0">Nueva solicitud desde la web</h2>'
                        f'<p><b>Nombre:</b> {e["nombre"]}</p><p><b>Teléfono:</b> {e["telefono"]}</p>'
                        f'<p><b>Correo:</b> {e["email"]}</p><p><b>Servicio / motivo:</b> {e["motivo"]}</p>'
                        f'<p><b>Mensaje:</b><br>{e["mensaje"]}</p>')
    reply = d["email"] if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", d["email"]) else ""
    try:
        await send_mail(CONTACT_RECIPIENT_EMAIL, f"Nueva solicitud web: {d['nombre']}", html, reply_to=reply, check=False)
    except Exception as ex:
        logger.error(f"contacto: correo fallido: {ex}")
        return {"ok": True, "status": "stored", "message": "Recibimos tu solicitud. Te contactaremos pronto."}
    return {"ok": True, "status": "success", "message": "¡Gracias! Tu solicitud fue enviada correctamente."}


@api.get("/")
async def root():
    return {"message": f"{BRAND_NAME} API"}


# ---------------------------------------------------------------------------
# Migracion de datos de las versiones anteriores (idempotente)
# ---------------------------------------------------------------------------
_PATIENT_MAP = {"name": "nombre", "age": "edad", "sex": "sexo", "blood_type": "tipo_sangre", "birthdate": "fecha_nacimiento",
                "phone": "telefono", "city": "ciudad", "address": "direccion", "marital_status": "estado_civil",
                "occupation": "ocupacion", "insurance": "seguro", "emergency_contact": "contacto_emergencia",
                "emergency_phone": "telefono_emergencia", "consulta_place": "consulta_lugar", "consulta_date": "fecha_consulta",
                "allergies": "alergias", "medications": "medicacion", "ex_respiratorio": "ex_fisico_respiratorio",
                "ex_cardiovascular": "ex_fisico_cardiovascular", "diagnostico": "titulo_diagnostico",
                "eco_desc": "eco_descripcion", "notes": "notas", "history": "notas"}


def _ref(r: dict) -> dict:
    if not r:
        return None
    if "path" in r and "storage_path" not in r:
        r.setdefault("content_type", "")
        r.setdefault("filename", "")
        return r
    ct = r.get("content_type", "")
    fn = r.get("original_filename", "")
    return {"path": r.get("storage_path", ""), "type": _kind(ct, fn), "filename": fn, "content_type": ct}


async def migrate():
    n = 0
    async for p in db.patients.find({"schema": {"$ne": 2}}):
        upd, unset = {}, {}
        for old, new in _PATIENT_MAP.items():
            if old in p:
                if p.get(old) and not p.get(new):
                    upd[new] = p[old]
                unset[old] = ""
        for old, new in (("ekg_files", "ekg_media"), ("eco_files", "eco_media"), ("lab_files", "lab_media")):
            if old in p:
                upd[new] = [x for x in (_ref(r) for r in p.get(old) or []) if x]
                unset[old] = ""
        for f in MEDIA_FIELDS:
            if f not in upd:
                upd[f] = [x for x in (_ref(r) for r in p.get(f) or []) if x]
        updates = list(p.get("updates") or [])
        for fu in p.get("followups") or []:
            updates.append({"id": fu.get("id") or str(uuid.uuid4()), "fecha": (fu.get("date") or "")[:10],
                            "nota": fu.get("text", ""), "created_at": fu.get("date") or now_iso()})
        if "followups" in p:
            unset["followups"] = ""
        upd["updates"] = updates
        pid = p.get("id") or str(p["_id"])
        upd["id"] = pid
        na = p.get("next_appointment")
        if na and na.get("fecha"):
            if not await db.appointments.find_one({"confirm_token": na.get("confirm_token") or "-"}):
                await db.appointments.insert_one({
                    "id": str(uuid.uuid4()), "patient_id": pid, "nombre": p.get("nombre") or p.get("name", ""),
                    "telefono": p.get("telefono") or p.get("phone", ""), "email": p.get("email", ""), "cedula": p.get("cedula", ""),
                    "servicio": "Control / seguimiento", "fecha": na.get("fecha"), "hora": na.get("hora", ""),
                    "nota": na.get("nota", ""), "status": na.get("status", "pendiente"),
                    "confirm_token": na.get("confirm_token") or secrets.token_urlsafe(16),
                    "requested_fecha": na.get("requested_fecha", ""), "nota_paciente": na.get("nota_paciente", ""),
                    "responded_at": na.get("responded_at"), "source": "panel", "email_sent": False,
                    "reminder_key": (f"{na.get('fecha')}|{na.get('hora', '')}" if p.get("auto_reminder_sent") else None),
                    "is_deleted": False, "schema": 2, "created_at": na.get("set_at") or now_iso()})
        for k in ("next_appointment", "auto_reminder_sent", "owner_id"):
            if k in p:
                unset[k] = ""
        upd.setdefault("is_deleted", bool(p.get("is_deleted")))
        upd["schema"] = 2
        op = {"$set": upd}
        if unset:
            op["$unset"] = unset
        await db.patients.update_one({"_id": p["_id"]}, op)
        n += 1
    async for a in db.appointments.find({"schema": {"$ne": 2}}):
        upd = {"schema": 2, "nombre": a.get("nombre") or a.get("name", ""), "telefono": a.get("telefono") or a.get("phone", ""),
               "fecha": a.get("fecha") or a.get("date", ""), "hora": a.get("hora") or a.get("time", ""),
               "servicio": a.get("servicio") or a.get("service", ""), "nota": a.get("nota") or a.get("reason", ""),
               "confirm_token": a.get("confirm_token") or secrets.token_urlsafe(16), "requested_fecha": a.get("requested_fecha", ""),
               "reminder_key": a.get("reminder_key"), "source": a.get("source", "panel")}
        await db.appointments.update_one({"_id": a["_id"]}, {"$set": upd, "$unset": {k: "" for k in
                                         ("name", "phone", "date", "time", "service", "reason", "owner_id") if k in a}})
        n += 1
    async for c in db.cases.find({"schema": {"$ne": 2}}):
        upd = {"schema": 2,
               "ekg_media": [x for x in (_ref(r) for r in c.get("ekg_files") or []) if x],
               "lab_media": [x for x in (_ref(r) for r in c.get("lab_files") or []) if x],
               "eco_media": [x for x in [_ref(c.get("eco_file"))] if x]}
        await db.cases.update_one({"_id": c["_id"]}, {"$set": upd, "$unset": {"ekg_files": "", "lab_files": "", "eco_file": "", "owner_id": ""}})
        n += 1
    async for pr in db.presentations.find({"schema": {"$ne": 2}}):
        await db.presentations.update_one({"_id": pr["_id"]}, {"$set": {"schema": 2, "file": _ref(pr.get("file") or {})},
                                                                "$unset": {"owner_id": ""}})
        n += 1
    if n:
        logger.info(f"migracion: {n} documentos actualizados")


# ---------------------------------------------------------------------------
# Arranque
# ---------------------------------------------------------------------------
app.include_router(api)
app.add_middleware(CORSMiddleware, allow_credentials=True,
                   allow_origins=list(dict.fromkeys([FRONTEND_URL, FRONTEND_URL.replace("https://", "https://www.")] + EXTRA_ORIGINS)),
                   allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
async def startup():
    try:
        staff = json.loads(os.environ.get("SEED_USERS", "[]"))
    except json.JSONDecodeError:
        staff, _ = [], logger.error("SEED_USERS no es JSON valido")
    for s in staff:
        uname = (s.get("username") or s.get("email") or "").strip().lower()
        if not uname or not s.get("password"):
            continue
        if not await db.users.find_one({"$or": [{"username": uname}, {"email": uname}]}):
            await db.users.insert_one({"id": str(uuid.uuid4()), "username": uname, "email": uname,
                                       "name": s.get("name", uname), "password_hash": hash_password(s["password"]),
                                       "role": "doctor", "created_at": now_iso()})
            logger.info(f"Usuario inicial creado: {uname}")
    try:
        await migrate()
    except Exception as e:
        logger.error(f"migracion fallida: {e}")
    for coll, key in (("patients", "id"), ("appointments", "id"), ("appointments", "confirm_token"), ("cases", "id")):
        try:
            await db[coll].create_index(key)
        except Exception:
            pass


@app.get("/health")
async def health():
    return {"ok": True}


@app.on_event("shutdown")
async def shutdown():
    client.close()
