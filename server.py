from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

import os
import uuid
import logging
import secrets
import bcrypt
import jwt
import hmac
import json
import smtplib
import asyncio
from email.message import EmailMessage
import re
import ipaddress
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlparse, quote
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Annotated

from fastapi import FastAPI, APIRouter, Request, Response, HTTPException, Depends, UploadFile, File, Query, Header, BackgroundTasks
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorGridFSBucket
from pydantic import BaseModel, Field, BeforeValidator, EmailStr
from bson import ObjectId

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("cardiobaus")

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")
CLINIC_WHATSAPP = os.environ.get("CLINIC_WHATSAPP", "")

# Email (SMTP, buzon del dominio en cPanel)
EMAIL_FROM_NAME = os.environ.get("EMAIL_FROM_NAME", "CardioBaus")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
CONTACT_RECIPIENT_EMAIL = os.environ.get("CONTACT_RECIPIENT_EMAIL", SMTP_USER)

APP_NAME = "cardiobaus"
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "25"))
EXTRA_ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]

app = FastAPI()
api_router = APIRouter(prefix="/api")

# ---------------------------------------------------------------------------
# Mongo helpers
# ---------------------------------------------------------------------------
PyObjectId = Annotated[str, BeforeValidator(str)]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Auth utilities
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(user_id: str, email: str) -> str:
    payload = {"sub": user_id, "email": email, "exp": datetime.now(timezone.utc) + timedelta(hours=12), "type": "access"}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    payload = {"sub": user_id, "exp": datetime.now(timezone.utc) + timedelta(days=7), "type": "refresh"}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def set_auth_cookies(response: Response, access: str, refresh: str):
    response.set_cookie("access_token", access, httponly=True, secure=True, samesite="none", max_age=43200, path="/")
    response.set_cookie("refresh_token", refresh, httponly=True, secure=True, samesite="none", max_age=604800, path="/")


def _extract_token(request: Request, auth_q: Optional[str] = None) -> Optional[str]:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token and auth_q:
        token = auth_q
    return token


async def get_current_user(request: Request) -> dict:
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="No autenticado")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Tipo de token invalido")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")
        user["id"] = str(user["_id"])
        user.pop("_id", None)
        user.pop("password_hash", None)
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Sesion expirada")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalido")


# ---------------------------------------------------------------------------
# Email guardrail gate (from playbook)
# ---------------------------------------------------------------------------
_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "goo.gl", "rebrand.ly")
_CRED_ASK = ("reply with your password", "reply with the code", "send your password", "cvv",
             "send us your password", "enter your password below", "confirm your card number",
             "your full card number", "seed phrase", "recovery phrase", "verify your card",
             "social security number", "confirm your bank details")
_HOSTISH = re.compile(r"\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)


def _host_ok(host: str) -> bool:
    if not host or "xn--" in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return not any(host == s or host.endswith("." + s) for s in _SHORTENERS)


def _same_site(shown: str, real: str) -> bool:
    return shown == real or real.endswith("." + shown) or shown.endswith("." + real)


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


def _assert_safe_email(subject: str, html: str) -> None:
    scan = _EmailScan()
    scan.feed(html)
    if scan.tags & {"form", "input", "textarea", "select"}:
        raise ValueError("No forms or input fields in email (G2)")
    body = f"{subject}\n{html}".lower()
    for p in _CRED_ASK:
        if p in body:
            raise ValueError(f"Email asks for credentials: {p!r} (G2)")
    for url in scan.urls:
        low = url.strip().lower()
        if low.startswith(("mailto:", "tel:", "cid:", "#")):
            continue
        if not low.startswith("https://"):
            raise ValueError(f"Email links must be absolute https: {url!r} (G3)")
        host = urlparse(low).hostname or ""
        if not _host_ok(host) or urlparse(low).username is not None:
            raise ValueError(f"Bad URL: {url!r} (G3)")
    for href, text in scan.anchors:
        real = urlparse(href.strip().lower()).hostname or ""
        if not real:
            continue
        for m in _HOSTISH.finditer(text):
            if not _same_site(m.group(1).lower(), real):
                raise ValueError(f"Anchor text mismatch (G3)")


async def send_email(*, to: str, subject: str, html: str) -> Optional[str]:
    _assert_safe_email(subject, html)
    try:
        await asyncio.to_thread(_smtp_send, to, subject, html)
        return "smtp"
    except Exception as e:
        logger.error(f"Email send error: {e}")
        raise HTTPException(status_code=500, detail="No se pudo enviar el email")


def _smtp_send(to: str, subject: str, html: str, reply_to: str = ""):
    if not (SMTP_HOST and SMTP_USER and SMTP_PASSWORD):
        raise RuntimeError("SMTP no configurado")
    msg = EmailMessage()
    msg["Subject"] = subject.replace("\n", " ").replace("\r", " ")
    msg["From"] = f"{EMAIL_FROM_NAME} <{SMTP_USER}>"
    msg["To"] = to
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content("Mensaje de CardioBaus (ver version HTML).")
    msg.add_alternative(html, subtype="html")
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30) as sm:
            sm.login(SMTP_USER, SMTP_PASSWORD); sm.send_message(msg)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as sm:
            sm.starttls(); sm.login(SMTP_USER, SMTP_PASSWORD); sm.send_message(msg)


# ---------------------------------------------------------------------------
# Object storage (MongoDB GridFS, privado)
# ---------------------------------------------------------------------------
fs_bucket = AsyncIOMotorGridFSBucket(db, bucket_name="uploads")


async def put_object(path: str, data: bytes, content_type: str) -> dict:
    await fs_bucket.upload_from_stream(path, data, metadata={"content_type": content_type})
    return {"path": path, "size": len(data)}


async def get_object(path: str):
    docs = await fs_bucket.find({"filename": path}).sort("uploadDate", -1).limit(1).to_list(1)
    if not docs:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    stream = await fs_bucket.open_download_stream(docs[0]["_id"])
    data = await stream.read()
    return data, (docs[0].get("metadata") or {}).get("content_type", "application/octet-stream")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class LoginInput(BaseModel):
    email: str
    password: str


class MediaRef(BaseModel):
    path: str
    type: str = "image"  # image | video
    filename: Optional[str] = None


class PatientInput(BaseModel):
    # Datos generales
    nombre: str
    edad: Optional[str] = ""
    cedula: Optional[str] = ""
    fecha_consulta: Optional[str] = ""
    telefono: Optional[str] = ""
    email: Optional[str] = ""
    consulta_lugar: Optional[str] = "Cenincardio"
    # Clinico
    motivo_control: Optional[str] = ""
    factores_riesgo: Optional[str] = ""
    alergias: Optional[str] = ""
    habitos: Optional[str] = ""
    app: Optional[str] = ""
    apqx: Optional[str] = ""
    medicacion: Optional[str] = ""
    actividad_fisica: Optional[str] = ""
    vacuna_covid: Optional[str] = ""
    enfermedades_cronicas: bool = False
    cuadro_clinico: Optional[str] = ""
    ex_fisico_respiratorio: Optional[str] = ""
    ex_fisico_cardiovascular: Optional[str] = ""
    igy: Optional[str] = ""
    sv: Optional[str] = ""
    imc: Optional[str] = ""
    ecg_reposo: Optional[str] = ""
    # Visor
    titulo_diagnostico: Optional[str] = ""
    laboratorios: Optional[str] = ""
    eco_descripcion: Optional[str] = ""
    ekg_media: List[MediaRef] = []
    eco_media: List[MediaRef] = []


class NextAppointmentInput(BaseModel):
    fecha: str
    hora: Optional[str] = ""
    nota: Optional[str] = ""
    channel: str = "email"  # email | whatsapp | both


class UpdateInput(BaseModel):
    fecha: Optional[str] = ""
    nota: Optional[str] = ""
    # Antecedentes y habitos
    motivo_control: Optional[str] = ""
    factores_riesgo: Optional[str] = ""
    alergias: Optional[str] = ""
    habitos: Optional[str] = ""
    app: Optional[str] = ""
    apqx: Optional[str] = ""
    medicacion: Optional[str] = ""
    actividad_fisica: Optional[str] = ""
    vacuna_covid: Optional[str] = ""
    # Examen fisico y signos
    cuadro_clinico: Optional[str] = ""
    ex_fisico_respiratorio: Optional[str] = ""
    ex_fisico_cardiovascular: Optional[str] = ""
    igy: Optional[str] = ""
    sv: Optional[str] = ""
    imc: Optional[str] = ""
    ecg_reposo: Optional[str] = ""


class RespondInput(BaseModel):
    action: str  # confirm | reschedule
    requested_fecha: Optional[str] = ""
    nota: Optional[str] = ""


class ContactInput(BaseModel):
    nombre: str
    telefono: str
    motivo: Optional[str] = ""
    mensaje: Optional[str] = ""


def patient_public(doc: dict) -> dict:
    doc["id"] = str(doc["_id"])
    doc.pop("_id", None)
    return doc


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@api_router.post("/auth/login")
async def login(payload: LoginInput, response: Response):
    email = payload.email.lower().strip()
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Credenciales invalidas")
    uid = str(user["_id"])
    access = create_access_token(uid, email)
    refresh = create_refresh_token(uid)
    set_auth_cookies(response, access, refresh)
    return {"id": uid, "email": email, "name": user.get("name", ""), "role": user.get("role", "admin"), "token": access}


@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"ok": True}


@api_router.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return user


# ---------------------------------------------------------------------------
# Patient routes
# ---------------------------------------------------------------------------
@api_router.get("/patients")
async def list_patients(user=Depends(get_current_user), q: Optional[str] = None):
    query = {}
    if q:
        query = {"$or": [{"nombre": {"$regex": q, "$options": "i"}},
                         {"cedula": {"$regex": q, "$options": "i"}}]}
    docs = await db.patients.find(query).sort("created_at", -1).to_list(1000)
    return [patient_public(d) for d in docs]


@api_router.post("/patients")
async def create_patient(payload: PatientInput, user=Depends(get_current_user)):
    doc = payload.model_dump()
    doc["created_at"] = now_iso()
    doc["updated_at"] = now_iso()
    doc["next_appointment"] = None
    doc["updates"] = []
    res = await db.patients.insert_one(doc)
    created = await db.patients.find_one({"_id": res.inserted_id})
    return patient_public(created)


@api_router.get("/patients/{pid}")
async def get_patient(pid: str, user=Depends(get_current_user)):
    doc = await db.patients.find_one({"_id": ObjectId(pid)})
    if not doc:
        raise HTTPException(status_code=404, detail="Paciente no encontrado")
    return patient_public(doc)


@api_router.put("/patients/{pid}")
async def update_patient(pid: str, payload: PatientInput, user=Depends(get_current_user)):
    doc = payload.model_dump()
    doc["updated_at"] = now_iso()
    await db.patients.update_one({"_id": ObjectId(pid)}, {"$set": doc})
    updated = await db.patients.find_one({"_id": ObjectId(pid)})
    if not updated:
        raise HTTPException(status_code=404, detail="Paciente no encontrado")
    return patient_public(updated)


@api_router.delete("/patients/{pid}")
async def delete_patient(pid: str, user=Depends(get_current_user)):
    await db.patients.delete_one({"_id": ObjectId(pid)})
    return {"ok": True}


@api_router.post("/patients/{pid}/next-appointment")
async def next_appointment(pid: str, payload: NextAppointmentInput, user=Depends(get_current_user)):
    patient = await db.patients.find_one({"_id": ObjectId(pid)})
    if not patient:
        raise HTTPException(status_code=404, detail="Paciente no encontrado")

    confirm_token = secrets.token_urlsafe(16)
    appt = {"fecha": payload.fecha, "hora": payload.hora, "nota": payload.nota, "set_at": now_iso(),
            "confirm_token": confirm_token, "status": "pendiente", "requested_fecha": "", "responded_at": None}
    await db.patients.update_one({"_id": ObjectId(pid)}, {"$set": {"next_appointment": appt, "auto_reminder_sent": None}})

    nombre = patient.get("nombre", "Paciente")
    when = payload.fecha + ((" a las " + payload.hora) if payload.hora else "")
    nota_txt = f" Nota: {payload.nota}." if payload.nota else ""
    confirm_url = _confirm_url(confirm_token)

    result = {"email_sent": False, "whatsapp_link": None, "confirm_url": confirm_url}

    # WhatsApp click-to-send link (prefilled)
    if payload.channel in ("whatsapp", "both"):
        phone = re.sub(r"\D", "", patient.get("telefono") or "")
        msg = (f"Hola {nombre}, le saludamos de CardioBaus - Dr. Bolivar Baus. "
               f"Le recordamos su proxima consulta: {when}.{nota_txt} "
               f"Confirme o reprograme su cita aqui: {confirm_url} . Gracias.")
        if phone:
            result["whatsapp_link"] = f"https://wa.me/{phone}?text={quote(msg)}"
        else:
            result["whatsapp_link"] = f"https://wa.me/?text={quote(msg)}"
        await log_reminder(patient, "manual", "whatsapp", "enlace_generado", payload.fecha)

    # Email via Resend
    if payload.channel in ("email", "both"):
        to = (patient.get("email") or "").strip()
        if not to:
            if payload.channel == "email":
                raise HTTPException(status_code=400, detail="El paciente no tiene email registrado")
        else:
            subject = "Recordatorio de proxima consulta - CardioBaus"
            html = (
                '<table role="presentation" width="100%" style="background:#0A0F1D;padding:0;margin:0">'
                '<tr><td align="center" style="padding:28px">'
                '<table role="presentation" width="560" style="background:#0F172A;border-radius:16px;'
                'font-family:Arial,Helvetica,sans-serif;color:#E2E8F0;overflow:hidden">'
                '<tr><td style="padding:28px 32px;border-bottom:1px solid #1E293B">'
                '<span style="color:#EC4899;font-size:13px;letter-spacing:2px;text-transform:uppercase">CardioBaus</span>'
                '<div style="color:#38BDF8;font-size:20px;font-weight:bold;margin-top:4px">Dr. Bolivar Baus · Cardiologia Integral</div>'
                '</td></tr>'
                '<tr><td style="padding:28px 32px">'
                f'<p style="font-size:16px;color:#F8FAFC">Estimado(a) <strong>{escape(nombre)}</strong>,</p>'
                f'<p style="font-size:15px;line-height:1.6">Le recordamos que su proxima consulta cardiologica esta agendada para:</p>'
                f'<div style="background:#0A0F1D;border:1px solid #EC4899;border-radius:12px;padding:18px 22px;margin:18px 0">'
                f'<div style="font-size:19px;color:#ffffff;font-weight:bold">{escape(when)}</div>'
                + (f'<div style="font-size:14px;color:#94A3B8;margin-top:6px">{escape(payload.nota)}</div>' if payload.nota else '')
                + '</div>'
                f'<a href="{confirm_url}" style="display:inline-block;background:#EC4899;color:#ffffff;text-decoration:none;font-weight:bold;padding:12px 22px;border-radius:10px;margin:4px 0 14px">Confirmar o reprogramar mi cita</a>'
                '<p style="font-size:14px;color:#94A3B8">Si necesita reprogramar, use el boton de arriba.</p>'
                '</td></tr>'
                '<tr><td style="padding:18px 32px;border-top:1px solid #1E293B">'
                '<p style="font-size:12px;color:#64748B;margin:0">Enviado por CardioBaus. Su corazon es nuestra prioridad. '
                'Nunca le pediremos contrasenas ni datos de tarjeta por email.</p>'
                '</td></tr></table></td></tr></table>'
            )
            await send_email(to=to, subject=subject, html=html)
            result["email_sent"] = True
            await log_reminder(patient, "manual", "email", "enviado", payload.fecha)

    return result


# ---------------------------------------------------------------------------
# Patient updates (seguimientos)
# ---------------------------------------------------------------------------
@api_router.get("/patients/{pid}/updates")
async def list_updates(pid: str, user=Depends(get_current_user)):
    patient = await db.patients.find_one({"_id": ObjectId(pid)})
    if not patient:
        raise HTTPException(status_code=404, detail="Paciente no encontrado")
    return patient.get("updates", [])


@api_router.post("/patients/{pid}/updates")
async def add_update(pid: str, payload: UpdateInput, user=Depends(get_current_user)):
    patient = await db.patients.find_one({"_id": ObjectId(pid)})
    if not patient:
        raise HTTPException(status_code=404, detail="Paciente no encontrado")
    update = payload.model_dump()
    update["id"] = str(uuid.uuid4())
    update["created_at"] = now_iso()
    await db.patients.update_one({"_id": ObjectId(pid)}, {"$push": {"updates": update}})
    return update


@api_router.delete("/patients/{pid}/updates/{uid}")
async def delete_update(pid: str, uid: str, user=Depends(get_current_user)):
    await db.patients.update_one({"_id": ObjectId(pid)}, {"$pull": {"updates": {"id": uid}}})
    return {"ok": True}


# ---------------------------------------------------------------------------
# File upload / serving
# ---------------------------------------------------------------------------
@api_router.post("/upload")
async def upload(file: UploadFile = File(...), user=Depends(get_current_user)):
    ext = file.filename.split(".")[-1].lower() if "." in file.filename else "bin"
    path = f"{APP_NAME}/uploads/{uuid.uuid4()}.{ext}"
    data = await file.read()
    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"El archivo supera {MAX_UPLOAD_MB} MB")
    ctype = file.content_type or "application/octet-stream"
    result = await put_object(path, data, ctype)
    await db.files.insert_one({
        "id": str(uuid.uuid4()),
        "storage_path": result["path"],
        "original_filename": file.filename,
        "content_type": ctype,
        "size": result.get("size"),
        "is_deleted": False,
        "created_at": now_iso(),
    })
    kind = "video" if ctype.startswith("video") else "image"
    return {"path": result["path"], "type": kind, "filename": file.filename}


@api_router.get("/files/{path:path}")
async def download(path: str, request: Request, auth: Optional[str] = Query(None)):
    token = _extract_token(request, auth)
    if not token:
        raise HTTPException(status_code=401, detail="No autenticado")
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token invalido")
    record = await db.files.find_one({"storage_path": path, "is_deleted": False})
    if not record:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    data, content_type = await get_object(path)
    return Response(content=data, media_type=record.get("content_type", content_type))


# ---------------------------------------------------------------------------
# Public contact form
# ---------------------------------------------------------------------------
@api_router.post("/contact")
async def contact(payload: ContactInput):
    doc = payload.model_dump()
    doc["created_at"] = now_iso()
    await db.contacts.insert_one(dict(doc))
    if CONTACT_RECIPIENT_EMAIL:
        e = {k: escape(str(v or "-")) for k, v in payload.model_dump().items()}
        html = (f'<div style="font-family:Arial;padding:20px"><h2 style="color:#E11D48">Nueva solicitud de cita (web)</h2>'
                f'<p><b>Nombre:</b> {e["nombre"]}</p><p><b>Telefono:</b> {e["telefono"]}</p>'
                f'<p><b>Motivo:</b> {e["motivo"]}</p><p><b>Mensaje:</b><br>{e["mensaje"]}</p></div>')
        try:
            await asyncio.to_thread(_smtp_send, CONTACT_RECIPIENT_EMAIL, f"Nueva solicitud web: {payload.nombre}", html)
        except Exception as ex:
            logger.error(f"contact email failed: {ex}")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Automatic reminders (Email via Resend + WhatsApp via Twilio) — daily cron
# ---------------------------------------------------------------------------
CRON_SECRET = os.environ.get("WEBHOOK_CRON_SECRET", "")


def _confirm_url(token: str) -> str:
    return f"{FRONTEND_URL.rstrip('/')}/cita/{token}"


async def log_reminder(patient: dict, kind: str, channel: str, status: str, fecha_cita: str, detail: str = ""):
    await db.reminder_logs.insert_one({
        "id": str(uuid.uuid4()),
        "patient_id": str(patient.get("_id")),
        "nombre": patient.get("nombre", ""),
        "kind": kind,
        "channel": channel,
        "status": status,
        "fecha_cita": fecha_cita,
        "detail": detail,
        "created_at": now_iso(),
    })


def _parse_date(s):
    if not s:
        return None
    try:
        return datetime.strptime(str(s)[:10], "%Y-%m-%d").date()
    except Exception:
        return None


def send_whatsapp(to: str, body: str) -> bool:
    sid = os.environ.get("TWILIO_ACCOUNT_SID")
    tok = os.environ.get("TWILIO_AUTH_TOKEN")
    frm = os.environ.get("TWILIO_WHATSAPP_FROM")
    if not (sid and tok and frm):
        return False
    num = re.sub(r"\D", "", to or "")
    if not num:
        return False
    sender_num = re.sub(r"\D", "", frm)
    try:
        from twilio.rest import Client
        client = Client(sid, tok)
        client.messages.create(from_=f"whatsapp:+{sender_num}", to=f"whatsapp:+{num}", body=body)
        return True
    except Exception as e:
        logger.error(f"WhatsApp send failed: {e}")
        return False


def _reminder_html(nombre, when, chronic, confirm_url=""):
    cron_note = ("<p style=\"font-size:14px;color:#94A3B8\">Por tratarse de un control de enfermedad cronica, "
                 "recuerde mantener sus controles cada 3 meses.</p>") if chronic else ""
    return (
        '<table role="presentation" width="100%" style="background:#0A0F1D;padding:0;margin:0"><tr><td align="center" style="padding:28px">'
        '<table role="presentation" width="560" style="background:#0F172A;border-radius:16px;font-family:Arial,Helvetica,sans-serif;color:#E2E8F0;overflow:hidden">'
        '<tr><td style="padding:28px 32px;border-bottom:1px solid #1E293B">'
        '<span style="color:#EC4899;font-size:13px;letter-spacing:2px;text-transform:uppercase">CardioBaus</span>'
        '<div style="color:#38BDF8;font-size:20px;font-weight:bold;margin-top:4px">Dr. Bolivar Baus · Cardiologia Integral</div></td></tr>'
        '<tr><td style="padding:28px 32px">'
        f'<p style="font-size:16px;color:#F8FAFC">Estimado(a) <strong>{escape(nombre)}</strong>,</p>'
        '<p style="font-size:15px;line-height:1.6">Le recordamos su proxima consulta cardiologica agendada para:</p>'
        f'<div style="background:#0A0F1D;border:1px solid #EC4899;border-radius:12px;padding:18px 22px;margin:18px 0"><div style="font-size:19px;color:#ffffff;font-weight:bold">{escape(when)}</div></div>'
        + cron_note +
        (f'<a href="{confirm_url}" style="display:inline-block;background:#EC4899;color:#ffffff;text-decoration:none;font-weight:bold;padding:12px 22px;border-radius:10px;margin:6px 0 14px">Confirmar o reprogramar mi cita</a>' if confirm_url else '') +
        '<p style="font-size:14px;color:#94A3B8">Por favor confirme su asistencia con anticipacion.</p></td></tr>'
        '<tr><td style="padding:18px 32px;border-top:1px solid #1E293B"><p style="font-size:12px;color:#64748B;margin:0">Enviado por CardioBaus. Su corazon es nuestra prioridad. Nunca le pediremos contrasenas ni datos de tarjeta por email.</p></td></tr>'
        '</table></td></tr></table>'
    )


async def process_reminders() -> dict:
    today = datetime.now(timezone.utc).date()
    sent = 0
    cursor = db.patients.find({})
    async for p in cursor:
        try:
            chronic = bool(p.get("enfermedades_cronicas"))
            consulta = _parse_date(p.get("fecha_consulta"))
            na = p.get("next_appointment")
            appt = None
            key = None
            if na and na.get("fecha"):
                appt = _parse_date(na.get("fecha"))
                key = f"appt:{na.get('fecha')}"
            elif chronic and consulta:
                appt = consulta + timedelta(days=90)
                key = f"control:{appt.isoformat()}"
            if not appt:
                continue
            lead = 7 if chronic else 5
            # Regla de 30 dias (solo no-cronicos): recordar unicamente si la cita
            # esta agendada 30+ dias despues de la atencion.
            if not chronic:
                if not consulta or (appt - consulta).days < 30:
                    continue
            if today != appt - timedelta(days=lead):
                continue
            if p.get("auto_reminder_sent") == key:
                continue

            # Asegurar cita registrada + token de confirmacion
            when = appt.isoformat()
            na_prev = p.get("next_appointment") or {}
            token = na_prev.get("confirm_token") or secrets.token_urlsafe(16)
            na_obj = {
                "fecha": when,
                "hora": na_prev.get("hora", ""),
                "nota": na_prev.get("nota") or ("Control periodico (cronico)" if chronic and not p.get("next_appointment") else ""),
                "set_at": na_prev.get("set_at") or now_iso(),
                "confirm_token": token,
                "status": na_prev.get("status", "pendiente"),
                "requested_fecha": na_prev.get("requested_fecha", ""),
                "responded_at": na_prev.get("responded_at"),
                "auto": na_prev.get("auto", not bool(p.get("next_appointment"))),
            }
            confirm_url = _confirm_url(token)
            nombre = p.get("nombre", "Paciente")
            to_email = (p.get("email") or "").strip()
            if to_email:
                try:
                    await send_email(to=to_email, subject="Recordatorio de consulta - CardioBaus",
                                     html=_reminder_html(nombre, when, chronic, confirm_url))
                    await log_reminder(p, "automatico", "email", "enviado", when)
                except Exception as e:
                    logger.error(f"reminder email failed: {e}")
                    await log_reminder(p, "automatico", "email", "fallido", when, str(e)[:200])
            else:
                await log_reminder(p, "automatico", "email", "omitido", when, "sin email")
            msg = (f"Hola {nombre}, le recordamos su proxima consulta en CardioBaus el {when}. "
                   + ("Por tratarse de un control cronico, mantenga sus controles cada 3 meses. " if chronic else "")
                   + f"Confirme o reprograme su cita aqui: {confirm_url} . Gracias.")
            wa_ok = send_whatsapp(p.get("telefono") or "", msg)
            await log_reminder(p, "automatico", "whatsapp", "enviado" if wa_ok else "omitido", when,
                               "" if wa_ok else "Twilio no configurado o sin telefono")
            await db.patients.update_one({"_id": p["_id"]}, {"$set": {"auto_reminder_sent": key, "next_appointment": na_obj}})
            sent += 1
        except Exception as e:
            logger.error(f"reminder error: {e}")
    logger.info(f"process_reminders done; sent={sent}")
    return {"sent": sent}


@api_router.post("/cron/reminders")
async def cron_reminders(request: Request, background_tasks: BackgroundTasks):
    # Cron endpoints must ack 2xx immediately; enqueue/background the actual work.
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    if not token or not CRON_SECRET or not hmac.compare_digest(token, CRON_SECRET):
        raise HTTPException(status_code=401, detail="No autorizado")
    background_tasks.add_task(process_reminders)
    return {"ok": True, "queued": True}


@api_router.get("/agenda")
async def agenda(user=Depends(get_current_user)):
    today = datetime.now(timezone.utc).date()
    out = []
    async for p in db.patients.find({}):
        chronic = bool(p.get("enfermedades_cronicas"))
        consulta = _parse_date(p.get("fecha_consulta"))
        na = p.get("next_appointment")
        appt = None
        hora = ""
        status = "pendiente"
        source = "cita"
        requested_fecha = ""
        if na and na.get("fecha"):
            appt = _parse_date(na.get("fecha"))
            hora = na.get("hora", "")
            status = na.get("status", "pendiente")
            requested_fecha = na.get("requested_fecha", "")
        elif chronic and consulta:
            appt = consulta + timedelta(days=90)
            source = "control"
        if not appt:
            continue
        if appt < today - timedelta(days=1):
            continue
        lead = 7 if chronic else 5
        reminder_date = appt - timedelta(days=lead)
        eligible = bool(chronic or (consulta and (appt - consulta).days >= 30))
        out.append({
            "patient_id": str(p["_id"]),
            "nombre": p.get("nombre", ""),
            "telefono": p.get("telefono", ""),
            "email": p.get("email", ""),
            "fecha": appt.isoformat(),
            "hora": hora,
            "chronic": chronic,
            "source": source,
            "status": status,
            "requested_fecha": requested_fecha,
            "lead_days": lead,
            "reminder_date": reminder_date.isoformat(),
            "reminder_eligible": eligible,
            "reminder_due_this_week": bool(eligible and today <= reminder_date <= today + timedelta(days=7)),
            "reminder_sent": bool(p.get("auto_reminder_sent")),
            "dias_para_cita": (appt - today).days,
        })
    out.sort(key=lambda x: x["fecha"])
    return out


@api_router.get("/reminders/history")
async def reminders_history(user=Depends(get_current_user), patient_id: Optional[str] = None):
    q = {"patient_id": patient_id} if patient_id else {}
    logs = await db.reminder_logs.find(q).sort("created_at", -1).to_list(500)
    for lg in logs:
        lg.pop("_id", None)
    return logs


@api_router.get("/public/appointment/{token}")
async def public_appointment(token: str):
    p = await db.patients.find_one({"next_appointment.confirm_token": token})
    if not p:
        raise HTTPException(status_code=404, detail="Cita no encontrada")
    na = p.get("next_appointment", {})
    return {
        "nombre": p.get("nombre", ""),
        "fecha": na.get("fecha", ""),
        "hora": na.get("hora", ""),
        "consulta_lugar": p.get("consulta_lugar", ""),
        "status": na.get("status", "pendiente"),
        "requested_fecha": na.get("requested_fecha", ""),
    }


@api_router.post("/public/appointment/{token}/respond")
async def public_respond(token: str, payload: RespondInput):
    p = await db.patients.find_one({"next_appointment.confirm_token": token})
    if not p:
        raise HTTPException(status_code=404, detail="Cita no encontrada")
    if payload.action == "confirm":
        upd = {"next_appointment.status": "confirmada", "next_appointment.responded_at": now_iso()}
        new_status = "confirmada"
    elif payload.action == "reschedule":
        upd = {
            "next_appointment.status": "reprogramar",
            "next_appointment.requested_fecha": payload.requested_fecha,
            "next_appointment.nota_paciente": payload.nota,
            "next_appointment.responded_at": now_iso(),
        }
        new_status = "reprogramar"
    else:
        raise HTTPException(status_code=400, detail="Accion invalida")
    await db.patients.update_one({"_id": p["_id"]}, {"$set": upd})
    await log_reminder(p, "paciente", "web", new_status, p.get("next_appointment", {}).get("fecha", ""),
                       payload.requested_fecha or "")
    return {"ok": True, "status": new_status}


@api_router.get("/")
async def root():
    return {"message": "CardioBaus API"}


# ---------------------------------------------------------------------------
# App wiring
# ---------------------------------------------------------------------------
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=[FRONTEND_URL] + EXTRA_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    # indexes
    await db.users.create_index("email", unique=True)
    # Usuarios iniciales desde la variable SEED_USERS (JSON: [{"username","name","password"}]).
    # Solo se crean si no existen; nunca se sobrescriben contrasenas.
    try:
        staff = json.loads(os.environ.get("SEED_USERS", "[]"))
    except json.JSONDecodeError:
        staff = []
        logger.error("SEED_USERS no es JSON valido")
    for s_ in staff:
        em = (s_.get("username") or s_.get("email") or "").lower().strip()
        if not em or not s_.get("password"):
            continue
        if await db.users.find_one({"email": em}) is None:
            await db.users.insert_one({"email": em, "password_hash": hash_password(s_["password"]),
                                       "name": s_.get("name", em), "role": "admin", "created_at": now_iso()})
            logger.info(f"User seeded: {em}")


@app.get("/health")
async def health():
    return {"ok": True}


@app.on_event("shutdown")
async def shutdown():
    client.close()
