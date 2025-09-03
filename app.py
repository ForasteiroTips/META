import os, time, requests, ipaddress, json, threading
from flask import Flask, request, jsonify
from flask_cors import CORS

# Aceita nomes META_* (preferido) ou FB_* (fallback), para não quebrar se os segredos mudarem
PIXEL_ID = (
    os.getenv("META_PIXEL_ID")
    or os.getenv("FB_PIXEL_ID")
    or ""
)
ACCESS_TOKEN = (
    os.getenv("META_ACCESS_TOKEN")
    or os.getenv("FB_ACCESS_TOKEN")
    or ""
)
TEST_EVENT_CODE = os.getenv("META_TEST_EVENT_CODE")  # opcional (use apenas em Eventos de teste)

GRAPH_URL = f"https://graph.facebook.com/v18.0/{PIXEL_ID}/events"

app = Flask(__name__)
CORS(app, resources={r"/capi/*": {"origins": "*"}})

# ---------------------------
# Deduplicação (persistente)
# ---------------------------
DEDUP_FILE = os.getenv("DEDUP_FILE", "dedup.json")
# TTL opcional (em horas). Se quiser que “expire” e aceite de novo depois de X horas, defina DEDUP_TTL_HOURS
DEDUP_TTL_HOURS = float(os.getenv("DEDUP_TTL_HOURS", "0"))  # 0 = sem expiração

_lock = threading.Lock()
_seen = {}  # dict: uid -> first_seen_epoch

def _now():
    return int(time.time())

def _load_seen():
    global _seen
    if os.path.exists(DEDUP_FILE):
        try:
            with open(DEDUP_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                # suporta formatos antigos (lista) e novo (dict)
                if isinstance(data, list):
                    _seen = {uid: _now() for uid in data}
                elif isinstance(data, dict):
                    _seen = {str(k): int(v) for k, v in data.items()}
                else:
                    _seen = {}
        except Exception:
            _seen = {}
    else:
        _seen = {}

def _save_seen():
    tmp = f"{DEDUP_FILE}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_seen, f, ensure_ascii=False)
    os.replace(tmp, DEDUP_FILE)

def _maybe_prune():
    """Remove entradas antigas se DEDUP_TTL_HOURS > 0."""
    if DEDUP_TTL_HOURS <= 0:
        return
    cutoff = _now() - int(DEDUP_TTL_HOURS * 3600)
    removed = [k for k, ts in _seen.items() if ts < cutoff]
    if removed:
        for k in removed:
            _seen.pop(k, None)

def _extract_uid(payload: dict) -> str | None:
    """
    Identificador de usuário em ordem de prioridade:
    1) user_id (se seu front enviar)
    2) fbp (cookie)
    3) fbc (fbclid)
    4) event_id (por último)
    """
    uid = (
        payload.get("user_id")
        or payload.get("fbp")
        or payload.get("fbc")
        or payload.get("event_id")
    )
    if uid:
        return str(uid)
    return None

def is_duplicate_and_mark(payload: dict) -> bool:
    """Retorna True se já vimos esse usuário; caso contrário marca e retorna False."""
    uid = _extract_uid(payload)
    if not uid:
        # Sem identificador → não dá para deduplicar; deixa passar
        return False
    with _lock:
        _maybe_prune()
        if uid in _seen:
            return True
        _seen[uid] = _now()
        try:
            _save_seen()
        except Exception:
            # Se falhar salvar, seguimos com a memória atual
            pass
    return False

# Carrega os já vistos na subida do app
_load_seen()

# ---------------------------
# Utilitários de rede / CAPI
# ---------------------------
def get_public_ip():
    """Retorna o 1º IP público válido encontrado (ignora privados/loopback/reservados)."""
    xff = request.headers.get("X-Forwarded-For", "")
    candidates = []
    if xff:
        candidates += [p.strip() for p in xff.split(",") if p.strip()]

    for h in ("Fly-Client-IP", "CF-Connecting-IP", "X-Real-IP"):
        v = request.headers.get(h)
        if v:
            candidates.append(v.strip())

    if request.remote_addr:
        candidates.append(request.remote_addr.strip())

    for ip in candidates:
        try:
            ipobj = ipaddress.ip_address(ip)
            if not (ipobj.is_private or ipobj.is_reserved or ipobj.is_loopback or ipobj.is_link_local):
                return ip
        except ValueError:
            pass
    return None

def _post_to_meta(event_name: str, j: dict):
    """Monta o payload padrão e envia ao Graph API."""
    event_id   = j.get("event_id")
    source_url = j.get("source_url")
    fbp        = j.get("fbp") or None      # só usa se vier do cookie real
    fbc        = j.get("fbc") or None      # só usa se vier de fbclid (tráfego)

    user_data = {
        "client_user_agent": request.headers.get("User-Agent"),
    }
    ip_pub = get_public_ip()
    if ip_pub:
        user_data["client_ip_address"] = ip_pub
    if fbp:
        user_data["fbp"] = fbp
    if fbc:
        user_data["fbc"] = fbc

    payload = {
        "data": [{
            "event_name": event_name,
            "event_time": int(time.time()),
            "event_id": event_id,                 # útil se um dia usar pixel browser para dedup
            "action_source": "website",
            "event_source_url": source_url,
            "user_data": user_data
        }],
        **({"test_event_code": TEST_EVENT_CODE} if TEST_EVENT_CODE else {})
    }

    if not PIXEL_ID or not ACCESS_TOKEN:
        print("❌ Faltando META_PIXEL_ID/META_ACCESS_TOKEN (ou FB_*). Configure nas variáveis de ambiente.", flush=True)
        return (jsonify({"error": "missing_secrets"}), 500)

    r = requests.post(
        GRAPH_URL,
        params={"access_token": ACCESS_TOKEN},
        json=payload,
        timeout=10
    )
    print(f"📤 CAPI {event_name} →", payload, flush=True)
    print("📥 Meta resp →", r.status_code, r.text, flush=True)

    return ("", 204) if r.ok else (jsonify(_safe_json(r)), r.status_code)

def _safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return {"status_code": resp.status_code, "text": resp.text[:5000]}

# ---------------------------
# Endpoints
# ---------------------------
@app.post("/capi/lead")
def capi_lead():
    j = request.get_json(silent=True) or {}
    # bloqueia usuário repetido
    if is_duplicate_and_mark(j):
        # já vimos este usuário → ignora silenciosamente
        return ("", 204)
    return _post_to_meta("Lead", j)

@app.post("/capi/pageview")
def capi_pageview():
    j = request.get_json(silent=True) or {}
    # PageView não é deduplicado
    return _post_to_meta("PageView", j)

@app.get("/")
def health():
    return "ok"
