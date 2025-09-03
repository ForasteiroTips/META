import os, time, requests, ipaddress
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
        print("❌ Faltando META_PIXEL_ID/META_ACCESS_TOKEN (ou FB_*). Configure com `fly secrets set`.", flush=True)
        return (jsonify({"error": "missing_secrets"}), 500)

    r = requests.post(
        GRAPH_URL,
        params={"access_token": ACCESS_TOKEN},
        json=payload,
        timeout=10
    )
    print(f"📤 CAPI {event_name} →", payload, flush=True)
    print("📥 Meta resp →", r.status_code, r.text, flush=True)

    return ("", 204) if r.ok else (jsonify(r.json()), r.status_code)

@app.post("/capi/lead")
def capi_lead():
    j = request.get_json(silent=True) or {}
    return _post_to_meta("Lead", j)

@app.post("/capi/pageview")
def capi_pageview():
    j = request.get_json(silent=True) or {}
    return _post_to_meta("PageView", j)

@app.get("/")
def health():
    return "ok"
