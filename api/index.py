import os, io, re, json, base64, ipaddress, urllib.parse
import qrcode
from PIL import Image, UnidentifiedImageError
from flask import Flask, request, jsonify, send_from_directory, Response
import pyshorteners

# ── Upstash Redis (Vercel KV) — graceful fallback ─────────────────────────────
try:
    from upstash_redis import Redis
    _kv = Redis.from_env()
    _kv.ping()
    KV_AVAILABLE = True
except Exception:
    _kv = None
    KV_AVAILABLE = False

KV_KEY       = "qreafy:url_history"
KV_MAX_ITEMS = 100

# ── Absolute paths (required for Vercel serverless) ───────────────────────────
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")

app = Flask(__name__, static_folder=PUBLIC_DIR, static_url_path="")

# ── Security constants ────────────────────────────────────────────────────────
MAX_DATA_LEN   = 2000
MAX_LOGO_BYTES = 3 * 1024 * 1024
MAGIC_BYTES    = {b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF"}
BLOCKED_HOSTS  = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_safe_url(url: str) -> tuple:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "URL mal formada."
    if parsed.scheme not in ("http", "https"):
        return False, "Solo se permiten URLs http o https."
    host = parsed.hostname or ""
    if not host:
        return False, "URL sin host válido."
    if host.lower() in BLOCKED_HOSTS:
        return False, "Host no permitido."
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            return False, "Host no permitido."
    except ValueError:
        pass
    return True, ""


def _validate_image_magic(data: bytes) -> bool:
    return any(data[:len(m)] == m for m in MAGIC_BYTES)


def _hex_to_rgb(h: str) -> tuple:
    h = h.strip().lstrip("#")
    if not re.fullmatch(r"[0-9a-fA-F]{6}", h):
        return (0, 0, 0)
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


def _clamp(val, lo, hi):
    return max(lo, min(val, hi))


# ── KV helpers ────────────────────────────────────────────────────────────────

def kv_push(item: dict) -> None:
    if not KV_AVAILABLE:
        return
    try:
        _kv.lpush(KV_KEY, json.dumps(item, ensure_ascii=False))
        _kv.ltrim(KV_KEY, 0, KV_MAX_ITEMS - 1)
    except Exception as e:
        app.logger.warning("KV push: %s", e)


def kv_get_all() -> list:
    if not KV_AVAILABLE:
        return []
    try:
        raw = _kv.lrange(KV_KEY, 0, KV_MAX_ITEMS - 1)
        out = []
        for item in (raw or []):
            try:
                out.append(json.loads(item) if isinstance(item, str) else item)
            except Exception:
                pass
        return out
    except Exception as e:
        app.logger.warning("KV get: %s", e)
        return []


# ── QR generation ─────────────────────────────────────────────────────────────

def make_qr_base64(data, logo_bytes=None, size=10, border=2,
                   fill_color="#000000", back_color="#ffffff", logo_ratio=0.28):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=_clamp(size, 4, 25),
        border=_clamp(border, 0, 8),
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(
        fill_color=_hex_to_rgb(fill_color),
        back_color=_hex_to_rgb(back_color),
    ).convert("RGBA")
    qw, qh = img.size

    if logo_bytes:
        try:
            logo = Image.open(io.BytesIO(logo_bytes)).convert("RGBA")
            mp = int(qw * _clamp(logo_ratio, 0.10, 0.42))
            logo.thumbnail((mp, mp), Image.LANCZOS)
            lw, lh = logo.size
            pad = max(4, int(min(lw, lh) * 0.08))
            bg = Image.new("RGBA", (lw + 2*pad, lh + 2*pad), (255, 255, 255, 255))
            bg.paste(logo, (pad, pad), logo)
            img.paste(bg, ((qw - bg.width) // 2, (qh - bg.height) // 2), bg)
        except Exception as e:
            app.logger.warning("Logo skip: %s", e)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


# ── Security headers ──────────────────────────────────────────────────────────

@app.after_request
def sec_headers(resp: Response) -> Response:
    resp.headers.update({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options":        "DENY",
        "X-XSS-Protection":       "1; mode=block",
        "Referrer-Policy":        "strict-origin-when-cross-origin",
        "Permissions-Policy":     "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        ),
    })
    resp.headers.pop("Server", None)
    return resp


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(PUBLIC_DIR, "index.html")

@app.route("/favicon.svg")
def favicon():
    return send_from_directory(PUBLIC_DIR, "favicon.svg")


@app.route("/api/generate-qr", methods=["POST"])
def api_generate_qr():
    data = (request.form.get("data") or "").strip()
    if not data:
        return jsonify({"error": "El campo 'data' es obligatorio."}), 400
    if len(data) > MAX_DATA_LEN:
        return jsonify({"error": f"Máximo {MAX_DATA_LEN} caracteres."}), 400

    try:
        size       = _clamp(int(request.form.get("size",   10)), 4, 25)
        border     = _clamp(int(request.form.get("border",  2)), 0,  8)
        logo_ratio = _clamp(float(request.form.get("logo_ratio", 0.28)), 0.10, 0.42)
        fill_color = (request.form.get("fill_color") or "#000000").strip()
        back_color = (request.form.get("back_color") or "#ffffff").strip()
    except (ValueError, TypeError):
        return jsonify({"error": "Parámetros inválidos."}), 400

    logo_bytes = None
    if "logo" in request.files:
        f = request.files["logo"]
        if f and f.filename:
            raw = f.read(MAX_LOGO_BYTES + 1)
            if len(raw) > MAX_LOGO_BYTES:
                return jsonify({"error": "Logo máx. 3 MB."}), 400
            if not _validate_image_magic(raw):
                return jsonify({"error": "Formato de imagen no permitido."}), 400
            logo_bytes = raw

    try:
        qr_b64 = make_qr_base64(data, logo_bytes, size, border, fill_color, back_color, logo_ratio)
        return jsonify({"qr": qr_b64})
    except Exception:
        return jsonify({"error": "Error generando QR."}), 500


@app.route("/api/shorten-url", methods=["POST"])
def api_shorten_url():
    body = request.get_json(silent=True) or {}
    url  = (body.get("url") or "").strip()

    if not url:
        return jsonify({"error": "El campo 'url' es obligatorio."}), 400
    if len(url) > 2000:
        return jsonify({"error": "URL demasiado larga."}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    safe, reason = _is_safe_url(url)
    if not safe:
        return jsonify({"error": reason}), 400

    try:
        short = pyshorteners.Shortener().tinyurl.short(url)
        item  = {"short_url": short, "original_url": url}
        kv_push(item)
        return jsonify({**item, "kv": KV_AVAILABLE})
    except Exception as e:
        app.logger.error("shorten-url error: %s", e)
        return jsonify({"error": "No se pudo acortar la URL. Intenta de nuevo."}), 500


@app.route("/api/history", methods=["GET"])
def api_history():
    return jsonify({"history": kv_get_all(), "kv_available": KV_AVAILABLE})


@app.route("/api/history", methods=["DELETE"])
def api_clear_history():
    if not KV_AVAILABLE:
        return jsonify({"error": "KV no disponible."}), 503
    try:
        _kv.delete(KV_KEY)
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"error": "No se pudo limpiar."}), 500


@app.errorhandler(404)
def not_found(_):         return jsonify({"error": "Ruta no encontrada."}),   404
@app.errorhandler(405)
def method_not_allowed(_): return jsonify({"error": "Método no permitido."}), 405
@app.errorhandler(500)
def internal_error(_):    return jsonify({"error": "Error interno."}),        500
