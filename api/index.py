import os, io, re, json, base64, ipaddress, urllib.parse, hashlib, hmac
import qrcode
import requests
from PIL import Image
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

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

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")

app = Flask(__name__, static_folder=PUBLIC_DIR, static_url_path="")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

MAX_DATA_LEN    = 2000
MAX_LOGO_BYTES  = 3 * 1024 * 1024
MAGIC_BYTES     = {b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF"}
BLOCKED_HOSTS   = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
HISTORY_TOKEN   = os.environ.get("HISTORY_TOKEN", "")

# Domains known to be URL shorteners — their URLs must be resolved
# before passing to third-party shorteners (anti-spam policy)
_SHORTENER_DOMAINS = {
    "goo.gl", "maps.app.goo.gl", "bit.ly", "bitly.com",
    "tinyurl.com", "t.co", "ow.ly", "buff.ly", "ift.tt",
    "dlvr.it", "fb.me", "youtu.be", "amzn.to", "short.link",
    "rb.gy", "cutt.ly", "tiny.cc", "shorturl.at", "is.gd",
    "v.gd", "lnkd.in", "wp.me", "adf.ly", "bc.vc",
}

_REQ_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; Googlebot/2.1; "
        "+http://www.google.com/bot.html)"
    ),
    "Accept": "text/html,application/xhtml+xml,*/*",
}


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


def _is_shortener_domain(url: str) -> bool:
    """Return True if this URL comes from a known URL shortener service."""
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        return any(
            host == d or host.endswith("." + d)
            for d in _SHORTENER_DOMAINS
        )
    except Exception:
        return False


def _resolve_url(url: str) -> str:
    """
    Follow redirect chain and return the final destination URL.
    Uses HEAD first (fast), falls back to GET if server rejects HEAD.
    Returns the original URL if resolution fails.
    """
    try:
        resp = requests.head(
            url,
            allow_redirects=True,
            timeout=6,
            headers=_REQ_HEADERS,
        )
        final = resp.url
        # Validate the resolved URL is safe to use
        if final and final.startswith(("http://", "https://")) and final != url:
            app.logger.info("Resolved %s -> %s", url, final)
            return final
    except Exception as e:
        app.logger.warning("HEAD resolve failed for %s: %s", url, e)

    # Some servers reject HEAD — try GET with stream=True (no body download)
    try:
        resp = requests.get(
            url,
            allow_redirects=True,
            timeout=6,
            headers=_REQ_HEADERS,
            stream=True,
        )
        resp.close()
        final = resp.url
        if final and final.startswith(("http://", "https://")) and final != url:
            app.logger.info("Resolved (GET) %s -> %s", url, final)
            return final
    except Exception as e:
        app.logger.warning("GET resolve failed for %s: %s", url, e)

    return url  # fallback: use original


def _validate_image_magic(data: bytes) -> bool:
    return any(data[:len(m)] == m for m in MAGIC_BYTES)


def _hex_to_rgb(h: str) -> tuple:
    h = h.strip().lstrip("#")
    if not re.fullmatch(r"[0-9a-fA-F]{6}", h):
        return (0, 0, 0)
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


def _clamp(val, lo, hi):
    return max(lo, min(val, hi))


def _verify_token(req) -> bool:
    if not HISTORY_TOKEN:
        return False
    provided = req.headers.get("X-History-Token", "").strip()
    if not provided:
        return False
    return hmac.compare_digest(
        hashlib.sha256(provided.encode()).digest(),
        hashlib.sha256(HISTORY_TOKEN.encode()).digest(),
    )


def _shorten_with_fallback(url: str) -> str | None:
    """
    Try is.gd → v.gd → TinyURL in order.
    Returns short URL or None if all fail.
    """
    providers = [
        {
            "api":    "https://is.gd/create.php",
            "params": {"format": "simple", "url": url},
            "prefix": "https://is.gd/",
        },
        {
            "api":    "https://v.gd/create.php",
            "params": {"format": "simple", "url": url},
            "prefix": "https://v.gd/",
        },
        {
            "api":    "https://tinyurl.com/api-create.php",
            "params": {"url": url},
            "prefix": "https://tinyurl.com/",
        },
    ]
    for p in providers:
        try:
            resp = requests.get(
                p["api"],
                params=p["params"],
                timeout=8,
                headers={"User-Agent": "qreafy/1.0", "Accept": "text/plain"},
            )
            if resp.status_code == 200:
                short = resp.text.strip()
                if short.startswith(p["prefix"]):
                    return short
                app.logger.warning(
                    "Unexpected response from %s: %s", p["api"], short[:120]
                )
            else:
                app.logger.warning(
                    "HTTP %s from %s", resp.status_code, p["api"]
                )
        except Exception as e:
            app.logger.warning("Shortener %s failed: %s", p["api"], e)

    return None


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
        "X-Content-Type-Options":    "nosniff",
        "X-Frame-Options":           "DENY",
        "X-XSS-Protection":          "1; mode=block",
        "Referrer-Policy":           "strict-origin-when-cross-origin",
        "Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
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
    resp.headers.pop("Access-Control-Allow-Origin", None)
    return resp


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(PUBLIC_DIR, "index.html")

@app.route("/favicon.svg")
def favicon():
    return send_from_directory(PUBLIC_DIR, "favicon.svg")


@app.route("/api/generate-qr", methods=["POST"])
@limiter.limit("20 per minute; 100 per hour")
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
        qr_b64 = make_qr_base64(
            data, logo_bytes, size, border, fill_color, back_color, logo_ratio
        )
        return jsonify({"qr": qr_b64})
    except Exception:
        return jsonify({"error": "Error generando QR."}), 500


@app.route("/api/shorten-url", methods=["POST"])
@limiter.limit("10 per minute; 50 per hour")
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

    # ── Key fix: resolve URL shortener chains before shortening ──────────────
    # Services like maps.app.goo.gl, bit.ly, t.co etc. are themselves
    # shorteners. Third-party APIs (is.gd, TinyURL) reject them as anti-spam.
    # We follow redirects to get the real destination URL first.
    url_to_shorten = url
    if _is_shortener_domain(url):
        resolved = _resolve_url(url)
        safe2, _ = _is_safe_url(resolved)
        if safe2:
            url_to_shorten = resolved
            app.logger.info("Using resolved URL: %s", url_to_shorten)

    short = _shorten_with_fallback(url_to_shorten)
    if short is None:
        return jsonify({"error": "No se pudo acortar la URL. Intenta de nuevo."}), 500

    # Store the original URL the user entered (not the resolved one)
    item = {"short_url": short, "original_url": url}
    kv_push(item)
    return jsonify({**item, "kv": KV_AVAILABLE})


# ── History — protected by token ──────────────────────────────────────────────

@app.route("/api/history", methods=["GET"])
@limiter.limit("30 per minute")
def api_history():
    if not _verify_token(request):
        return jsonify({"error": "No autorizado."}), 401
    return jsonify({"history": kv_get_all(), "kv_available": KV_AVAILABLE})


@app.route("/api/history", methods=["DELETE"])
@limiter.limit("5 per minute")
def api_clear_history():
    if not _verify_token(request):
        return jsonify({"error": "No autorizado."}), 401
    if not KV_AVAILABLE:
        return jsonify({"error": "KV no disponible."}), 503
    try:
        _kv.delete(KV_KEY)
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"error": "No se pudo limpiar."}), 500


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(429)
def rate_limit_exceeded(_):
    return jsonify({"error": "Demasiadas solicitudes. Intenta más tarde."}), 429

@app.errorhandler(404)
def not_found(_):          return jsonify({"error": "Ruta no encontrada."}),   404
@app.errorhandler(405)
def method_not_allowed(_): return jsonify({"error": "Método no permitido."}), 405
@app.errorhandler(500)
def internal_error(_):     return jsonify({"error": "Error interno."}),        500
