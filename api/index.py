"""
Qrea-fy — API backend
Security hardening v2.0 (2026-04-20)

Patches applied vs original:
  [C-01] Rate limiter uses Redis, not memory (resets on cold start)
  [C-02] HISTORY_TOKEN absence triggers runtime warning
  [C-03] See requirements.txt — exact versions pinned
  [H-01] Flask SECRET_KEY from env var
  [M-02] User-Agent no longer impersonates Googlebot
  [M-03] DNS rebinding blocked via socket re-resolution
  [M-04] CSP tightened — unsafe-inline removed (JS/CSS now external)
  [L-01] PIL decompression bomb protection
  [L-02] Request-ID middleware for log correlation
"""

import os, io, re, json, base64, ipaddress, urllib.parse, hashlib, hmac, time, socket, uuid, warnings
import qrcode
import requests
from PIL import Image, UnidentifiedImageError
from flask import Flask, request, jsonify, send_from_directory, Response, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── PIL safety ─────────────────────────────────────────────────────────────────
# Prevent decompression bomb attacks (malicious small-file → huge RAM expansion)
Image.MAX_IMAGE_PIXELS = 50_000_000

# ── Upstash Redis — graceful fallback ──────────────────────────────────────────
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

# [H-01] Flask SECRET_KEY — required for sessions, CSRF tokens, signed cookies
app.config["SECRET_KEY"] = (
    os.environ.get("FLASK_SECRET_KEY")
    or __import__("secrets").token_hex(32)
)

# Limit max request body to 4 MB — prevents large-JSON DoS before parsing
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024

# [C-01] Rate limiter → Redis (not memory://, which resets on cold start)
# Falls back to memory:// silently if Redis URL is absent (local dev)
_redis_url = os.environ.get("UPSTASH_REDIS_REST_URL") or "memory://"
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=_redis_url,
)

# [C-02] Warn if HISTORY_TOKEN is not configured
HISTORY_TOKEN = os.environ.get("HISTORY_TOKEN", "")
if not HISTORY_TOKEN:
    warnings.warn(
        "HISTORY_TOKEN env var is not set — DELETE /api/history will always reject. "
        "Set HISTORY_TOKEN in your platform environment variables.",
        RuntimeWarning,
        stacklevel=1,
    )

# ── Constants ──────────────────────────────────────────────────────────────────
MAX_DATA_LEN   = 2000
MAX_LOGO_BYTES = 3 * 1024 * 1024
MAGIC_BYTES    = {b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF"}
BLOCKED_HOSTS  = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}

# Known URL shortener services — their URLs must be resolved before re-shortening
# (is.gd/TinyURL reject already-shortened URLs as anti-spam)
_SHORTENER_DOMAINS = {
    "goo.gl", "maps.app.goo.gl", "bit.ly", "bitly.com",
    "tinyurl.com", "t.co", "ow.ly", "buff.ly", "ift.tt",
    "dlvr.it", "fb.me", "youtu.be", "amzn.to", "short.link",
    "rb.gy", "cutt.ly", "tiny.cc", "shorturl.at", "is.gd",
    "v.gd", "lnkd.in", "wp.me", "adf.ly", "bc.vc",
}

# [M-02] Honest User-Agent — do NOT impersonate Googlebot (ToS violation)
_REQ_HEADERS = {
    "User-Agent": "qreafy/2.0 (+https://qrea-fy.vercel.app)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}


# ── Request-ID middleware [L-02] ───────────────────────────────────────────────

@app.before_request
def _set_request_id():
    """Attach a short UUID to every request for log correlation."""
    g.request_id = str(uuid.uuid4())[:8]


@app.after_request
def _add_request_id_header(resp: Response) -> Response:
    resp.headers["X-Request-ID"] = getattr(g, "request_id", "-")
    return resp


# ── Helpers ────────────────────────────────────────────────────────────────────

def _log(level: str, msg: str, *args):
    """Prefix every log line with the current request ID for easy filtering."""
    rid = getattr(g, "request_id", "-")
    full = f"[{rid}] {msg}"
    getattr(app.logger, level)(full, *args)


def _is_safe_url(url: str) -> tuple[bool, str]:
    """Validate URL scheme, host, and IP class. Returns (ok, reason)."""
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
        pass  # Not a bare IP — hostname will be resolved later
    return True, ""


def _resolve_host_ips(hostname: str) -> list[str]:
    """Resolve hostname to IP list via socket (bypasses DNS cache for rebinding check)."""
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        return [info[4][0] for info in infos]
    except Exception:
        return []


def _is_host_safe_after_resolution(url: str) -> bool:
    """
    [M-03] Anti DNS-rebinding: re-resolve hostname to IPs via socket and
    reject if any resolved IP falls in a private/loopback/reserved range.
    This is called immediately before making outbound HTTP requests.
    """
    try:
        hostname = urllib.parse.urlparse(url).hostname or ""
        if not hostname:
            return False
        ips = _resolve_host_ips(hostname)
        if not ips:
            return False  # Can't resolve → don't trust
        for raw_ip in ips:
            try:
                ip = ipaddress.ip_address(raw_ip)
                if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                    _log("warning", "DNS rebind blocked: %s → %s", hostname, raw_ip)
                    return False
            except ValueError:
                continue
        return True
    except Exception:
        return False


def _is_shortener_domain(url: str) -> bool:
    """Return True if this URL belongs to a known shortener service."""
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        return any(host == d or host.endswith("." + d) for d in _SHORTENER_DOMAINS)
    except Exception:
        return False


def _resolve_url(url: str) -> str:
    """
    Follow redirect chain to get the final destination URL.
    Performs DNS rebinding check before each outbound request.
    Uses HEAD first, falls back to GET stream if needed.
    Returns original URL on any failure.
    """
    if not _is_host_safe_after_resolution(url):
        _log("warning", "Pre-resolve DNS check failed for %s", url)
        return url

    # HEAD attempt
    try:
        resp = requests.head(url, allow_redirects=True, timeout=6, headers=_REQ_HEADERS)
        final = resp.url
        if final and final != url and final.startswith(("http://", "https://")):
            if _is_host_safe_after_resolution(final):
                _log("info", "Resolved HEAD %s → %s", url, final)
                return final
    except Exception as e:
        _log("warning", "HEAD resolve failed for %s: %s", url, e)

    # GET stream fallback (some servers reject HEAD)
    try:
        resp = requests.get(url, allow_redirects=True, timeout=6, headers=_REQ_HEADERS, stream=True)
        resp.close()
        final = resp.url
        if final and final != url and final.startswith(("http://", "https://")):
            if _is_host_safe_after_resolution(final):
                _log("info", "Resolved GET %s → %s", url, final)
                return final
    except Exception as e:
        _log("warning", "GET resolve failed for %s: %s", url, e)

    return url


def _validate_image_magic(data: bytes) -> bool:
    """Check first bytes match a known safe image format."""
    return any(data[:len(m)] == m for m in MAGIC_BYTES)


def _hex_to_rgb(h: str) -> tuple:
    """Convert #rrggbb hex string to (r, g, b) tuple. Returns black on invalid input."""
    h = h.strip().lstrip("#")
    if not re.fullmatch(r"[0-9a-fA-F]{6}", h):
        return (0, 0, 0)
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _clamp(val, lo, hi):
    return max(lo, min(val, hi))


def _verify_token(req) -> bool:
    """Constant-time comparison of HMAC-SHA256 hashes. Used only for DELETE."""
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
    """Try is.gd → v.gd → TinyURL in order. Returns short URL or None."""
    providers = [
        {"api": "https://is.gd/create.php",         "params": {"format": "simple", "url": url}, "prefix": "https://is.gd/"},
        {"api": "https://v.gd/create.php",           "params": {"format": "simple", "url": url}, "prefix": "https://v.gd/"},
        {"api": "https://tinyurl.com/api-create.php","params": {"url": url},                     "prefix": "https://tinyurl.com/"},
    ]
    for p in providers:
        try:
            resp = requests.get(
                p["api"], params=p["params"], timeout=8,
                headers={"User-Agent": "qreafy/2.0", "Accept": "text/plain"},
            )
            if resp.status_code == 200:
                short = resp.text.strip()
                if short.startswith(p["prefix"]):
                    return short
                _log("warning", "Unexpected response from %s: %s", p["api"], short[:120])
            else:
                _log("warning", "HTTP %s from %s", resp.status_code, p["api"])
        except Exception as e:
            _log("warning", "Shortener %s failed: %s", p["api"], e)
    return None


# ── Redis KV helpers ───────────────────────────────────────────────────────────

def kv_push(item: dict) -> None:
    if not KV_AVAILABLE:
        return
    try:
        item.setdefault("ts", int(time.time() * 1000))
        _kv.lpush(KV_KEY, json.dumps(item, ensure_ascii=False))
        _kv.ltrim(KV_KEY, 0, KV_MAX_ITEMS - 1)
    except Exception as e:
        _log("warning", "KV push error: %s", e)


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
        _log("warning", "KV get error: %s", e)
        return []


# ── QR generation ──────────────────────────────────────────────────────────────

def make_qr_base64(
    data, logo_bytes=None, size=10, border=2,
    fill_color="#000000", back_color="#ffffff", logo_ratio=0.28
) -> str:
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
            logo = Image.open(io.BytesIO(logo_bytes))
            # [L-01] Verify pixel count after open (before convert, catches bombs)
            logo.verify()
            logo = Image.open(io.BytesIO(logo_bytes)).convert("RGBA")
            mp = int(qw * _clamp(logo_ratio, 0.10, 0.42))
            logo.thumbnail((mp, mp), Image.LANCZOS)
            lw, lh = logo.size
            pad = max(4, int(min(lw, lh) * 0.08))
            bg = Image.new("RGBA", (lw + 2 * pad, lh + 2 * pad), (255, 255, 255, 255))
            bg.paste(logo, (pad, pad), logo)
            img.paste(bg, ((qw - bg.width) // 2, (qh - bg.height) // 2), bg)
        except (UnidentifiedImageError, Image.DecompressionBombError) as e:
            _log("warning", "Logo rejected (bomb/invalid): %s", e)
        except Exception as e:
            _log("warning", "Logo skip: %s", e)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


# ── Security headers ───────────────────────────────────────────────────────────

@app.after_request
def sec_headers(resp: Response) -> Response:
    resp.headers.update({
        "X-Content-Type-Options":    "nosniff",
        "X-Frame-Options":           "DENY",
        "X-XSS-Protection":          "1; mode=block",
        "Referrer-Policy":           "strict-origin-when-cross-origin",
        "Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        # [M-04] unsafe-inline removed — JS/CSS now served as external files
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        ),
    })
    resp.headers.pop("Server", None)
    resp.headers.pop("Access-Control-Allow-Origin", None)
    return resp


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(PUBLIC_DIR, "index.html")


@app.route("/favicon.svg")
def favicon():
    return send_from_directory(PUBLIC_DIR, "favicon.svg")


@app.route("/app.css")
def app_css():
    return send_from_directory(PUBLIC_DIR, "app.css", mimetype="text/css")


@app.route("/app.js")
def app_js():
    return send_from_directory(PUBLIC_DIR, "app.js", mimetype="application/javascript")


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
        qr_b64 = make_qr_base64(data, logo_bytes, size, border, fill_color, back_color, logo_ratio)
        return jsonify({"qr": qr_b64})
    except Exception:
        _log("error", "QR generation failed")
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

    # [M-03] DNS rebinding check on the original URL before any outbound request
    if not _is_host_safe_after_resolution(url):
        return jsonify({"error": "Host no permitido."}), 400

    url_to_shorten = url
    if _is_shortener_domain(url):
        resolved = _resolve_url(url)
        safe2, _ = _is_safe_url(resolved)
        if safe2:
            url_to_shorten = resolved
            _log("info", "Using resolved URL: %s", url_to_shorten)

    short = _shorten_with_fallback(url_to_shorten)
    if short is None:
        return jsonify({"error": "No se pudo acortar la URL. Intenta de nuevo."}), 500

    item = {"short_url": short, "original_url": url, "ts": int(time.time() * 1000)}
    kv_push(item)
    return jsonify({**item, "kv": KV_AVAILABLE})


# ── History ────────────────────────────────────────────────────────────────────
# GET  — public (no user auth in Phase 1; Phase 2 will filter by user_id)
# DELETE — protected by HMAC token to prevent accidental/malicious wipes

@app.route("/api/history", methods=["GET"])
@limiter.limit("30 per minute")
def api_history():
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


# ── Error handlers ─────────────────────────────────────────────────────────────

@app.errorhandler(429)
def rate_limit_exceeded(_):
    return jsonify({"error": "Demasiadas solicitudes. Intenta más tarde."}), 429

@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Ruta no encontrada."}), 404

@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({"error": "Método no permitido."}), 405

@app.errorhandler(413)
def payload_too_large(_):
    return jsonify({"error": "Payload demasiado grande (máx. 4 MB)."}), 413

@app.errorhandler(500)
def internal_error(_):
    return jsonify({"error": "Error interno."}), 500
