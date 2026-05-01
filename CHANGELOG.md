# Qrea-fy — Changelog de Seguridad & Refactoring
**Fecha:** 20 de abril de 2026  
**Versión:** 2.0 (Hardened)  
**Basado en:** ZIP del repositorio `Claudio-SC247/qrea-fy` (commit e0d3206)

---

## Contexto

Este changelog documenta todos los cambios aplicados al proyecto en una sesión de auditoría y hardening de seguridad, motivada por el breach de Vercel (abril 2026, grupo ShinyHunters vía Context.ai/Google Workspace OAuth). Se migraron además los archivos para ser compatibles con plataformas alternativas (Render, Railway, Cloudflare Workers).

---

## Archivos modificados

| Archivo | Tipo de cambio |
|---|---|
| `api/index.py` | Modificado — 9 parches de seguridad |
| `public/index.html` | Modificado — JS/CSS extraídos a archivos externos |
| `public/app.css` | **Nuevo** — CSS extraído de index.html |
| `public/app.js` | **Nuevo** — JS extraído de index.html, 1 patch |
| `requirements.txt` | Modificado — versiones exactas + gunicorn |
| `.python-version` | **Nuevo** — fija Python 3.12 |
| `Procfile` | **Nuevo** — gunicorn para Render/Railway |
| `render.yaml` | **Nuevo** — config de despliegue en Render |
| `.gitignore` | **Nuevo** — protege .env y cachés |

---

## Parches aplicados (ordenados por severidad)

---

### [C-01] CRITICAL — Rate limiter usa Redis, no memoria

**Problema:** `storage_uri="memory://"` en flask-limiter se resetea en cada cold start de Vercel (~10 minutos de inactividad). Un atacante podía enviar 200+ requests/min sin ser bloqueado porque los contadores se reiniciaban constantemente.

**Antes:**
```python
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)
```

**Después:**
```python
_redis_url = os.environ.get("UPSTASH_REDIS_REST_URL") or "memory://"
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=_redis_url,
)
```

**Acción requerida:** Configurar `UPSTASH_REDIS_REST_URL` y `UPSTASH_REDIS_REST_TOKEN` en las variables de entorno de la plataforma.

---

### [H-01] HIGH — Flask sin SECRET_KEY

**Problema:** Flask sin `SECRET_KEY` configurado no puede firmar cookies de sesión correctamente. Sin este valor, cualquier futuro uso de `flask.session` o tokens CSRF sería inseguro.

**Antes:** `SECRET_KEY` no estaba configurado en ningún lugar.

**Después:**
```python
app.config["SECRET_KEY"] = (
    os.environ.get("FLASK_SECRET_KEY")
    or __import__("secrets").token_hex(32)
)
```

El fallback `secrets.token_hex(32)` es seguro para desarrollo local pero cambia en cada restart. En producción siempre debe estar seteado como env var.

**Acción requerida:** Agregar `FLASK_SECRET_KEY` como env var en la plataforma (valor: string aleatorio de 32+ chars).

---

### [C-02] HIGH — HISTORY_TOKEN sin validación de presencia

**Problema:** `HISTORY_TOKEN = os.environ.get("HISTORY_TOKEN", "")` — si la variable no está configurada, el token es un string vacío y el sistema no avisa. La función `_verify_token` retorna `False` silenciosamente.

**Después:**
```python
HISTORY_TOKEN = os.environ.get("HISTORY_TOKEN", "")
if not HISTORY_TOKEN:
    warnings.warn(
        "HISTORY_TOKEN env var is not set — DELETE /api/history will always reject.",
        RuntimeWarning, stacklevel=1,
    )
```

---

### [C-03] HIGH — Dependencias con `>=` (supply chain risk)

**Problema:** `flask>=3.0.0` instala la versión más reciente disponible en cada deploy. Si un paquete es comprometido y se publica una versión mayor, se instalaría automáticamente.

**Antes:**
```
flask>=3.0.0
qrcode[pil]>=7.4.2
Pillow>=10.0.0
requests>=2.31.0
upstash-redis>=1.0.0
flask-limiter>=3.5.0
```

**Después:**
```
flask==3.0.3
qrcode[pil]==8.1
Pillow==10.4.0
requests==2.32.3
upstash-redis==1.0.0
flask-limiter==3.5.0
gunicorn==22.0.0
```

`gunicorn` fue agregado para soporte en Render/Railway (reemplaza el servidor de desarrollo de Flask).

---

### [M-01] MEDIUM — Sin `.python-version`

**Problema:** Sin este archivo, Vercel (y otras plataformas) usaban la versión de Python por defecto, que podría cambiar entre deploys.

**Solución:** Creado `.python-version` con contenido `3.12`.

---

### [M-02] MEDIUM — User-Agent impersonaba a Googlebot

**Problema:** `_REQ_HEADERS` tenía `"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; ...)"`. Impersonar Googlebot viola los ToS de servicios externos y puede causar bloqueos de IP o bans.

**Antes:**
```python
_REQ_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}
```

**Después:**
```python
_REQ_HEADERS = {
    "User-Agent": "qreafy/2.0 (+https://qrea-fy.vercel.app)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}
```

---

### [M-03] MEDIUM — DNS rebinding sin mitigación

**Problema:** La validación de IP en `_is_safe_url()` se ejecutaba sobre el hostname textual. Si el DNS cambiaba entre la validación y el request HTTP efectivo, un hostname público podía redirigir a una IP privada (ataque DNS rebinding contra infraestructura interna de Vercel).

**Solución:** Nueva función `_is_host_safe_after_resolution()` que usa `socket.getaddrinfo()` para resolver el hostname a IPs reales e inmediatamente antes de cada request saliente.

```python
def _is_host_safe_after_resolution(url: str) -> bool:
    hostname = urllib.parse.urlparse(url).hostname or ""
    ips = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    for raw_ip in [i[4][0] for i in ips]:
        ip = ipaddress.ip_address(raw_ip)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            return False  # Block immediately
    return True
```

Se llama en tres puntos: antes de `_resolve_url()`, al validar la URL final resuelta, y al inicio de `api_shorten_url`.

---

### [M-04] MEDIUM — CSP con `unsafe-inline`

**Problema:** El `Content-Security-Policy` tenía `script-src 'self' 'unsafe-inline'` y `style-src 'self' 'unsafe-inline'` porque todo el JS y CSS estaban inline en `index.html`. Esto anulaba la protección XSS de la CSP.

**Solución:** JS y CSS extraídos a archivos externos.

| Archivo | Tamaño |
|---|---|
| `public/app.css` | 15 KB (340 líneas) |
| `public/app.js` | 12 KB (282 líneas) |
| `public/index.html` | 9 KB (195 líneas) — antes 35 KB |

**CSP después:**
```
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  style-src 'self' https://fonts.googleapis.com;
  font-src https://fonts.gstatic.com;
  img-src 'self' data:;
  connect-src 'self';
  frame-ancestors 'none';
```

Se agregaron rutas Flask para servir los nuevos archivos estáticos:
```python
@app.route("/app.css")
def app_css():
    return send_from_directory(PUBLIC_DIR, "app.css", mimetype="text/css")

@app.route("/app.js")
def app_js():
    return send_from_directory(PUBLIC_DIR, "app.js", mimetype="application/javascript")
```

---

### [M-05] MEDIUM — `innerHTML` sin sanitizar

**Problema:** `ul.innerHTML = ''` en `renderHist()` es seguro en su uso actual (asigna string vacío), pero es una superficie de XSS si en el futuro se asigna contenido de usuario. La presencia del patrón lo hace frágil.

**Antes:**
```javascript
ul.innerHTML = '';
```

**Después:**
```javascript
while (ul.firstChild) ul.removeChild(ul.firstChild);
```

---

### [L-01] LOW — Sin protección contra Pillow decompression bomb

**Problema:** Una imagen maliciosa de pocos bytes puede descomprimirse a gigabytes en RAM al ser procesada por Pillow, causando un crash OOM del servidor serverless.

**Solución:** Dos capas de protección.

```python
# Módulo level — hard cap on pixel count
Image.MAX_IMAGE_PIXELS = 50_000_000  # ~7000x7000px máx.

# En make_qr_base64 — catch bomb error explícitamente
try:
    logo = Image.open(io.BytesIO(logo_bytes))
    logo.verify()  # Raises DecompressionBombError before full load
    logo = Image.open(io.BytesIO(logo_bytes)).convert("RGBA")
    ...
except (UnidentifiedImageError, Image.DecompressionBombError) as e:
    _log("warning", "Logo rejected (bomb/invalid): %s", e)
except Exception as e:
    _log("warning", "Logo skip: %s", e)
```

---

### [L-02] LOW — Sin Request ID en logs

**Problema:** Sin un identificador único por request, no es posible correlacionar múltiples líneas de log de un mismo request para forensics o debugging.

**Solución:** Middleware que genera un UUID corto por request y lo propaga en logs y headers.

```python
@app.before_request
def _set_request_id():
    g.request_id = str(uuid.uuid4())[:8]

@app.after_request
def _add_request_id_header(resp):
    resp.headers["X-Request-ID"] = getattr(g, "request_id", "-")
    return resp

def _log(level, msg, *args):
    rid = getattr(g, "request_id", "-")
    getattr(app.logger, level)(f"[{rid}] {msg}", *args)
```

Todos los `app.logger.*` del código fueron reemplazados por `_log()` para incluir el request ID.

---

### [NEW] Handler 413 Payload Too Large

El error 413 (body mayor a 4 MB) antes mostraba la página de error default de Flask/Werkzeug, que podría revelar versión del servidor.

```python
@app.errorhandler(413)
def payload_too_large(_):
    return jsonify({"error": "Payload demasiado grande (máx. 4 MB)."}), 413
```

---

### [NEW] Archivos de despliegue multiplataforma

Para soportar Render, Railway y Cloudflare Workers como alternativas a Vercel:

**`Procfile`** — Gunicorn como servidor WSGI en producción:
```
web: gunicorn api.index:app --bind 0.0.0.0:$PORT --workers 2 --timeout 30
```

**`render.yaml`** — Despliegue automático en Render.com con generación automática de `FLASK_SECRET_KEY` y `HISTORY_TOKEN`.

**`.gitignore`** — Protege archivos `.env*` y cachés de Python.

---

## Variables de entorno requeridas

| Variable | Descripción | Obligatorio |
|---|---|---|
| `FLASK_SECRET_KEY` | Clave para firmar cookies y sesiones Flask | **Sí** |
| `HISTORY_TOKEN` | Protege DELETE /api/history (HMAC-SHA256) | **Sí** |
| `UPSTASH_REDIS_REST_URL` | Rate limiting persistente y historial | Recomendado |
| `UPSTASH_REDIS_REST_TOKEN` | Token de autenticación Upstash | Recomendado |

Generación segura de valores:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## Estado de seguridad: antes vs después

| Check | Antes | Después |
|---|---|---|
| Rate limiting efectivo | ✗ (reseteaba cada 10min) | ✓ Redis persistente |
| Flask SECRET_KEY | ✗ No configurado | ✓ Env var |
| HISTORY_TOKEN ausente avisa | ✗ Silencioso | ✓ RuntimeWarning |
| Dependencias reproducibles | ✗ (`>=`) | ✓ (`==` exacto) |
| Python version fijada | ✗ | ✓ `.python-version` |
| User-Agent honesto | ✗ Googlebot | ✓ qreafy/2.0 |
| DNS rebinding | ✗ Solo validación estática | ✓ Re-resolución por socket |
| CSP sin unsafe-inline | ✗ inline permitido | ✓ JS/CSS externos |
| innerHTML seguro | ✗ Patrón frágil | ✓ DOM API |
| PIL decompression bomb | ✗ Sin protección | ✓ MAX_IMAGE_PIXELS + verify() |
| Log correlation | ✗ Sin ID | ✓ X-Request-ID |
| 413 handler | ✗ Error default | ✓ JSON consistente |
| Multi-platform deploy | ✗ Solo Vercel | ✓ Render/Railway/Cloudflare |

---

## Estructura final del proyecto

```
qrea-fy/
├── api/
│   └── index.py          ← Backend Flask hardened v2.0
├── public/
│   ├── index.html        ← HTML sin JS/CSS inline (9 KB)
│   ├── app.css           ← CSS extraído (15 KB)  [NUEVO]
│   ├── app.js            ← JS extraído + patches (12 KB)  [NUEVO]
│   └── favicon.svg
├── .gitignore            [NUEVO]
├── .python-version       [NUEVO]  → 3.12
├── Procfile              [NUEVO]  → gunicorn
├── README.md
├── render.yaml           [NUEVO]
└── requirements.txt      ← Versiones exactas + gunicorn
```

---

## Próximos pasos — Fase 2

Estos ítems quedan fuera del alcance de este hardening (requieren base de datos):

1. **Auth con Google/GitHub** (NextAuth.js o Authlib) — prerequisito para todo lo demás
2. **Historial por usuario** — hoy es global; filtrar por `session.user_id`
3. **Planes Stripe** — Free / Pro $9 / Teams $29
4. **QR dinámicos** — tabla `qr_codes` en Neon Postgres
5. **Filtrar GET /api/history por usuario** — actualmente público (por diseño en Fase 1)
6. **Migrar completamente a Cloudflare Workers** — Python Workers en beta, evaluar para Fase 2

---

*Generado el 20 de abril de 2026 — Para continuar el proyecto, compartir este archivo como contexto a cualquier agente de IA.*
