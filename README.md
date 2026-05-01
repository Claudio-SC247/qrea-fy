# Qrea-fy

**Generador de códigos QR personalizados y acortador de URLs** — sin registros, sin cuentas, listo para usar.

[![Deploy on Render](https://img.shields.io/badge/Deploy-Render-46CF8F?logo=render&logoColor=white)](https://qrea-fy.onrender.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Hardened_v2.3-green)](SECURITY.md)

---

## Demo

🌐 **[qrea-fy.onrender.com](https://qrea-fy.onrender.com)**

> El free tier de Render hiberna tras 15 min de inactividad. El primer request puede tardar ~30s en despertar el servidor.

---

## Características

### Generador de QR
- Colores personalizados (módulos y fondo)
- Logo central con drop-and-drop
- Control de tamaño de celda y margen
- Descarga en PNG o copia al portapapeles
- Modo claro / oscuro

### Acortador de URLs
- 3 proveedores con fallback automático: is.gd → v.gd → TinyURL
- Soporte para URLs ya acortadas (resuelve redirecciones antes de re-acortar)
- Historial híbrido: localStorage (instantáneo) + Redis KV (persistente)
- Contador de URLs acortadas hoy y en total

---

## Stack tecnológico

| Capa | Tecnología |
|------|-----------|
| Backend | Python 3.12 + Flask 3.0.3 |
| Servidor WSGI | Gunicorn 22.0.0 |
| Frontend | HTML5 + CSS3 + JavaScript ES6+ (sin frameworks) |
| Cache & Rate limiting | Upstash Redis |
| Hosting | Render (free tier) |
| Fuentes | Google Fonts (DM Mono + Outfit) |

---

## Seguridad

Protecciones implementadas:

- **DoS** — Rate limiting distribuido con Redis (fail-safe en memoria si Redis cae)
- **IP spoofing** — Usa `remote_addr` real de Render, ignora `X-Forwarded-For`
- **SSRF** — Validación de IP + re-resolución DNS anti-rebinding antes de cada request saliente
- **XSS** — CSP estricta sin `unsafe-inline`, JS y CSS en archivos externos
- **Filtración de datos** — `Cache-Control: no-store` en todas las APIs
- **Supply chain** — Dependencias con versiones exactas (`==`), esquemas peligrosos bloqueados
- **Pillow bombs** — `MAX_IMAGE_PIXELS` + `verify()` antes de procesar imágenes
- **Headers** — HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **Robots** — `/robots.txt` bloquea bots de las rutas `/api/`
- **Disclosure** — `/.well-known/security.txt` con canal de reporte

---

## Estructura del proyecto

```
qrea-fy/
├── api/
│   └── index.py          ← Backend Flask (hardened v2.3)
├── public/
│   ├── index.html        ← HTML sin JS/CSS inline
│   ├── app.css           ← Estilos (dark mode, responsivo)
│   ├── app.js            ← Lógica del frontend
│   └── favicon.svg
├── .gitignore
├── .python-version        → 3.12
├── CHANGELOG.md
├── Procfile               → gunicorn (Railway/Heroku)
├── README.md
├── render.yaml            → Deploy automático en Render
├── requirements.txt       → Dependencias con versiones exactas
```

---

## Deploy propio

### Opción 1 — Render (recomendado)

1. Fork este repositorio
2. Crear cuenta en [render.com](https://render.com) y conectar el repo
3. Render detecta `render.yaml` automáticamente y configura todo
4. Agregar manualmente en **Environment**:

| Variable | Cómo obtenerla |
|----------|----------------|
| `UPSTASH_REDIS_REST_URL` | [console.upstash.com](https://console.upstash.com) → Redis → REST URL |
| `UPSTASH_REDIS_REST_TOKEN` | Mismo dashboard → REST Token |

`FLASK_SECRET_KEY` e `HISTORY_TOKEN` se generan automáticamente.

### Opción 2 — Railway

```bash
# Instalar Railway CLI
npm install -g @railway/cli
railway login
railway init
railway up
```

### Opción 3 — Local

```bash
git clone https://github.com/Claudio-SC247/qrea-fy.git
cd qrea-fy
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Variables de entorno (opcional — el historial solo usará localStorage sin Redis)
export FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export HISTORY_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Iniciar
gunicorn api.index:app --bind 0.0.0.0:5000 --workers 1
# Abrir http://localhost:5000
```

---

## Variables de entorno

| Variable | Descripción | Obligatorio |
|----------|-------------|-------------|
| `FLASK_SECRET_KEY` | Clave para firmar cookies Flask | **Sí** |
| `HISTORY_TOKEN` | Protege `DELETE /api/history` (HMAC-SHA256) | **Sí** |
| `UPSTASH_REDIS_REST_URL` | Rate limiting distribuido + historial persistente | Recomendado |
| `UPSTASH_REDIS_REST_TOKEN` | Token de autenticación Upstash | Recomendado |

Generar valores seguros:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## API

### `POST /api/generate-qr`

Genera un QR como imagen PNG en base64.

**Body** (multipart/form-data):

| Campo | Tipo | Requerido | Descripción |
|-------|------|-----------|-------------|
| `data` | string | ✅ | URL o texto para el QR (máx. 2000 chars) |
| `fill_color` | string | No | Color de módulos hex `#000000` |
| `back_color` | string | No | Color de fondo hex `#ffffff` |
| `size` | int | No | Tamaño de celda px (4–25, default 10) |
| `border` | int | No | Margen en celdas (0–8, default 2) |
| `logo` | file | No | Imagen central PNG/JPG/GIF/WEBP (máx. 3 MB) |
| `logo_ratio` | float | No | Tamaño del logo relativo al QR (0.10–0.42) |

**Respuesta:**
```json
{ "qr": "<base64 PNG>" }
```

**Límites:** 20 req/min · 100 req/hora por IP

---

### `POST /api/shorten-url`

Acorta una URL usando is.gd → v.gd → TinyURL como fallback.

**Body** (application/json):
```json
{ "url": "https://ejemplo.com/ruta-muy-larga" }
```

**Respuesta:**
```json
{
  "short_url": "https://is.gd/abc123",
  "original_url": "https://ejemplo.com/ruta-muy-larga",
  "ts": 1714500000000
}
```

**Límites:** 10 req/min · 50 req/hora por IP

---

### `GET /api/history`

Retorna el historial global de URLs acortadas (máx. 100).

```json
{
  "history": [{ "short_url": "...", "original_url": "...", "ts": 1714500000000 }],
  "kv_available": true
}
```

**Límites:** 30 req/min por IP

---

### `DELETE /api/history`

Limpia el historial en Redis. Requiere header `X-History-Token`.

**Límites:** 5 req/min por IP

---

### `GET /api/history/export`

Descarga el historial completo como JSON. Requiere header `X-History-Token`.

---

### `GET /api/health`

```json
{ "status": "ok" }
```

---

## Roadmap

### Fase 1 — En progreso
- [x] Generador QR con colores y logo
- [x] Acortador de URLs con fallback
- [x] Historial híbrido localStorage + Redis
- [x] Dark mode
- [x] Hardening de seguridad (13 vectores)
- [x] Deploy en Render
- [ ] QR para WiFi, vCard y App Store
- [ ] Editor QR en tiempo real (debounce)
- [ ] PWA — app instalable
- [ ] CI/CD con GitHub Actions

### Fase 2 — Próxima
- [ ] Auth con Google / GitHub (OAuth)
- [ ] Historial por usuario
- [ ] QR dinámicos (URL editable sin reimprimir)
- [ ] Dashboard de estadísticas

### Fase 3 — Futuro
- [ ] Planes Pro ($9) y Teams ($29)
- [ ] API pública con créditos
- [ ] Bulk QR — sube CSV, descarga ZIP
- [ ] Dominios personalizados

---

## Changelog

Ver [`CHANGELOG.md`](CHANGELOG.md) para el historial completo de cambios y parches de seguridad.

---

## Contribuir

1. Fork el repo
2. Crea una rama: `git checkout -b feat/nombre-feature`
3. Commit con mensaje claro: `git commit -m "feat: descripción"`
4. Abre un Pull Request

Por favor revisa [`SECURITY.md`](SECURITY.md) antes de reportar problemas de seguridad.

---

## Licencia

MIT © 2026 [Claudio-SC247](https://github.com/Claudio-SC247)

---

*Construido con Flask · Desplegado en Render · Protegido con Upstash Redis*
