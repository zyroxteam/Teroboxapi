# Teroboxapi

TeraBox share-link **resolver + downloader HTTP API** (pure Python, no browser).
Works with all TeraBox mirror domains (terabox.com, 1024tera.com, terabox.app,
4funbox.com, mirrobox.com, nephobox.com, terasharelink.com, ...).

Features: email+password login with **automatic slide-captcha solving**
(image analysis, retries), account registration via email code, share
resolution, direct `dlink` retrieval, and file streaming.

## Run locally

```bash
pip install -r requirements.txt
python main.py            # listens on 0.0.0.0:8000 (override with PORT env)
```

## API

### Auth (two ways)
* **Session**: `POST /api/login` -> `session_id` (in-memory; pass it on later calls)
* **Stateless**: pass `email` + `password` on each call

### Endpoints

| Method | Path | Body / query | Returns |
|--------|------|--------------|---------|
| GET | `/health` | – | `{status:"ok"}` |
| GET | `/` | – | endpoint list |
| POST | `/api/login` | `{email, password}` | `{session_id, host, ndus}` |
| POST | `/api/register/send` | `{email}` | `{token}` — 4-digit code emailed |
| POST | `/api/register/finish` | `{email, token, code, password}` | `{session_id, host, ndus}` |
| POST | `/api/resolve` | `{url, session_id? \| email,password?}` | `{host, surl, files:[{name,size,fs_id,dlink}]}` |
| GET | `/api/links` | `?url=&session_id=` | same file list (quick dlinks) |
| GET | `/api/download` | `?url=&fs_id=&session_id=` | raw file stream (Content-Disposition) |

### Examples

```bash
# login
curl -s -X POST localhost:8000/api/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@gmail.com","password":"pass"}'
# -> {"ok":true,"session_id":"abc123","host":"www.1024tera.com","ndus":"..."}

# resolve a share (get direct download links)
curl -s -X POST localhost:8000/api/resolve \
  -H 'content-type: application/json' \
  -d '{"url":"https://terabox.com/s/1AbCd...","session_id":"abc123"}'

# stream a file (fs_id optional when the share has a single file)
curl -s -o "Phone pe.apk" \
  "localhost:8000/api/download?url=https://terabox.com/s/1AbCd...&fs_id=652676776238843&session_id=abc123"
```

## Deploy

* **antideploy.com** — push this folder; it detects Python + requirements.txt
  and runs `main.py` (binds 0.0.0.0:$PORT).
* Any PaaS (Render/Railway/Koyeb): start command `python main.py`, set `PORT`.

## Notes

* Sessions live in memory — a redeploy clears them; `/api/login` again.
* Captcha solving is best-effort image analysis; rare puzzles auto-retry
  (up to 8 fresh puzzles) and may still need a second call.
* Core crypto (RSA-1024 password encryption, SHA1 prand, AES key unwrap)
  is 1024-bit RSA / pure-Python in `core.py` — no native deps beyond
  pillow + numpy.
