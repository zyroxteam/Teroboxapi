#!/usr/bin/env python3
"""Teroboxapi — HTTP API wrapper around the TeraBox downloader core.

Endpoints
  GET  /health
  GET  /
  POST /api/login            {email, password}                 -> {session_id, host, ndus}
  POST /api/register/send    {email}                           -> {token}
  POST /api/register/finish  {email, token, code, password}    -> {session_id, host, ndus}
  POST /api/resolve          {url, session_id? | email,password?}
                                                    -> {host, surl, files:[{name,size,fs_id,dlink}]}
  GET  /api/links?url=&session_id=...            -> {files:[{name,dlink}]}
  GET  /api/download?url=&fs_id=&session_id=...  -> raw file stream (or email/password)

Sessions persist to disk (sessions.json + accounts.json): login once, restarts
keep working. Only a fresh redeploy clears them (ephemeral filesystem) — then
/api/login once again. Pass session_id, or email+password, whichever is convenient.
"""

import io
import json
import os
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

import core
from core import TBox, _cookie

CANON_URL = "https://www.1024tera.com/"

app = FastAPI(title="Teroboxapi", version="1.0.0",
              description="TeraBox share-link resolver & downloader API (pure Python).")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# ---- persistent session / account store ----------------------------------
# session_id -> {email, password, ndus, host}
# email      -> {password, ndus, host, updated}   (account cache)
# Both are saved to disk, so a restart/crash does NOT log you out.
# Only a fresh redeploy (ephemeral filesystem) clears them.
DATA_DIR = os.path.dirname(os.path.abspath(__file__))
SESSIONS_FILE = os.environ.get("SESSIONS_FILE", os.path.join(DATA_DIR, "sessions.json"))
ACCOUNTS_FILE = os.environ.get("ACCOUNTS_FILE", os.path.join(DATA_DIR, "accounts.json"))


def _load_json(path: str, fallback: dict) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else fallback
    except Exception:
        return fallback


def _store_json(path: str, obj: dict):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1)
        os.replace(tmp, path)
    except Exception as e:
        print(f"[store] save {os.path.basename(path)} failed: {e}", flush=True)


SESSIONS: dict = _load_json(SESSIONS_FILE, {})
ACCOUNTS: dict = _load_json(ACCOUNTS_FILE, {})
print(f"[store] restored {len(SESSIONS)} session(s), {len(ACCOUNTS)} account(s)", flush=True)


def _remember_account(email: str, password: str, ndus: str, host: str,
                      cookies: list = None, region_prefix: str = ""):
    """Cache a successful login so the session cookies are reused without re-login."""
    if not email:
        return
    ACCOUNTS[email] = {"password": password, "ndus": ndus, "host": host,
                       "cookies": cookies or [], "region_prefix": region_prefix,
                       "updated": int(time.time())}
    _store_json(ACCOUNTS_FILE, ACCOUNTS)


def _mask(email: str) -> str:
    name, _, dom = email.partition("@")
    return (name[:2] + "***@" + dom) if dom else "***"


class LoginReq(BaseModel):
    email: str
    password: str


class RegSendReq(BaseModel):
    email: str


class RegFinishReq(BaseModel):
    email: str
    token: str
    code: str
    password: str


class ResolveReq(BaseModel):
    url: str
    session_id: str = ""
    email: str = ""
    password: str = ""


def _new_sid(rec: dict) -> str:
    sid = uuid.uuid4().hex
    SESSIONS[sid] = rec
    _store_json(SESSIONS_FILE, SESSIONS)
    return sid


def _get_creds(body_session: str, body_email: str, body_password: str) -> dict:
    """Return a creds record: {email, password, ndus, host, cookies}."""
    if body_session:
        rec = SESSIONS.get(body_session)
        if not rec:
            raise HTTPException(401, "unknown or expired session_id — call /api/login first")
        return rec
    if body_email and body_password:
        rec = ACCOUNTS.get(body_email)
        if rec and rec.get("password") == body_password:
            return rec
        return {"email": body_email, "password": body_password, "ndus": "",
                "host": "", "cookies": None}
    raise HTTPException(400, "provide session_id (from /api/login) or email+password")


def _ensure_login(tbox: TBox, email: str, password: str, ndus: str,
                  cookies: list = None, region_prefix: str = "") -> bool:
    """Make sure tbox has a usable session. Returns True if we have one."""
    if ndus:
        tbox.set_ndus(ndus)
        if cookies:
            tbox.jar_load(cookies)
        if region_prefix:
            tbox.region_prefix = region_prefix
        tbox.refresh_tokens()  # session-bound jsToken for user APIs
        return True
    if email and password:
        ok, msg = tbox.login_full(email, password)
        if ok:
            _remember_account(email, password, _cookie(tbox.jar, "ndus"), tbox.host)
            return bool(_cookie(tbox.jar, "ndus"))
        raise HTTPException(401, f"login failed: {msg}")
    raise HTTPException(401, "no session and no credentials")


def _refresh_if_needed(tbox: TBox, email: str, password: str):
    """Re-login on the target host if the cached cookies stopped working."""
    ok, msg = tbox.login_full(email, password)
    if ok:
        ndus = _cookie(tbox.jar, "ndus")
        cookies = tbox.jar_dump()
        region = getattr(tbox, "region_prefix", None) or ""
        changed = False
        for sid, rec in SESSIONS.items():
            if rec.get("email") == email and rec.get("password") == password:
                rec["ndus"] = ndus
                rec["host"] = tbox.host
                rec["cookies"] = cookies
                rec["region_prefix"] = region
                changed = True
        if changed:
            _store_json(SESSIONS_FILE, SESSIONS)
        _remember_account(email, password, ndus, tbox.host, cookies, region)
        return True
    raise HTTPException(401, f"re-login failed: {msg}")


@app.get("/health")
def health():
    return {"status": "ok", "ts": int(time.time())}


@app.get("/")
def root():
    return {
        "service": "Teroboxapi",
        "version": "1.0.0",
        "endpoints": {
            "POST /api/login": "{email, password} -> {session_id, host, ndus}",
            "POST /api/register/send": "{email} -> {token}  (4-digit code emailed)",
            "POST /api/register/finish": "{email, token, code, password} -> {session_id}",
            "POST /api/resolve": "{url, session_id? | email,password?} -> {files:[...dlink]}",
            "GET  /api/links": "?url=&session_id= -> {files:[{name,dlink}]}",
            "GET  /api/download": "?url=&fs_id=&session_id= -> file stream",
            "GET  /api/sessions": "-> session/account store status (masked)",
        },
        "note": "Login once with /api/login — sessions persist to disk and survive restarts. "
                "ndus auto-refreshes silently with the stored account.",
    }


@app.post("/api/login")
def api_login(req: LoginReq):
    try:
        tbox = TBox(CANON_URL)
        ok, msg = tbox.login_full(req.email, req.password)
    except core.TBoxError as ex:
        raise HTTPException(502, f"terabox: {ex}")
    if not ok:
        raise HTTPException(401, msg)
    ndus = _cookie(tbox.jar, "ndus")
    cookies = tbox.jar_dump()
    region = getattr(tbox, "region_prefix", None) or ""
    sid = _new_sid({"email": req.email, "password": req.password,
                    "ndus": ndus, "host": tbox.host, "cookies": cookies,
                    "region_prefix": region})
    _remember_account(req.email, req.password, ndus, tbox.host, cookies, region)
    return {"ok": True, "session_id": sid, "host": tbox.host, "ndus": ndus}


@app.post("/api/register/send")
def api_register_send(req: RegSendReq):
    try:
        tbox = TBox(CANON_URL)
        ok, tok = tbox.register_sendcode(req.email)
    except core.TBoxError as ex:
        raise HTTPException(502, f"terabox: {ex}")
    if not ok:
        raise HTTPException(400, f"sendcode failed: {tok}")
    return {"ok": True, "token": tok,
            "note": f"a 4-digit code was sent to {req.email}; use it in /api/register/finish"}


@app.post("/api/register/finish")
def api_register_finish(req: RegFinishReq):
    try:
        tbox = TBox(CANON_URL)
        ok, msg, raw = tbox.register_verify(req.email, req.token, req.code)
    except core.TBoxError as ex:
        raise HTTPException(502, f"terabox: {ex}")
    if not ok:
        raise HTTPException(400, f"verify failed: {msg}")
    tok2 = (raw.get("data") or {}).get("token") or req.token
    ok2, msg2 = tbox.register_finish(req.email, tok2, req.password)
    if not ok2:
        raise HTTPException(400, f"finish failed: {msg2}")
    ndus = _cookie(tbox.jar, "ndus")
    if not ndus:
        ok3, msg3 = tbox.login_full(req.email, req.password)
        if not ok3:
            raise HTTPException(401, f"post-register login failed: {msg3}")
        ndus = _cookie(tbox.jar, "ndus")
    cookies = tbox.jar_dump()
    region = getattr(tbox, "region_prefix", None) or ""
    sid = _new_sid({"email": req.email, "password": req.password,
                    "ndus": ndus, "host": tbox.host, "cookies": cookies,
                    "region_prefix": region})
    _remember_account(req.email, req.password, ndus, tbox.host, cookies, region)
    return {"ok": True, "session_id": sid, "host": tbox.host, "ndus": ndus}


@app.get("/api/sessions")
def api_sessions():
    """Session/account store status (masked). Handy to confirm persistence."""
    return {
        "ok": True,
        "persistent": True,
        "sessions_file": os.path.basename(SESSIONS_FILE),
        "accounts_file": os.path.basename(ACCOUNTS_FILE),
        "sessions": len(SESSIONS),
        "accounts": [{"email": _mask(e), "host": r.get("host", ""),
                      "has_ndus": bool(r.get("ndus")),
                      "updated": r.get("updated")} for e, r in ACCOUNTS.items()],
        "note": "sessions survive restarts; only a redeploy clears them",
    }


def _dlink_with_fallback(tbox: TBox, data: dict, fid, name: str = ""):
    """share/download -> get_new_download_url -> save-to-drive -> filemetas."""
    notes = {}
    try:
        dl = tbox.get_share_dlink(data, fid)
    except Exception as ex:
        dl, notes["share_download"] = "", f"network: {ex}"
    if dl:
        return dl, "share_download", notes
    notes["share_download"] = getattr(tbox, "last_dlink_error", "")
    try:
        dl = tbox.get_dlink(fid, data.get("sign", ""), str(data.get("timestamp", "")))
    except Exception as ex:
        dl, notes["direct"] = "", f"network: {ex}"
    if dl:
        return dl, "direct", notes
    notes["direct"] = getattr(tbox, "last_dlink_error", "")
    try:
        tr = tbox.save_share_file(data, fid)
    except Exception as ex:
        tr, notes["transfer_net"] = {}, f"network: {ex}"
    notes["transfer_errno"] = tr.get("errno")
    new_fid = None
    if tr.get("errno") == 0:
        lst = ((tr.get("data") or {}).get("extra") or {}).get("list") or []
        if lst:
            new_fid = lst[0].get("to_fs_id") or lst[0].get("fs_id")
    elif tr.get("errno") == 12 and name:
        # already in drive from an earlier save — find it
        new_fid = tbox.find_in_drive(name)
        notes["found_in_drive"] = bool(new_fid)
    if new_fid:
        dl = tbox.get_dlink_filemetas(new_fid)
        if dl:
            return dl, "filemetas", notes
        notes["filemetas"] = getattr(tbox, "last_dlink_error", "")
    else:
        notes["transfer"] = tr
    return "", "failed", notes


@app.get("/api/debug/dlink")
def api_debug_dlink(url: str, fs_id: str = "", session_id: str = "",
                    email: str = "", password: str = ""):
    """Diagnose the whole dlink chain: direct -> transfer -> filemetas."""
    rec = _get_creds(session_id, email, password)
    e, p = rec.get("email", ""), rec.get("password", "")
    tbox = TBox(url, host=rec.get("host") or None)
    try:
        _ensure_login(tbox, e, p, rec.get("ndus", ""),
                      rec.get("cookies"), rec.get("region_prefix", ""))
        data = tbox.resolve_share()
    except core.TBoxError as ex:
        raise HTTPException(502, f"terabox: {ex}")
    lst = data.get("list") or []
    target = None
    for it in lst:
        if fs_id and str(it.get("fs_id")) == str(fs_id):
            target = it
            break
    if target is None:
        if len(lst) == 1:
            target = lst[0]
        else:
            raise HTTPException(400, "pass fs_id; files: " +
                                ",".join(str(i.get("fs_id")) for i in lst))
    fid = target.get("fs_id")
    name = target.get("server_filename") or "file"
    dl, how, notes = _dlink_with_fallback(tbox, data, fid, name)
    return {"ok": bool(dl), "via": how, "fs_id": fid, "dlink": dl,
            "notes": notes, "host": tbox.host, "final_url": tbox.final_url}


@app.get("/api/debug/raw")
def api_debug_raw(url: str, path: str, extra: str = "", session_id: str = "",
                  email: str = "", password: str = "", host: str = ""):
    """Fire an arbitrary GET at a whitelisted TeraBox API with session cookies.
    Placeholders in `extra`: {sign} {ts} {surl} {fid}"""
    rec = _get_creds(session_id, email, password)
    e, p = rec.get("email", ""), rec.get("password", "")
    allowed = {"/share/list", "/api/list", "/api/filemetas", "/api/download",
               "/file/get_new_download_url", "/share/verify", "/api/shorturlinfo",
               "/share/download"}
    if path not in allowed:
        raise HTTPException(400, f"path not allowed; one of {sorted(allowed)}")
    tbox = TBox(url, host=rec.get("host") or None)
    try:
        _ensure_login(tbox, e, p, rec.get("ndus", ""), rec.get("cookies"))
        if host:
            import http.cookiejar as cj
            ndus_v = rec.get("ndus", "")
            tbox.host = host
            tbox.final_url = f"https://{host}/sharing/link?surl=" + (tbox.final_url.split("surl=")[-1].split("&")[0] if "surl=" in tbox.final_url else "")
            tbox.jar = __import__("http.cookiejar", fromlist=["CookieJar"]).CookieJar()
            tbox.op = __import__("urllib.request", fromlist=["build_opener"]).build_opener(__import__("urllib.request", fromlist=["HTTPCookieProcessor"]).HTTPCookieProcessor(tbox.jar))
            tbox.set_ndus(ndus_v)
        data = tbox.resolve_share()
    except core.TBoxError as ex:
        raise HTTPException(502, f"terabox: {ex}")
    sign = data.get("sign", "")
    ts = str(data.get("timestamp", ""))
    surl = tbox.final_url.split("surl=")[-1].split("&")[0] if "surl=" in tbox.final_url else ""
    fid = ""
    lst = data.get("list") or []
    if lst:
        fid = str(lst[0].get("fs_id", ""))
    full = f"https://{tbox.host}{path}?{tbox.Q}&{extra}"
    for k, v in (("{sign}", sign), ("{ts}", ts), ("{surl}", surl), ("{fid}", fid)):
        full = full.replace(k, v)
    try:
        from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
        sp = urlsplit(full)
        full = urlunsplit((sp.scheme, sp.netloc, sp.path,
                           urlencode(parse_qsl(sp.query, keep_blank_values=True)), ""))
    except Exception:
        pass
    s, out, _ = tbox._http("GET", full, headers={"Referer": tbox.final_url})
    body = out.decode("utf-8", "ignore")
    return {"http": s, "requested": full[:300], "body": body[:20000]}


@app.post("/api/debug/login")
def api_debug_login(req: LoginReq):
    """Fresh login returning the RAW passport response + cookie names."""
    try:
        tbox = TBox(CANON_URL)
        ok, msg = tbox.login_full(req.email, req.password)
    except core.TBoxError as ex:
        raise HTTPException(502, f"terabox: {ex}")
    last = getattr(tbox, "_last_login_resp", None)
    return {"ok": ok, "msg": msg,
            "cookie_names": [c.name for c in tbox.jar],
            "login_resp": last}


@app.get("/api/debug/transfer")
def api_debug_transfer(url: str, session_id: str = "", email: str = "",
                       password: str = ""):
    """Try share/transfer param variants, return every raw result."""
    rec = _get_creds(session_id, email, password)
    e, p = rec.get("email", ""), rec.get("password", "")
    tbox = TBox(url, host=rec.get("host") or None)
    try:
        _ensure_login(tbox, e, p, rec.get("ndus", ""),
                      rec.get("cookies"), rec.get("region_prefix", ""))
        data = tbox.resolve_share()
    except core.TBoxError as ex:
        raise HTTPException(502, f"terabox: {ex}")
    lst = data.get("list") or []
    if not lst:
        raise HTTPException(404, "no files")
    fid = str(lst[0].get("fs_id", ""))
    shareid = str(data.get("shareid", ""))
    uk = str(data.get("uk", ""))
    randsk = data.get("randsk", "")
    import urllib.parse as up
    variants = {
        "int_list_to_path": {"shareid": shareid, "from": uk, "to": "/",
                             "fidlist": json.dumps([int(fid)]), "path": "/",
                             "sekey": randsk},
        "str_list_to": {"shareid": shareid, "from": uk, "to": "/",
                        "fidlist": json.dumps([fid]), "sekey": randsk},
        "path_only": {"shareid": shareid, "from": uk, "path": "/",
                      "fidlist": json.dumps([fid]), "sekey": randsk},
        "to_apps": {"shareid": shareid, "from": uk, "to": "/apps",
                    "fidlist": json.dumps([fid]), "sekey": randsk},
        "no_sekey": {"shareid": shareid, "from": uk, "to": "/",
                     "fidlist": json.dumps([fid])},
    }
    out = {}
    for name, form in variants.items():
        try:
            s, raw, _ = tbox._http(
                "POST", f"https://{tbox.api_host}/share/transfer?{tbox.Q}",
                data=up.urlencode(form).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "Origin": f"https://{tbox.host}"},
                referer=tbox.final_url)
            out[name] = {"http": s, "body": raw.decode("utf-8", "ignore")[:300]}
        except Exception as ex:
            out[name] = {"error": str(ex)}
    return {"fid": fid, "shareid": shareid, "uk": uk,
            "randsk_head": randsk[:24], "results": out}


@app.get("/api/debug/cookies")
def api_debug_cookies(url: str = "", session_id: str = "",
                      email: str = "", password: str = ""):
    """Cookie names held by the current session (values not returned)."""
    rec = _get_creds(session_id, email, password)
    names = [c.get("name") for c in (rec.get("cookies") or [])]
    return {"ok": True, "cookie_names": names,
            "count": len(names), "host": rec.get("host", ""),
            "region_prefix": rec.get("region_prefix", ""),
            "api_host_note": f"user APIs go to {rec.get('region_prefix') or 'www'}." +
                             (rec.get("host") or "").removeprefix("www.")}


def _resolve_with_creds(url: str, rec: dict, want_links: bool = True):
    email, password = rec.get("email", ""), rec.get("password", "")
    try:
        tbox = TBox(url, host=rec.get("host") or None)
        _ensure_login(tbox, email, password, rec.get("ndus", ""),
                      rec.get("cookies"), rec.get("region_prefix", ""))
    except core.TBoxError as e:
        raise HTTPException(502, f"terabox: {e}")
    lst = data.get("list") or []
    if not lst:
        raise HTTPException(404, "no files in this share")
    sign = data.get("sign", "")
    ts = str(data.get("timestamp", ""))
    files = []
    for it in lst:
        name = it.get("server_filename") or it.get("filename") or "file"
        fid = it.get("fs_id")
        size = it.get("size", 0)
        dlink = tbox.get_dlink(fid, sign, ts) if want_links else ""
        via = "direct" if dlink else ""
        dnotes = {}
        if want_links and not dlink and (email and password):
            # cached ndus may be stale -> re-login on this host and retry once
            try:
                _refresh_if_needed(tbox, email, password)
                rec["ndus"], rec["cookies"] = _cookie(tbox.jar, "ndus"), tbox.jar_dump()
                data = tbox.resolve_share()
                sign = data.get("sign", "")
                ts = str(data.get("timestamp", ""))
                dlink = tbox.get_dlink(fid, sign, ts)
                via = "direct" if dlink else ""
            except core.TBoxError:
                pass
        if want_links and not dlink:
            dlink, via, dnotes = _dlink_with_fallback(tbox, data, fid, name)
        files.append({
            "name": name,
            "size": size,
            "size_human": core.fmt_size(size),
            "fs_id": fid,
            "dlink": dlink,
            **({"via": via} if dlink else {}),
            **({"notes": dnotes} if (not dlink and dnotes) else {}),
        })
    surl = tbox.final_url.split("surl=")[-1].split("&")[0] if "surl=" in tbox.final_url else ""
    return {"ok": True, "host": tbox.host, "final_url": tbox.final_url,
            "surl": surl, "files": files}


@app.post("/api/resolve")
def api_resolve(req: ResolveReq):
    rec = _get_creds(req.session_id, req.email, req.password)
    return _resolve_with_creds(req.url, rec)


@app.get("/api/links")
def api_links(url: str, session_id: str = "", email: str = "", password: str = ""):
    rec = _get_creds(session_id, email, password)
    return _resolve_with_creds(url, rec)


@app.get("/api/download")
def api_download(url: str, fs_id: str = "", session_id: str = "",
                 email: str = "", password: str = ""):
    rec = _get_creds(session_id, email, password)
    e, p = rec.get("email", ""), rec.get("password", "")
    tbox = TBox(url, host=rec.get("host") or None)
    try:
        _ensure_login(tbox, e, p, rec.get("ndus", ""),
                      rec.get("cookies"), rec.get("region_prefix", ""))
        data = tbox.resolve_share()
    except core.TBoxError as ex:
        raise HTTPException(502, f"terabox: {ex}")
    lst = data.get("list") or []
    if not lst:
        raise HTTPException(404, "no files in this share")
    target = None
    for it in lst:
        if fs_id and str(it.get("fs_id")) == str(fs_id):
            target = it
            break
    if target is None:
        if len(lst) == 1:
            target = lst[0]
        else:
            raise HTTPException(400,
                                "multiple files — pass fs_id. ids: " +
                                ",".join(str(i.get("fs_id")) for i in lst))
    sign = data.get("sign", "")
    ts = str(data.get("timestamp", ""))
    fid = target.get("fs_id")
    name = target.get("server_filename") or target.get("filename") or "file"
    dlink, via, dnotes = _dlink_with_fallback(tbox, data, fid, name)
    if not dlink and (e and p):
        try:
            _refresh_if_needed(tbox, e, p)
            data = tbox.resolve_share()
            dlink, via, dnotes = _dlink_with_fallback(tbox, data, fid, name)
        except core.TBoxError:
            pass
    if not dlink:
        raise HTTPException(403, f"no download link ({via}: {json.dumps(dnotes, ensure_ascii=False)[:300]}) — re-login may help")

    req = urllib.request.Request(dlink, headers={
        "User-Agent": core.UA, "Referer": tbox.final_url,
        "Cookie": "; ".join(f"{c.name}={c.value}" for c in tbox.jar),
    })
    try:
        resp = tbox.op.open(req, timeout=120)
    except urllib.error.HTTPError as ex:
        raise HTTPException(502, f"download source HTTP {ex.code}")
    total = resp.headers.get("Content-Length")

    def gen():
        while True:
            chunk = resp.read(256 * 1024)
            if not chunk:
                break
            yield chunk

    headers = {
        "Content-Disposition": f'attachment; filename="{urllib.parse.quote(name)}"',
        "Accept-Ranges": "bytes",
    }
    if total:
        headers["Content-Length"] = total
    return StreamingResponse(gen(), media_type="application/octet-stream", headers=headers)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
