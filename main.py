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

Sessions are in-memory (single instance). Pass session_id, or email+password,
whichever is convenient.
"""

import io
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

# session_id -> {email, password, ndus, host}
SESSIONS: dict = {}


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
    return sid


def _get_creds(body_session: str, body_email: str, body_password: str):
    """Return (email, password, ndus) from a session id or inline creds."""
    if body_session:
        rec = SESSIONS.get(body_session)
        if not rec:
            raise HTTPException(401, "unknown or expired session_id — call /api/login first")
        return rec.get("email", ""), rec.get("password", ""), rec.get("ndus", "")
    if body_email and body_password:
        return body_email, body_password, ""
    raise HTTPException(400, "provide session_id (from /api/login) or email+password")


def _ensure_login(tbox: TBox, email: str, password: str, ndus: str) -> bool:
    """Make sure tbox has a usable ndus. Returns True if we have one."""
    if ndus:
        tbox.set_ndus(ndus)
        return True
    if email and password:
        ok, msg = tbox.login_full(email, password)
        if ok:
            return bool(_cookie(tbox.jar, "ndus"))
        raise HTTPException(401, f"login failed: {msg}")
    raise HTTPException(401, "no session and no credentials")


def _refresh_if_needed(tbox: TBox, email: str, password: str):
    """Re-login on the target host if the cached ndus stopped working."""
    ok, msg = tbox.login_full(email, password)
    if ok:
        ndus = _cookie(tbox.jar, "ndus")
        for sid, rec in SESSIONS.items():
            if rec.get("email") == email and rec.get("password") == password:
                rec["ndus"] = ndus
                rec["host"] = tbox.host
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
        },
        "note": "Pass session_id (from /api/login) or email+password on each call.",
    }


@app.post("/api/login")
def api_login(req: LoginReq):
    tbox = TBox(CANON_URL)
    ok, msg = tbox.login_full(req.email, req.password)
    if not ok:
        raise HTTPException(401, msg)
    ndus = _cookie(tbox.jar, "ndus")
    sid = _new_sid({"email": req.email, "password": req.password,
                    "ndus": ndus, "host": tbox.host})
    return {"ok": True, "session_id": sid, "host": tbox.host, "ndus": ndus}


@app.post("/api/register/send")
def api_register_send(req: RegSendReq):
    tbox = TBox(CANON_URL)
    ok, tok = tbox.register_sendcode(req.email)
    if not ok:
        raise HTTPException(400, f"sendcode failed: {tok}")
    return {"ok": True, "token": tok,
            "note": f"a 4-digit code was sent to {req.email}; use it in /api/register/finish"}


@app.post("/api/register/finish")
def api_register_finish(req: RegFinishReq):
    tbox = TBox(CANON_URL)
    ok, msg, raw = tbox.register_verify(req.email, req.token, req.code)
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
    sid = _new_sid({"email": req.email, "password": req.password,
                    "ndus": ndus, "host": tbox.host})
    return {"ok": True, "session_id": sid, "host": tbox.host, "ndus": ndus}


def _resolve_with_creds(url: str, email: str, password: str, ndus: str, want_links: bool = True):
    tbox = TBox(url)
    _ensure_login(tbox, email, password, ndus)
    data = tbox.resolve_share()
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
        if not dlink and (email and password):
            # cached ndus may be stale -> re-login on this host and retry once
            _refresh_if_needed(tbox, email, password)
            data = tbox.resolve_share()
            sign = data.get("sign", "")
            ts = str(data.get("timestamp", ""))
            dlink = tbox.get_dlink(fid, sign, ts)
        files.append({
            "name": name,
            "size": size,
            "size_human": core.fmt_size(size),
            "fs_id": fid,
            "dlink": dlink,
        })
    surl = tbox.final_url.split("surl=")[-1].split("&")[0] if "surl=" in tbox.final_url else ""
    return {"ok": True, "host": tbox.host, "final_url": tbox.final_url,
            "surl": surl, "files": files}


@app.post("/api/resolve")
def api_resolve(req: ResolveReq):
    email, password, ndus = _get_creds(req.session_id, req.email, req.password)
    return _resolve_with_creds(req.url, email, password, ndus)


@app.get("/api/links")
def api_links(url: str, session_id: str = "", email: str = "", password: str = ""):
    e, p, n = _get_creds(session_id, email, password)
    return _resolve_with_creds(url, e, p, n)


@app.get("/api/download")
def api_download(url: str, fs_id: str = "", session_id: str = "",
                 email: str = "", password: str = ""):
    e, p, n = _get_creds(session_id, email, password)
    tbox = TBox(url)
    _ensure_login(tbox, e, p, n)
    data = tbox.resolve_share()
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
    dlink = tbox.get_dlink(fid, sign, ts)
    if not dlink and (e and p):
        _refresh_if_needed(tbox, e, p)
        data = tbox.resolve_share()
        sign = data.get("sign", "")
        ts = str(data.get("timestamp", ""))
        dlink = tbox.get_dlink(fid, sign, ts)
    if not dlink:
        raise HTTPException(403, "no download link (login required / expired) — re-login")

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
