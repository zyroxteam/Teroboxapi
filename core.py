#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
terabox_dl.py — TeraBox share-link downloader for Termux / Linux / anywhere.

Features
  * Login with email + password (full 2026 passport flow, pure Python)
  * Automatic slide-captcha solving (no browser needed)
  * New account registration via email verification code
  * Download share files with progress bar: percent, speed, ETA, resume

Dependencies:  Python 3.8+ ,  pillow ,  numpy     (pip install pillow numpy)
Termux:        pkg install python && pip install pillow numpy

Usage
  python terabox_dl.py <share_url>              # download (logs in if needed)
  python terabox_dl.py --login   EMAIL PASS     # login and cache session
  python terabox_dl.py --register EMAIL PASS    # create account (email code)
  python terabox_dl.py --cookie NDUS_VALUE      # use an existing ndus cookie
  python terabox_dl.py --logout                 # forget cached session
  options: -o DIR   (output dir, default ./terabox_downloads)
           --no-captcha (never auto-solve; only works without captcha)

A cached session (email + password) is stored in ~/.terabox_session.json
so that a future ndus expiry is handled automatically by re-login.
"""

import argparse
import base64
import hashlib
import io
import json
import math
import os
import random
import re
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from http.cookiejar import CookieJar

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36")
SESSION_FILE = os.path.expanduser("~/.terabox_session.json")
APP_ID = "250528"
PASS_VERSION = "2.8"

class TBoxError(RuntimeError):
    """Raised on fatal TeraBox errors (was sys.exit in the CLI days)."""

# ----------------------------------------------------------------------------
# tiny console helpers
# ----------------------------------------------------------------------------
def info(*a):
    print(*a, flush=True)

def die(msg, code=1):
    print("ERROR: " + msg, file=sys.stderr, flush=True)
    raise TBoxError(msg)

def hr():
    print("-" * 60, flush=True)

# ----------------------------------------------------------------------------
# pure-python AES-128 (decrypt only, CBC) — used to unwrap the RSA public key
# ----------------------------------------------------------------------------
_AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

def _aes_key_expand_128(key):
    sbox = _AES_SBOX
    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
            0x6C, 0xD8, 0xAB, 0x4D]
    w = [list(key[4*i:4*i+4]) for i in range(4)]
    for i in range(4, 44):
        t = w[i-1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [sbox[b] for b in t]
            t[0] ^= rcon[i//4 - 1]
        w.append([a ^ b for a, b in zip(w[i-4], t)])
    return w

def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def _aes_decrypt_block(block, w):
    inv_sbox = bytearray(256)
    for i, v in enumerate(_AES_SBOX):
        inv_sbox[v] = i
    st = [[block[4*c + r] for r in range(4)] for c in range(4)]  # st[c][r]

    def add_round_key(rk_idx):
        for c in range(4):
            for r in range(4):
                st[c][r] ^= w[rk_idx + c][r]

    def inv_shift_rows():
        for r in range(1, 4):
            tmp = [st[c][r] for c in range(4)]
            for c in range(4):
                st[c][r] = tmp[(c - r) % 4]

    def inv_sub_bytes():
        for c in range(4):
            for r in range(4):
                st[c][r] = inv_sbox[st[c][r]]

    def inv_mix_columns():
        for c in range(4):
            a = [st[c][r] for r in range(4)]
            st[c][0] = _gmul(a[0],14) ^ _gmul(a[1],11) ^ _gmul(a[2],13) ^ _gmul(a[3],9)
            st[c][1] = _gmul(a[0],9)  ^ _gmul(a[1],14) ^ _gmul(a[2],11) ^ _gmul(a[3],13)
            st[c][2] = _gmul(a[0],13) ^ _gmul(a[1],9)  ^ _gmul(a[2],14) ^ _gmul(a[3],11)
            st[c][3] = _gmul(a[0],11) ^ _gmul(a[1],13) ^ _gmul(a[2],9)  ^ _gmul(a[3],14)

    add_round_key(10*4)
    for rnd in range(9, 0, -1):
        inv_shift_rows()
        inv_sub_bytes()
        add_round_key(rnd*4)
        inv_mix_columns()
    inv_shift_rows()
    inv_sub_bytes()
    add_round_key(0)
    return bytes(st[c][r] for c in range(4) for r in range(4))

def aes128_cbc_decrypt(data, key, iv=b"\x00" * 16):
    w = _aes_key_expand_128(key)
    out = b""
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i+16]
        dec = _aes_decrypt_block(blk, w)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return out

# ----------------------------------------------------------------------------
# pure-python RSA (public encrypt, PKCS#1 v1.5)
# ----------------------------------------------------------------------------
def rsa_encrypt_pkcs1v15(plain: bytes, n: int, e: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    if len(plain) > k - 11:
        raise ValueError("message too long for RSA key")
    ps = bytearray()
    while len(ps) < k - len(plain) - 3:
        ps.append(random.randrange(1, 255))
    em = b"\x00\x02" + bytes(ps) + b"\x00" + plain
    m = int.from_bytes(em, "big")
    c = pow(m, e, n)
    return c.to_bytes(k, "big")

def _der_int(b, o):
    if b[o] != 0x02:
        raise ValueError("not an INTEGER")
    o += 1
    ln = b[o]; o += 1
    if ln & 0x80:
        nl = ln & 0x7F
        ln = int.from_bytes(b[o:o+nl], "big"); o += nl
    v = int.from_bytes(b[o:o+ln], "big"); o += ln
    return v, o

def _der_skip(b, o):
    """skip one DER element starting at tag position o; return new offset"""
    o += 1
    ln = b[o]; o += 1
    if ln & 0x80:
        nl = ln & 0x7F
        ln = int.from_bytes(b[o:o+nl], "big"); o += nl
    return o + ln

def parse_rsa_public(material: bytes):
    """Accept PEM (PKCS#1 or SPKI), DER, or raw hex 'Nhex||ehex'."""
    if material[:5] == b"-----":
        material = base64.b64decode(re.sub(r"-----[^-]*-----|\s", "", material.decode()))
    if len(material) >= 260 and all(c in b"0123456789abcdefABCDEF" for c in material):
        try:
            hx = material.decode()
            n = int(hx[:256], 16)
            e = int(hx[256:256 + min(64, len(hx) - 256)], 16)
            if e.bit_length() <= 32:
                return n, e
        except ValueError:
            pass
    if material[0] == 0x30:
        o = _der_skip_peek(material)
        if material[o] == 0x02:            # PKCS#1 { n, e }
            n, o2 = _der_int(material, o)
            e, _ = _der_int(material, o2)
            return n, e
        if material[o] == 0x30:            # SPKI { alg, bitstring { n, e } }
            o = _der_skip(material, o)     # skip algorithm sequence
            if material[o] != 0x03:
                raise ValueError("no BIT STRING")
            o = _der_skip(material, o)     # skip bitstring header -> inside
            n, o2 = _der_int(material, o)
            e, _ = _der_int(material, o2)
            return n, e
    raise ValueError("cannot parse RSA public key material")

def _der_skip_peek(b):
    o = 1
    ln = b[o]; o += 1
    if ln & 0x80:
        nl = ln & 0x7F
        ln = int.from_bytes(b[o:o+nl], "big"); o += nl
    return o

# ----------------------------------------------------------------------------
# TeraBox API session
# ----------------------------------------------------------------------------
class TBox:
    def __init__(self, share_url, host=None):
        self.jar = CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.host = None
        self.js_token = None
        self.pcf_token = None
        self.final_url = None
        self.pp1 = self.pp2 = None
        self.rsa_n = self.rsa_e = None
        self.force_host = host or None
        self._resolve_share(share_url)

    def _http(self, method, url, data=None, headers=None, referer=None, timeout=45):
        body = data.encode() if isinstance(data, str) else data
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("User-Agent", UA)
        req.add_header("Accept", "*/*")
        if referer:
            req.add_header("Referer", referer)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            r = self.op.open(req, timeout=timeout)
            return r.status, r.read(), r.geturl()
        except urllib.error.HTTPError as e:
            return e.code, e.read(), url

    def _resolve_share(self, share_url):
        """Follow the share link to the final host and extract page tokens."""
        if self.force_host:
            # Pin every request to the session's host so cookies match the login.
            m = re.search(r"/s/([A-Za-z0-9]+)", share_url)
            surl = m.group(1) if m else ""
            if "surl=" in share_url:
                surl = share_url.split("surl=")[-1].split("&")[0]
            if surl.startswith("1") and len(surl) > 20:
                surl = surl[1:]
            target = f"https://{self.force_host}/sharing/link?surl={surl}"
            s, html, final = self._http("GET", target, headers={"Accept": "text/html"})
            if s == 200:
                txt = html.decode("utf-8", "ignore")
                m = re.search(r'fn%28%22([A-Fa-f0-9]+)', txt)
                self.js_token = m.group(1) if m else ""
                m = re.search(r'"pcftoken":"([a-f0-9]{32})"', txt)
                self.pcf_token = m.group(1) if m else ""
                if not (self.js_token and self.pcf_token):
                    m = re.search(r'jsToken["\s:=]+([A-Fa-f0-9]{32,128})', txt)
                    self.js_token = self.js_token or (m.group(1) if m else "")
                    m = re.search(r'pcftoken["\s:=]+([a-f0-9]{32})', txt)
                    self.pcf_token = self.pcf_token or (m.group(1) if m else "")
                if self.js_token and self.pcf_token:
                    self.host = self.force_host
                    self.final_url = final
                    return
            # forced host failed -> fall through to the redirect chain
        s, html, final = self._http("GET", share_url, headers={"Accept": "text/html"})
        if s != 200:
            die(f"share page HTTP {s} (link may be dead)")
        txt = html.decode("utf-8", "ignore")
        m = re.search(r'fn%28%22([A-Fa-f0-9]+)', txt)
        self.js_token = m.group(1) if m else ""
        m = re.search(r'"pcftoken":"([a-f0-9]{32})"', txt)
        self.pcf_token = m.group(1) if m else ""
        if not (self.js_token and self.pcf_token):
            # fallback token patterns
            m = re.search(r'jsToken["\s:=]+([A-Fa-f0-9]{32,128})', txt)
            self.js_token = self.js_token or (m.group(1) if m else "")
            m = re.search(r'pcftoken["\s:=]+([a-f0-9]{32})', txt)
            self.pcf_token = self.pcf_token or (m.group(1) if m else "")
        if not (self.js_token and self.pcf_token):
            die("could not extract jsToken/pcftoken from share page")
        self.host = urllib.parse.urlparse(final).hostname
        self.final_url = final

    @property
    def Q(self):
        return f"app_id={APP_ID}&web=1&channel=dubox&clienttype=0&jsToken={self.js_token}"

    def _form(self, **extra):
        base = {
            "client": "web", "pass_version": PASS_VERSION, "lang": "en",
            "clientfrom": "h5", "pcftoken": self.pcf_token,
        }
        base.update(extra)
        base["psign"] = "0"
        return urllib.parse.urlencode(base)

    def _post(self, path, form):
        h = {"Content-Type": "application/x-www-form-urlencoded",
             "Origin": f"https://{self.host}"}
        s, out, _ = self._http("POST", f"https://{self.host}{path}?{self.Q}",
                               data=form, headers=h, referer=self.final_url)
        try:
            return json.loads(out.decode("utf-8", "ignore"))
        except Exception:
            return {"code": s, "msg": out.decode("utf-8", "ignore")[:300]}

    # ---- crypto -----------------------------------------------------------
    def gain_public_key(self):
        if self.rsa_n:
            return
        r = self._post("/passport/getpubkey", self._form())
        if r.get("code") != 0:
            die(f"getpubkey failed: {r}")
        d = r["data"]
        self.pp1, self.pp2 = d["pp1"], d["pp2"]
        p1_std = self.pp1.replace("-", "+").replace("_", "/")
        key = self.pp2.replace("_", "/").replace("-", "+").encode()
        iv = p1_std[:16].encode()
        ct = base64.b64decode(p1_std[16:])
        material = aes128_cbc_decrypt(ct, key, iv)
        material = material.rstrip(b"\x00")
        self.rsa_n, self.rsa_e = parse_rsa_public(material)

    def encrypt_pwd(self, password: str) -> str:
        self.gain_public_key()
        md5 = hashlib.md5(password.encode()).hexdigest()
        v = md5 + str(len(md5))          # dataSubstitutev
        ct = rsa_encrypt_pkcs1v15(v.encode(), self.rsa_n, self.rsa_e)
        return base64.b64encode(ct).decode().replace("+", "-").replace("/", "_")

    def browser_id(self):
        for c in self.jar:
            if c.name == "browserid":
                return c.value
        return ""

    # ---- login ------------------------------------------------------------
    def login(self, email, password, use_captcha=True):
        r = self._post("/passport/prelogin",
                       self._form(email=email))
        if r.get("code") != 0:
            die(f"prelogin failed: {r}")
        d = r["data"]
        return self._login_attempt(email, password, d, use_captcha)

    def _login_attempt(self, email, password, pre, use_captcha=True, captcha_token=""):
        self.gain_public_key()
        pwd = self.encrypt_pwd(password)
        prand = hashlib.sha1(
            f"web-{pre['seval']}-{pwd}-{email}-{self.browser_id()}-{pre['random']}".encode()
        ).hexdigest()
        form = {
            "client": "web", "pass_version": PASS_VERSION, "lang": "en",
            "clientfrom": "h5", "pcftoken": self.pcf_token,
            "prand": prand, "email": email, "pwd": pwd,
            "seval": str(pre["seval"]), "random": str(pre["random"]),
            "identity": "", "g_identity": "",
            "vcode": captcha_token if not captcha_token or use_captcha == "vcode" else "",
            "vcode_str": captcha_token,
            "timestamp": str(pre["timestamp"]),
            "need_merge": "0", "op_type": "2", "reg_source": "share",
            "first_referer": "", "psign": "0",
        }
        h = {"Content-Type": "application/x-www-form-urlencoded",
             "Origin": f"https://{self.host}"}
        s, out, _ = self._http("POST", f"https://{self.host}/passport/login?{self.Q}",
                               data=urllib.parse.urlencode(form), headers=h,
                               referer=self.final_url)
        resp = json.loads(out.decode("utf-8", "ignore"))
        self._last_login_resp = resp
        return resp

    def solve_captcha_once(self, relation_logid):
        """Fetch a slide challenge, solve it, submit. Returns (ok, token|msg)."""
        t = int(time.time() * 1000)
        s, out, _ = self._http(
            "GET", f"https://{self.host}/captcha/getslide?type=dragdrop&_t={t}",
            headers={"Accept": "application/json"}, referer=self.final_url)
        if s != 200:
            return False, f"getslide HTTP {s}"
        g = json.loads(out.decode())
        if g.get("errno") != 0:
            return False, f"getslide errno {g.get('errno')}"
        d = g["data"]
        master = _img_from_datauri(d["master_image"])
        piece = _img_from_datauri(d["tile_image"])
        cx, cy = solve_slide(master, piece)
        tile_w, tile_h = d.get("tile_width", 64), d.get("tile_height", 64)
        dx = int(round(cx - (d["tile_x"] + tile_w / 2.0)))
        dy = int(round(cy - (d["tile_y"] + tile_h / 2.0)))
        boundary = "----WebKitFormBoundary" + hashlib.md5(os.urandom(8)).hexdigest()
        fields = {
            "challenge_id": d["challenge_id"], "delta_x": str(dx), "delta_y": str(dy),
            "type": "dragdrop", "lang": "en",
            "relation_logid": str(relation_logid or d.get("relation_logid") or ""),
            "platform": "web",
        }
        body = b""
        for k, v in fields.items():
            body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").encode()
        body += f"--{boundary}--\r\n".encode()
        s, out, _ = self._http(
            "POST", f"https://{self.host}/captcha/checkslide", data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            referer=self.final_url)
        try:
            r = json.loads(out.decode())
        except Exception:
            return False, f"checkslide HTTP {s}"
        if r.get("errno") == 0:
            return True, r["data"]["capt_token"]
        return False, r.get("show_msg") or f"errno {r.get('errno')}"

    def login_full(self, email, password, max_captchas=8):
        """Login with automatic slide-captcha retries. Returns (ok, msg)."""
        r = self._post("/passport/prelogin", self._form(email=email))
        if r.get("code") != 0:
            return False, f"prelogin failed: {r}"
        pre = r["data"]
        for attempt in range(1, max_captchas + 1):
            resp = self._login_attempt(email, password, pre)
            err = resp.get("errno", resp.get("code"))
            if err == 0 or (err not in (460030, 460020) and "dragdrop" not in str(resp.get("errmsg", ""))):
                ndus = _cookie(self.jar, "ndus")
                if ndus:
                    return True, "ok"
                return False, f"login response without ndus: {resp}"
            if (resp.get("errmsg") == "dragdrop" or err in (460030, 460020)
                    or "dragdrop" in str(resp.get("errmsg", ""))
                    or "need verify" in str(resp.get("errmsg", ""))):
                logid = resp.get("request_id_string") or resp.get("request_id")
                print(f"  [captcha] attempt {attempt}/{max_captchas} ...", flush=True)
                ok, tok = self.solve_captcha_once(logid)
                if ok:
                    resp2 = self._login_attempt(email, password, pre, captcha_token=tok)
                    err2 = resp2.get("errno", resp2.get("code"))
                    if err2 == 0 or _cookie(self.jar, "ndus"):
                        return True, "ok (captcha passed)"
                    if err2 in (460030, 460020):
                        # try token in the other field
                        pre2 = self._post("/passport/prelogin", self._form(email=email))["data"]
                        resp3 = self._login_attempt(email, password, pre2, use_captcha="vcode",
                                                    captcha_token=tok)
                        if resp3.get("errno") in (0, None) and _cookie(self.jar, "ndus"):
                            return True, "ok (captcha passed, vcode field)"
                        print(f"  [captcha] token rejected ({resp3.get('msg') or resp3.get('errmsg')}) — new challenge", flush=True)
                        pre = pre2
                        continue
                    return False, f"after captcha: {resp2}"
                else:
                    print(f"  [captcha] solve failed: {tok}", flush=True)
                    time.sleep(1.2)
                    continue
            if resp.get("msg") == "user not exist" or err == 44:
                return False, "user not exist (account not registered)"
            return False, f"login error: {resp}"
        return False, "captcha: too many failures"

    # ---- registration -----------------------------------------------------
    def register_sendcode(self, email):
        r = self._post("/passport/register_v4/sendcode",
                       self._form(reg_source="share", email=email, op_type="1",
                                  koltype="0", g_identity="", first_referer=""))
        if r.get("code") == 0:
            return True, r.get("token", "")
        return False, r.get("msg") or str(r)

    def register_verify(self, email, token, code):
        r = self._post("/passport/register_v4/verify",
                       self._form(token=token, g_identity="", skip_code="0", code=code))
        return (r.get("code") == 0), (r.get("msg") or str(r)), r

    def register_finish(self, email, token, password):
        self.gain_public_key()
        pwd = self.encrypt_pwd(password)
        r = self._post("/passport/register_v4/finish",
                       self._form(token=token, pwd=pwd, g_identity="",
                                  membership_info="1", reg_source="share"))
        if r.get("code") == 0:
            return True, "ok"
        return False, r.get("msg") or str(r)

    # ---- download flow ----------------------------------------------------
    def get_session_cookie_names(self):
        return {c.name: c.value for c in self.jar}

    def set_ndus(self, ndus):
        import http.cookiejar as cj
        c = cj.Cookie(version="0", name="ndus", value=ndus, port=None,
                      port_specified=False, domain=self.host, domain_specified=True,
                      domain_initial_dot=False, path="/", path_specified=True,
                      secure=False, expires=int(time.time()) + 86400 * 30,
                      discard=False, comment=None, comment_url=None, rest={}, rfc2109=False)
        self.jar.set_cookie(c)

    def jar_dump(self):
        """Serialize the whole cookie jar (ndus alone is not enough for user APIs)."""
        out = []
        for c in self.jar:
            out.append({"name": c.name, "value": c.value, "domain": c.domain,
                        "path": c.path or "/", "expires": c.expires})
        return out

    def jar_load(self, cookies):
        """Restore a serialized cookie jar."""
        import http.cookiejar as cj
        for c in cookies or []:
            try:
                dom = c.get("domain") or self.host or ""
                jar_c = cj.Cookie(version=0, name=c["name"], value=c["value"],
                                  port=None, port_specified=False, domain=dom,
                                  domain_specified=True,
                                  domain_initial_dot=dom.startswith("."),
                                  path=c.get("path") or "/", path_specified=True,
                                  secure=False,
                                  expires=c.get("expires") or int(time.time()) + 86400 * 30,
                                  discard=False, comment=None, comment_url=None,
                                  rest={}, rfc2109=False)
                self.jar.set_cookie(jar_c)
            except Exception as e:
                print(f"[jar_load] skip {c.get('name')}: {e}", flush=True)

    def refresh_tokens(self):
        """Re-fetch the share page WITH session cookies — user APIs need a
        jsToken minted for the logged-in session, not an anonymous one."""
        if not self.final_url:
            return False
        try:
            s, html, final = self._http("GET", self.final_url,
                                        headers={"Accept": "text/html"})
        except Exception:
            return False
        if s != 200:
            return False
        txt = html.decode("utf-8", "ignore")
        m = re.search(r'fn%28%22([A-Fa-f0-9]+)', txt)
        tok = m.group(1) if m else ""
        m = re.search(r'"pcftoken":"([a-f0-9]{32})"', txt)
        pcf = m.group(1) if m else ""
        if not (tok and pcf):
            m2 = re.search(r'jsToken["\s:=]+([A-Fa-f0-9]{32,128})', txt)
            tok = tok or (m2.group(1) if m2 else "")
            m2 = re.search(r'pcftoken["\s:=]+([a-f0-9]{32})', txt)
            pcf = pcf or (m2.group(1) if m2 else "")
        if tok:
            self.js_token = tok
        if pcf:
            self.pcf_token = pcf
        return bool(tok)

    def resolve_share(self):
        """Steps 1-3: shorturlinfo -> file list + sign."""
        surl = self.final_url.split("surl=")[-1].split("&")[0] if "surl=" in self.final_url else ""
        if not surl:
            m = re.search(r"/s/([A-Za-z0-9]+)", self.final_url)
            surl = m.group(1) if m else ""
        if not surl:
            die("cannot find surl in share URL")
        dp = random.randint(4 * 10**17, 10**18 - 1)
        url = (f"https://{self.host}/api/shorturlinfo?app_id={APP_ID}&shorturl=1{surl}"
               f"&root=1&web=1&channel=dubox&clienttype=0&jsToken={self.js_token}"
               f"&t={int(time.time())}&dp-logid={dp}")
        s, out, _ = self._http("GET", url, headers={"Referer": self.final_url})
        r = json.loads(out.decode())
        if r.get("errno") != 0:
            die(f"shorturlinfo failed: {r}")
        return r

    def get_dlink(self, fid, sign, timestamp):
        url = (f"https://{self.host}/file/get_new_download_url?app_id={APP_ID}"
               f"&channel=dubox&clienttype=0&fid={fid}&dsid={fid}&id={fid}"
               f"&osserr=0&sign={sign}&token={timestamp}")
        self.last_dlink_error = ""
        try:
            s, out, _ = self._http("GET", url, headers={"Referer": self.final_url})
        except Exception as e:
            self.last_dlink_error = f"HTTP request failed: {e}"
            return ""
        try:
            r = json.loads(out.decode("utf-8", "ignore"))
        except Exception:
            self.last_dlink_error = f"non-JSON response (HTTP {s}): {out[:200]!r}"
            return ""
        d = r.get("data") or {}
        if not d.get("dlink"):
            self.last_dlink_error = f"HTTP {s} errno={r.get('errno')} errcode={r.get('error_code')} msg={r.get('error_msg') or r.get('show_msg')}"
            return ""
        return d["dlink"]

    def save_share_file(self, data, fid):
        """Save a shared file into the account's own drive (folder '/').
        TeraBox only issues dlinks for files that exist in YOUR drive.
        Returns the raw json dict."""
        form = {
            "shareid": str(data.get("shareid", "")),
            "from": str(data.get("uk", "")),
            "to": "/",
            "fidlist": json.dumps([int(fid)]),
            "path": "/",
            "sekey": data.get("randsk", ""),
        }
        s, out, _ = self._http(
            "POST", f"https://{self.host}/share/transfer?{self.Q}",
            data=urllib.parse.urlencode(form).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Origin": f"https://{self.host}"},
            referer=self.final_url)
        try:
            return json.loads(out.decode("utf-8", "ignore"))
        except Exception:
            return {"errno": None, "http": s,
                    "raw": out[:300].decode("utf-8", "ignore")}

    def find_in_drive(self, name):
        """fs_id of a file by name in the drive root (for errno-12 re-saves)."""
        s, out, _ = self._http(
            "GET", f"https://{self.host}/api/list?dir=%2F&web=1&{self.Q}",
            headers={"Referer": self.final_url})
        try:
            r = json.loads(out.decode("utf-8", "ignore"))
        except Exception:
            return None
        for it in r.get("list") or []:
            if it.get("server_filename") == name:
                return it.get("fs_id")
        return None

    def get_dlink_filemetas(self, fid):
        """dlink for a file in the OWN drive via /api/filemetas."""
        self.last_dlink_error = ""
        s, out, _ = self._http(
            "GET", f"https://{self.host}/api/filemetas?target={fid}&dlink=1&{self.Q}",
            headers={"Referer": self.final_url})
        try:
            r = json.loads(out.decode("utf-8", "ignore"))
        except Exception:
            self.last_dlink_error = f"filemetas non-JSON (HTTP {s})"
            return ""
        if r.get("errno") != 0:
            self.last_dlink_error = f"filemetas errno={r.get('errno')} {r.get('show_msg', '')}"
            return ""
        lst = r.get("list") or []
        if not lst:
            self.last_dlink_error = "filemetas: empty list"
            return ""
        return lst[0].get("dlink") or ""

# ----------------------------------------------------------------------------
# captcha solving (PIL + numpy)
# ----------------------------------------------------------------------------
def _img_from_datauri(uri):
    from PIL import Image
    return Image.open(io.BytesIO(base64.b64decode(uri.split(",", 1)[1])))

def _box_blur(a, k):
    import numpy as np
    c = a.cumsum(0).cumsum(1)
    h, w = a.shape
    y0c = np.maximum(np.arange(h) - k + 1, 0); y1c = np.minimum(np.arange(h) + 1, h)
    x0c = np.maximum(np.arange(w) - k + 1, 0); x1c = np.minimum(np.arange(w) + 1, w)
    yy0, xx0 = np.meshgrid(y0c, x0c, indexing="ij")
    yy1, xx1 = np.meshgrid(y1c, x1c, indexing="ij")
    out = c[yy1-1, xx1-1] - c[yy0, xx1-1] - c[yy1-1, xx0] + c[yy0, xx0]
    return out / ((yy1 - yy0) * (xx1 - xx0)).clip(1)

def _components(dark, min_area=1000):
    H, W = dark.shape
    seen = dark.copy()
    comps = []
    for y in range(H):
        for x in range(W):
            if dark[y, x] and not seen[y, x]:
                q = deque([(y, x)]); seen[y, x] = False; cells = []
                while q:
                    cy, cx = q.popleft(); cells.append((cy, cx))
                    for dy, dx in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                        ny, nx = cy + dy, cx + dx
                        if 0 <= ny < H and 0 <= nx < W and dark[ny, nx] and not seen[ny, nx]:
                            seen[ny, nx] = False
                            q.append((ny, nx))
                if len(cells) >= min_area:
                    comps.append(cells)
    return comps

def solve_slide(master, piece):
    """Return hole center (cx, cy) in master-image pixels."""
    import numpy as np
    from PIL import Image
    m = np.asarray(master.convert("RGB"), dtype=np.float32).mean(axis=2)
    a = np.asarray(piece.convert("RGBA"), dtype=np.float32)[..., 3] / 255.0
    ys, xs = np.nonzero(a > 0.5)
    tile = (a[ys.min():ys.max() + 1, xs.min():xs.max() + 1] > 0.5).astype(np.uint8)

    def iou_score(cells):
        ys3 = [c[0] for c in cells]; xs3 = [c[1] for c in cells]
        comp = np.zeros((max(ys3) - min(ys3) + 1, max(xs3) - min(xs3) + 1), np.uint8)
        for cy, cx in cells:
            comp[cy - min(ys3), cx - min(xs3)] = 1
        th, tw = tile.shape; ch, cw = comp.shape
        canvas = np.zeros((max(th, ch) + 40, max(tw, cw) + 40), np.uint8)
        def place(mask):
            out = np.zeros_like(canvas)
            y3, x3 = np.nonzero(mask)
            top = int(canvas.shape[0] / 2 - y3.mean())
            left = int(canvas.shape[1] / 2 - x3.mean())
            h, w = mask.shape; H, W = canvas.shape
            t0, t1 = max(0, top), min(H, top + h)
            l0, l1 = max(0, left), min(W, left + w)
            out[t0:t1, l0:l1] = mask[t0 - top:t1 - top, l0 - left:l1 - left]
            return out
        t2, c2 = place(tile), place(comp)
        i, u = (t2 & c2).sum(), (t2 | c2).sum()
        iou = i / u if u else 0.0
        fill = len(cells) / ((max(ys3) - min(ys3) + 1) * (max(xs3) - min(xs3) + 1))
        return iou, float(np.mean(xs3)), float(np.mean(ys3)), iou * fill

    best = None
    for thr in (85, 75, 95):
        for cells in _components(m < thr):
            iou_s, cx, cy, sc = iou_score(cells)
            if best is None or sc > best[0]:
                best = (sc, cx, cy, iou_s)
        if best and best[3] > 0.8:
            break
    if best and best[3] >= 0.55:
        return best[1], best[2]
    # fallback: soft darkness cross-correlation
    hgt, wid = tile.shape
    neigh = _box_blur(m, max(24, hgt))
    dmap = np.clip((neigh - m - 5) / 25.0, 0, 1)
    alpha = (tile > 0).astype(np.float32)
    from numpy.lib.stride_tricks import sliding_window_view
    win = sliding_window_view(dmap, (hgt, wid))
    scores = np.einsum("ijkl,kl->ij", win, alpha) / alpha.sum()
    bi, bj = np.unravel_index(np.argmax(scores), scores.shape)
    return bj + wid / 2.0, bi + hgt / 2.0

# ----------------------------------------------------------------------------
# misc helpers
# ----------------------------------------------------------------------------
def _cookie(jar, name):
    for c in jar:
        if c.name == name:
            return c.value
    return None

def save_session(email, password, ndus, host):
    try:
        with open(SESSION_FILE, "w") as f:
            json.dump({"email": email, "password": password,
                       "ndus": ndus, "host": host}, f)
        os.chmod(SESSION_FILE, 0o600)
    except Exception as e:
        print(f"  (could not save session: {e})", flush=True)

def load_session():
    try:
        with open(SESSION_FILE) as f:
            return json.load(f)
    except Exception:
        return None

def fmt_size(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} B"
        n /= 1024.0

def fmt_eta(sec):
    if sec < 0 or sec != sec:
        return "--:--"
    sec = int(sec)
    h, m, s = sec // 3600, (sec % 3600) // 60, sec % 60
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

def human(s):
    for u, n in (("GB", 1024**3), ("MB", 1024**2), ("KB", 1024)):
        if s >= n:
            return f"{s / n:.2f} {u}/s"
    return f"{s:.0f} B/s"

def download_file(tbox, url, dest, referer):
    """Stream download with progress bar, resume support."""
    total = None
    pos = 0
    if os.path.exists(dest):
        pos = os.path.getsize(dest)
    headers = {"Referer": referer, "User-Agent": UA}
    if pos > 0:
        headers["Range"] = f"bytes={pos}-"
    req = urllib.request.Request(url, headers=headers)
    try:
        r = tbox.op.open(req, timeout=60)
    except urllib.error.HTTPError as e:
        if e.code == 416:  # whole file already downloaded
            print("  already complete.", flush=True)
            return True
        raise
    if r.status == 206:
        total = pos + int(r.headers.get("Content-Length", 0))
        mode = "ab"
    else:
        total = int(r.headers.get("Content-Length", 0)) or None
        pos = 0
        mode = "wb"
    if total and pos >= total:
        print("  already complete.", flush=True)
        return True
    bar_w = 28
    t0 = time.time()
    last = pos
    last_t = t0
    with open(dest, mode) as f:
        while True:
            chunk = r.read(256 * 1024)
            if not chunk:
                break
            f.write(chunk)
            pos += len(chunk)
            now = time.time()
            dt = now - last_t
            if dt >= 0.25 or (total and pos >= total):
                last_t = now
                avg = pos / max(now - t0, 1e-6)
                if total:
                    pct = 100.0 * pos / total
                    filled = int(bar_w * pos / total)
                    eta = (total - pos) / avg if avg > 1 else -1
                    line = (f"\r  [{'#' * filled}{'.' * (bar_w - filled)}] "
                            f"{pct:5.1f}%  {fmt_size(pos)}/{fmt_size(total)}  "
                            f"{human(avg)}  ETA {fmt_eta(eta)}")
                else:
                    line = f"\r  {fmt_size(pos)}  {human(avg)}"
                print(line[:200], end="", flush=True)
    print(flush=True)
    if total and pos < total:
        return False
    return True

# ----------------------------------------------------------------------------
# main flow
# ----------------------------------------------------------------------------
def ensure_login(tbox, args):
    """Make sure we have a working ndus (via cache, cookie arg, or login)."""
    if args.cookie:
        # inject ndus directly
        import http.cookiejar as cj
        c = cj.Cookie(version="0", name="ndus", value=args.cookie, port=None,
                      port_specified=False, domain=tbox.host, domain_specified=True,
                      domain_initial_dot=False, path="/", path_specified=True,
                      secure=False, expires=int(time.time()) + 86400 * 30,
                      discard=False, comment=None, comment_url=None, rest={}, rfc2109=False)
        tbox.jar.set_cookie(c)
        return True

    sess = load_session()
    if sess and sess.get("ndus"):
        # try cached ndus
        import http.cookiejar as cj
        c = cj.Cookie(version="0", name="ndus", value=sess["ndus"], port=None,
                      port_specified=False, domain=tbox.host, domain_specified=True,
                      domain_initial_dot=False, path="/", path_specified=True,
                      secure=False, expires=int(time.time()) + 86400 * 30,
                      discard=False, comment=None, comment_url=None, rest={}, rfc2109=False)
        tbox.jar.set_cookie(c)
        # cheap check: try resolving; caller validates via get_dlink
        print(f"  using cached session ({sess.get('email')})", flush=True)
        return True

    email = (args.login or [None, None])[0] if args.login else None
    password = (args.login or [None, None])[1] if args.login else None
    email = email or (sess or {}).get("email")
    password = password or (sess or {}).get("password")
    if not email or not password:
        die("no credentials. Run:  python terabox_dl.py --login EMAIL PASSWORD\n"
            "          (or --register EMAIL PASSWORD, or --cookie NDUS)")
    print(f"  logging in as {email} ...", flush=True)
    ok, msg = tbox.login_full(email, password)
    if not ok:
        die(msg)
    ndus = _cookie(tbox.jar, "ndus")
    save_session(email, password, ndus, tbox.host)
    print("  login OK (session cached)", flush=True)
    return True

def main():
    ap = argparse.ArgumentParser(description="TeraBox downloader (Termux-friendly)")
    ap.add_argument("url", nargs="?", help="share URL to download")
    ap.add_argument("--login", nargs=2, metavar=("EMAIL", "PASSWORD"))
    ap.add_argument("--register", nargs=2, metavar=("EMAIL", "PASSWORD"))
    ap.add_argument("--cookie", help="use this ndus cookie value")
    ap.add_argument("--logout", action="store_true")
    ap.add_argument("-o", "--out", default=None, help="output dir (default: /sdcard/Download on Android, ./terabox_downloads elsewhere)")
    ap.add_argument("--no-captcha", action="store_true")
    args = ap.parse_args()

    if args.logout:
        try:
            os.remove(SESSION_FILE)
            print("session cleared.")
        except FileNotFoundError:
            print("no session file.")
        return

    if args.register:
        email, password = args.register
        if not args.url:
            args.url = DEFAULT_SHARE
        tbox = TBox(args.url)
        print(f"[*] registration for {email} on {tbox.host}")
        ok, tok = tbox.register_sendcode(email)
        if not ok:
            die(f"sendcode failed: {tok}")
        print(f"  code sent to {email} (token {tok[:10]}...), retry period 60s")
        code = input("Enter the 4-digit code from the email: ").strip()
        ok, msg, raw = tbox.register_verify(email, tok, code)
        if not ok:
            die(f"verify failed: {msg}")
        print("  code verified, creating account ...")
        ok, msg = tbox.register_finish(email, tok, password)
        if not ok:
            die(f"finish failed: {msg}")
        ndus = _cookie(tbox.jar, "ndus")
        if ndus:
            save_session(email, password, ndus, tbox.host)
            print("  account created + logged in. Ready to download!")
        else:
            # some hosts don't auto-login after finish
            ok2, msg2 = tbox.login_full(email, password)
            if ok2:
                save_session(email, password, _cookie(tbox.jar, "ndus"), tbox.host)
                print("  account created + logged in. Ready to download!")
            else:
                die(msg2)
        return

    if args.login:
        email, password = args.login
        if not args.url:
            args.url = DEFAULT_SHARE
        tbox = TBox(args.url)
        ok, msg = tbox.login_full(email, password)
        if not ok:
            die(msg)
        save_session(email, password, _cookie(tbox.jar, "ndus"), tbox.host)
        print("login OK, session cached in " + SESSION_FILE)
        return

    if not args.url:
        ap.print_help()
        die("share URL required (or use --login / --register)")

    hr()
    print(f"[*] TeraBox downloader  —  host resolution ...")
    tbox = TBox(args.url)
    print(f"    final host: {tbox.host}")
    print(f"    final url:  {tbox.final_url}")

    ensure_login(tbox, args)

    info("[*] resolving share ...")
    data = tbox.resolve_share()
    lst = data.get("list") or []
    if not lst:
        die("no files in share")
    sign = data.get("sign", "")
    timestamp = str(data.get("timestamp", ""))
    outdir = os.path.abspath(args.out or default_outdir())
    os.makedirs(outdir, exist_ok=True)

    for it in lst:
        name = it.get("server_filename") or it.get("filename") or "file"
        size = it.get("size", 0)
        fid = it.get("fs_id")
        info(f"    - {name}  ({fmt_size(size)})")
    hr()

    failed = 0
    for it in lst:
        name = it.get("server_filename") or it.get("filename") or "file"
        size = it.get("size", 0)
        fid = it.get("fs_id")
        info(f"[*] {name}  ({fmt_size(size)})")
        dlink = tbox.get_dlink(fid, sign, timestamp)
        if not dlink:
            sess = load_session()
            if sess and sess.get("email") and sess.get("password"):
                print("  ndus expired — re-login ...", flush=True)
                ok, msg = tbox.login_full(sess["email"], sess["password"])
                if ok:
                    save_session(sess["email"], sess["password"],
                                 _cookie(tbox.jar, "ndus"), tbox.host)
                    data2 = tbox.resolve_share()
                    sign = data2.get("sign", "")
                    timestamp = str(data2.get("timestamp", ""))
                    dlink = tbox.get_dlink(fid, sign, timestamp)
        if not dlink:
            print("  !! no download link — re-login or use --cookie", flush=True)
            failed += 1
            continue
        dest = os.path.join(outdir, name)
        info("  downloading ...")
        try:
            ok = download_file(tbox, dlink, dest, tbox.final_url)
        except Exception as e:
            ok = False
            print(f"  !! download error: {e}", flush=True)
        if ok:
            print(f"  done -> {dest}", flush=True)
        else:
            failed += 1
    hr()
    if failed:
        print(f"[!] {failed} file(s) failed.")
        sys.exit(2)
    print("[*] all done.")

DEFAULT_SHARE = "https://terasharelink.com/s/1rlXii3bmTe68W8mtNIjxmQ"

def default_outdir():
    if os.environ.get("TERMUX_VERSION") or os.path.isdir("/sdcard"):
        return "/sdcard/Download"
    return "./terabox_downloads"

if __name__ == "__main__":
    main()
