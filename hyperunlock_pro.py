#!/usr/bin/env python3
"""
HyperOS Fastboot Toolkit — Xiaomi & POCO HyperOS Bootloader Status & Fastboot Utility
======================================================================================
A zero-dependency Python utility (Dark-Mode GUI + Terminal CLI) for:
1. Authenticating with Xiaomi Community Global (Direct Email/ID + Password API,
   QR Login, Browser Cookie Helper, or Manual `new_bbs_serviceToken` entry).
2. Checking HyperOS bootloader unlock eligibility (`/bbs/api/global/user/bl-switch/state`).
3. Synchronizing local requests via NTP and HTTP/1.1 Keep-Alive scheduling around
   the 00:00:00 Beijing Time (GMT+8) window (`/bbs/api/global/apply/bl-auth`).
4. Inspecting and servicing Xiaomi/POCO devices via ADB & Fastboot (lock status,
   anti-rollback checks, signed token staging, and Windows USB 3.0 driver fixes).

Author: Faris Emad Al-Yamni
Email: Farisemad2019@gmail.com
License: MIT
"""

import base64
import datetime
import getpass
import hashlib
import http.client
import http.cookiejar
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from typing import Callable, Dict, List, Optional, Tuple

# Ensure UTF-8 console output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

APP_NAME = "HyperOS Fastboot Toolkit"
APP_VERSION = "2.0.0"
AUTHOR_NAME = "Faris Emad Al-Yamni"
AUTHOR_LINKEDIN = "linkedin.com/in/faris-emad-2a852536a"
AUTHOR_EMAIL = "Farisemad2019@gmail.com"
API_HOST = "sgp-api.buy.mi.com"
STATE_PATH = "/bbs/api/global/user/bl-switch/state"
APPLY_PATH = "/bbs/api/global/apply/bl-auth"
PASSPORT_SID = "18n_bbs_global"
TOKEN_FILE = "token.txt"
SESSION_COOKIE_FILE = "xiaomi_session.txt"
UNLOCK_SESSION_FILE = "unlock_session.json"
LOG_FILE = "unlock_result.log"

NTP_SERVERS = [
    "time.cloudflare.com",
    "time.google.com",
    "pool.ntp.org",
    "time.windows.com",
]

BEIJING_TZ = datetime.timezone(datetime.timedelta(hours=8))


# ============================================================================
# CORE NETWORK, AUTHENTICATION & API ENGINE
# ============================================================================

def clean_token_string(raw_token: str) -> str:
    """Extracts and cleans the raw `new_bbs_serviceToken` value."""
    token = raw_token.strip()
    if "new_bbs_serviceToken=" in token:
        token = token.split("new_bbs_serviceToken=", 1)[1].split(";", 1)[0].strip()
    return token.strip("\"' \r\n\t")


def load_saved_token() -> str:
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                return clean_token_string(f.read())
        except Exception:
            return ""
    return ""


def save_token(token: str) -> None:
    cleaned = clean_token_string(token)
    if cleaned:
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            f.write(cleaned)


def generate_device_id(token: str) -> str:
    """Generates a deterministic 16-char uppercase hex deviceId from token."""
    return hashlib.md5(token.encode("utf-8")).hexdigest()[:16].upper()


def build_headers(token: str, device_id: Optional[str] = None) -> Dict[str, str]:
    if not device_id:
        device_id = generate_device_id(token)
    return {
        "Cookie": (
            f"new_bbs_serviceToken={token};"
            f"versionCode=500411;"
            f"versionName=5.4.11;"
            f"deviceId={device_id};"
        ),
        "User-Agent": "okhttp/4.12.0",
        "Content-Type": "application/json; charset=utf-8",
        "Connection": "keep-alive",
        "Accept-Encoding": "identity",
    }


def strip_xiaomi_prefix(raw_text: str) -> str:
    prefix = "&&&START&&&"
    if raw_text.startswith(prefix):
        return raw_text[len(prefix):]
    return raw_text


class XiaomiRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Custom redirect handler for Xiaomi Passport & Community login:
    1. Captures `new_bbs_serviceToken` from any intermediate 302 `Set-Cookie` header.
    2. Reads `extension-pragma` (`ssecurity` + `nonce`) on 2FA `Auth2/end` redirects
       and automatically injects `&clientSign=...` into the callback redirect URL.
    """

    def __init__(self, captured_tokens: List[str]):
        super().__init__()
        self.captured_tokens = captured_tokens
        self.last_ssecurity: Optional[str] = None
        self.last_nonce: Optional[object] = None

    def _scan_headers(self, headers) -> None:
        if not headers:
            return
        pragma = headers.get("extension-pragma") or headers.get("Extension-Pragma")
        if pragma:
            try:
                p_json = json.loads(pragma)
                if p_json.get("ssecurity"):
                    self.last_ssecurity = p_json["ssecurity"]
                if p_json.get("nonce") is not None:
                    self.last_nonce = p_json["nonce"]
            except Exception:
                pass

        for cookie_hdr in headers.get_all("Set-Cookie", []):
            for key in ("new_bbs_serviceToken=", "serviceToken="):
                if key in cookie_hdr:
                    val = cookie_hdr.split(key, 1)[1].split(";", 1)[0].strip()
                    if val and val not in ("EXPIRED", '""', "null"):
                        self.captured_tokens.append(val)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._scan_headers(headers)
        # If redirecting to Xiaomi's callback (`login-back`) after 2FA, inject `clientSign`
        if "login-back" in newurl and "clientSign=" not in newurl:
            if self.last_nonce is not None and self.last_ssecurity:
                sign_str = f"nonce={self.last_nonce}&{self.last_ssecurity}"
                sha1_digest = hashlib.sha1(sign_str.encode("utf-8")).digest()
                client_sign = base64.b64encode(sha1_digest).decode("utf-8").strip()
                sep = "&" if "?" in newurl else "?"
                newurl = f"{newurl}{sep}clientSign={urllib.parse.quote(client_sign)}"
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def extract_token_from_jar(jar: http.cookiejar.CookieJar, captured: Optional[List[str]] = None) -> Optional[str]:
    if captured:
        return captured[-1]
    for cookie in jar:
        if cookie.name == "new_bbs_serviceToken" and cookie.value:
            return cookie.value
    for cookie in jar:
        if cookie.name == "serviceToken" and cookie.value:
            return cookie.value
    return None


def safe_open_ignore_404(
    opener: urllib.request.OpenerDirector,
    url_or_req,
    timeout: int = 12,
    redirect_handler: Optional[XiaomiRedirectHandler] = None,
) -> str:
    """
    Opens a URL while preserving cookies in CookieJar and scanning headers
    even if the final redirect (like `https://sgp-api.buy.mi.com/global/user/`) returns HTTP 404.
    """
    try:
        with opener.open(url_or_req, timeout=timeout) as resp:
            if redirect_handler:
                redirect_handler._scan_headers(resp.headers)
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if redirect_handler and e.headers:
            redirect_handler._scan_headers(e.headers)
        try:
            return e.read().decode("utf-8", errors="replace")
        except Exception:
            return ""


def complete_callback_location(
    opener: urllib.request.OpenerDirector,
    jar: http.cookiejar.CookieJar,
    location: str,
    nonce: Optional[object] = None,
    ssecurity: Optional[str] = None,
    redirect_handler: Optional[XiaomiRedirectHandler] = None,
) -> Optional[str]:
    """Follows Xiaomi's login callback location (ignoring final 404 page) and extracts token."""
    final_url = location
    if nonce is not None and ssecurity and "clientSign=" not in location:
        sign_str = f"nonce={nonce}&{ssecurity}"
        sha1_digest = hashlib.sha1(sign_str.encode("utf-8")).digest()
        client_sign = base64.b64encode(sha1_digest).decode("utf-8").strip()
        sep = "&" if "?" in location else "?"
        final_url = f"{location}{sep}clientSign={urllib.parse.quote(client_sign)}"

    safe_open_ignore_404(opener, final_url, timeout=12, redirect_handler=redirect_handler)
    return extract_token_from_jar(jar, redirect_handler.captured_tokens if redirect_handler else None)


def login_xiaomi_passport(
    user: str,
    password: str,
    code_prompt_cb: Optional[Callable[[str], Optional[str]]] = None,
) -> Tuple[bool, str, Optional[str]]:
    """
    Authenticates directly with Xiaomi Passport (`sid=18n_bbs_global`) using
    Email / Phone / Mi Account ID and Password, handles Email/SMS 2FA verification
    directly in-app via `code_prompt_cb`, and extracts `new_bbs_serviceToken`.

    Returns:
        (success: bool, token_or_message: str, verification_url: Optional[str])
    """
    import re

    captured_tokens: List[str] = []
    jar = http.cookiejar.LWPCookieJar(SESSION_COOKIE_FILE)
    if os.path.exists(SESSION_COOKIE_FILE):
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
        except Exception:
            pass
    ctx = ssl.create_default_context()
    redir_handler = XiaomiRedirectHandler(captured_tokens)
    opener = urllib.request.build_opener(
        redir_handler,
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
    )
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )
    opener.addheaders = [
        ("User-Agent", ua),
        ("Accept", "application/json, text/plain, */*"),
    ]

    try:
        # Step 1: Fetch serviceLogin parameters (_sign, qs, callback)
        init_url = f"https://account.xiaomi.com/pass/serviceLogin?sid={PASSPORT_SID}&_json=true"
        raw_step1 = strip_xiaomi_prefix(safe_open_ignore_404(opener, init_url, timeout=12, redirect_handler=redir_handler))
        step1 = json.loads(raw_step1)

        qs = step1.get("qs", f"%3Fsid%3D{PASSPORT_SID}%26_json%3Dtrue")
        sign = step1.get("_sign", "")
        callback = step1.get("callback", "https://sgp-api.buy.mi.com/bbs/api/global/user/login-back")

        # Step 2: Submit MD5 password hash to serviceLoginAuth2
        pwd_hash = hashlib.md5(password.encode("utf-8")).hexdigest().upper()
        form_data = urllib.parse.urlencode(
            {
                "_json": "true",
                "qs": qs,
                "callback": callback,
                "_sign": sign,
                "sid": PASSPORT_SID,
                "user": user.strip(),
                "hash": pwd_hash,
            }
        ).encode("utf-8")

        auth_req = urllib.request.Request(
            "https://account.xiaomi.com/pass/serviceLoginAuth2",
            data=form_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        raw_step2 = strip_xiaomi_prefix(safe_open_ignore_404(opener, auth_req, timeout=12, redirect_handler=redir_handler))
        step2 = json.loads(raw_step2)

        code = step2.get("code")
        desc = step2.get("desc") or step2.get("description") or "Unknown error"
        notif_url = step2.get("notificationUrl")
        captcha_url = step2.get("captchaUrl")

        # Step 2B: Handle In-App 2FA Email / SMS Verification Challenge
        if notif_url:
            if notif_url.startswith("/"):
                notif_url = "https://account.xiaomi.com" + notif_url

            if not code_prompt_cb:
                return (
                    False,
                    "Xiaomi requested 2FA Email/SMS security verification.",
                    notif_url,
                )

            # Open notificationUrl inside our CookieJar to initialize `identity_session` and `ick`
            safe_open_ignore_404(opener, notif_url, timeout=12, redirect_handler=redir_handler)
            parsed_notif = urllib.parse.urlparse(notif_url)
            q_params = urllib.parse.parse_qs(parsed_notif.query)
            context_val = q_params.get("context", [""])[0]

            # Query identity/list using proper urlencode (`quote_plus`) so `/` in context is encoded as `%2F`
            list_query = urllib.parse.urlencode(
                {"sid": PASSPORT_SID, "context": context_val, "_locale": "en_US"}
            )
            list_url = f"https://account.xiaomi.com/identity/list?{list_query}"
            safe_open_ignore_404(opener, list_url, timeout=12, redirect_handler=redir_handler)

            # Always use Email (`sendEmailTicket`) when user logs in with an email address
            # (or when phone is in Fastboot mode and cannot receive SMS!)
            mode = "email" if ("@" in user or True) else "phone"

            def get_ick() -> str:
                for c in jar:
                    if c.name == "ick":
                        return c.value
                return ""

            # Request Xiaomi to send the 6-digit verification code to Gmail (`sendEmailTicket`)
            dc_ms = str(int(time.time() * 1000))
            send_endpoint = "https://account.xiaomi.com/identity/auth/sendEmailTicket"
            send_query = urllib.parse.urlencode(
                {
                    "_dc": dc_ms,
                    "sid": PASSPORT_SID,
                    "context": context_val,
                    "mask": "0",
                    "_locale": "en_US",
                }
            )
            send_url = f"{send_endpoint}?{send_query}"
            send_body = urllib.parse.urlencode(
                {"retry": "0", "icode": "", "_json": "true", "ick": get_ick()}
            ).encode("utf-8")
            send_req = urllib.request.Request(
                send_url,
                data=send_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            send_raw = strip_xiaomi_prefix(
                safe_open_ignore_404(opener, send_req, timeout=12, redirect_handler=redir_handler)
            )
            send_status_note = "Status: Email code requested."
            try:
                send_json = json.loads(send_raw)
                s_code = send_json.get("code")
                if s_code == 0:
                    send_status_note = "Status: Xiaomi confirmed NEW 6-digit code was just sent to your Gmail!"
                elif s_code == 70022:
                    tips = send_json.get("tips") or "Sent too many codes. Try again tomorrow."
                    return (
                        False,
                        f"Xiaomi Email 2FA Limit Reached (Code 70022: '{tips}').\n"
                        "Please click '📱 Sign In via QR Code' instead (requires NO email or SMS code!), "
                        "or use your already-saved token in Method C.",
                        None,
                    )
                elif s_code == 87001 or send_json.get("captchaUrl"):
                    send_status_note = (
                        f"Status: Xiaomi rate-limited email sending (Captcha required: code {s_code}). "
                        "Wait 5 minutes or use your existing saved token."
                    )
                else:
                    send_status_note = f"Status from Xiaomi: {send_json}"
            except Exception:
                pass

            # Allow up to 3 attempts in case user types an older email code first
            finish_loc = None
            last_err = ""
            for attempt in range(1, 4):
                extra_hint = (
                    f"\n(Attempt {attempt}/3: Previous code didn't match — check the NEWEST email at the bottom of your Gmail thread!)"
                    if attempt > 1
                    else ""
                )
                otp_code = code_prompt_cb(
                    f"{send_status_note}\n"
                    f"Target: {mode.upper()} ({user}){extra_hint}\n\n"
                    "Enter the 6-digit verification code:"
                )
                if not otp_code or not otp_code.strip():
                    return (False, "2FA verification cancelled by user.", None)

                flag_val = "4" if mode == "phone" else "8"
                verify_endpoint = (
                    "https://account.xiaomi.com/identity/auth/verifyPhone"
                    if mode == "phone"
                    else "https://account.xiaomi.com/identity/auth/verifyEmail"
                )
                verify_query = urllib.parse.urlencode(
                    {
                        "_flag": flag_val,
                        "_json": "true",
                        "sid": PASSPORT_SID,
                        "context": context_val,
                        "mask": "0",
                        "_locale": "en_US",
                    }
                )
                verify_url = f"{verify_endpoint}?{verify_query}"
                verify_body = urllib.parse.urlencode(
                    {
                        "_flag": flag_val,
                        "ticket": otp_code.strip(),
                        "trust": "true",
                        "_json": "true",
                        "ick": get_ick(),
                    }
                ).encode("utf-8")
                verify_req = urllib.request.Request(
                    verify_url,
                    data=verify_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                verify_raw = strip_xiaomi_prefix(
                    safe_open_ignore_404(opener, verify_req, timeout=12, redirect_handler=redir_handler)
                )

                try:
                    v_json = json.loads(verify_raw)
                    finish_loc = v_json.get("location") or v_json.get("finish_loc")
                    if v_json.get("code") == 0 or finish_loc:
                        break
                    last_err = str(v_json)
                except Exception:
                    m = re.search(r"https://account\.xiaomi\.com/identity/result/check\?[^\"'\s]+", verify_raw)
                    if m:
                        finish_loc = m.group(0)
                        break
                    last_err = verify_raw[:200]

            if not finish_loc and last_err:
                return (False, f"2FA code verification failed: {last_err}", None)

            if not finish_loc:
                chk_query = urllib.parse.urlencode(
                    {"sid": PASSPORT_SID, "context": context_val, "_locale": "en_US"}
                )
                finish_loc = f"https://account.xiaomi.com/identity/result/check?{chk_query}"
            elif finish_loc.startswith("/"):
                finish_loc = "https://account.xiaomi.com" + finish_loc

            # Follow finish_loc -> XiaomiRedirectHandler reads `extension-pragma`, injects `clientSign`,
            # and captures `new_bbs_serviceToken` from `login-back`!
            safe_open_ignore_404(opener, finish_loc, timeout=12, redirect_handler=redir_handler)
            extracted_2fa = extract_token_from_jar(jar, captured_tokens)

            if not extracted_2fa:
                # Fallback: Now that 2FA session (`passToken`) is active in `jar`, call `serviceLogin` / `serviceLoginAuth2`
                raw_s1 = strip_xiaomi_prefix(
                    safe_open_ignore_404(opener, init_url, timeout=12, redirect_handler=redir_handler)
                )
                try:
                    s1 = json.loads(raw_s1)
                    if s1.get("location") and s1.get("ssecurity") and s1.get("nonce") is not None:
                        extracted_2fa = complete_callback_location(
                            opener, jar, s1["location"], s1["nonce"], s1["ssecurity"], redir_handler
                        )
                except Exception:
                    pass

            if not extracted_2fa:
                # Fallback 2: Re-submit auth_req with the trusted 2FA CookieJar
                raw_s2 = strip_xiaomi_prefix(
                    safe_open_ignore_404(opener, auth_req, timeout=12, redirect_handler=redir_handler)
                )
                try:
                    s2 = json.loads(raw_s2)
                    if s2.get("location") and s2.get("ssecurity") and s2.get("nonce") is not None:
                        extracted_2fa = complete_callback_location(
                            opener, jar, s2["location"], s2["nonce"], s2["ssecurity"], redir_handler
                        )
                except Exception:
                    pass

            if extracted_2fa:
                try:
                    jar.save(ignore_discard=True, ignore_expires=True)
                except Exception:
                    pass
                try:
                    if os.path.exists(UNLOCK_SESSION_FILE):
                        os.remove(UNLOCK_SESSION_FILE)
                except Exception:
                    pass
                save_token(extracted_2fa)
                return (True, extracted_2fa, None)

            return (
                False,
                "2FA verified, but token cookie was not found. Please check Browser Login.",
                None,
            )

        if captcha_url:
            return (
                False,
                "Xiaomi requested a CAPTCHA image challenge. Please use Method B (Browser Login).",
                "https://c.mi.com/global",
            )

        if code != 0:
            if code == 70016:
                return (False, "Invalid Email/Mi ID or Password (Error 70016).", None)
            return (False, f"Xiaomi Login Error {code}: {desc}", None)

        location = step2.get("location")
        nonce = step2.get("nonce")
        ssecurity = step2.get("ssecurity")
        if not location or nonce is None or not ssecurity:
            return (False, "Login succeeded on Passport, but callback parameters were missing.", None)

        # Step 3: Sign nonce + ssecurity (`clientSign`) and follow callback location (ignoring final 404)
        extracted_token = complete_callback_location(opener, jar, location, nonce, ssecurity, redir_handler)
        if extracted_token:
            try:
                jar.save(ignore_discard=True, ignore_expires=True)
            except Exception:
                pass
            try:
                if os.path.exists(UNLOCK_SESSION_FILE):
                    os.remove(UNLOCK_SESSION_FILE)
            except Exception:
                pass
            save_token(extracted_token)
            return (True, extracted_token, None)

        return (
            False,
            "Authenticated with Xiaomi, but `new_bbs_serviceToken` was not issued. "
            "Please open https://c.mi.com/global once to activate your Global Community profile.",
            "https://c.mi.com/global",
        )
    except Exception as e:
        return (False, f"Network/Login exception: {e}", None)


def start_xiaomi_qr_session(sid: str = PASSPORT_SID) -> Tuple[bool, dict, bytes, str]:
    """
    Starts a Xiaomi QR Code login session (`longPolling/loginUrl`).
    Returns (ok, meta_dict, qr_png_bytes, error_msg).
    Avoids Email/SMS OTP rate limits (`70022`) via device-confirmed QR authorization.
    """
    ctx = ssl.create_default_context()
    url = f"https://account.xiaomi.com/longPolling/loginUrl?sid={sid}&_json=true"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=12, context=ctx) as resp:
            raw = strip_xiaomi_prefix(resp.read().decode("utf-8", errors="replace"))
        meta = json.loads(raw)
        qr_url = meta.get("qr")
        lp_url = meta.get("lp")
        if not qr_url or not lp_url:
            return False, {}, b"", f"QR endpoint did not return qr/lp URLs: {meta}"
        with urllib.request.urlopen(qr_url, timeout=12, context=ctx) as qresp:
            png_bytes = qresp.read()
        return True, meta, png_bytes, ""
    except Exception as e:
        return False, {}, b"", f"Failed to initialize QR login: {e}"


def poll_xiaomi_qr_login(meta: dict, stop_evt: threading.Event) -> Tuple[bool, str]:
    """
    Long-polls `meta['lp']` until user scans the QR code in Settings -> Xiaomi Account on their phone.
    Saves `passToken`, `userId`, and `ssecurity` into `xiaomi_session.txt` and extracts `new_bbs_serviceToken`.
    """
    lp_url = meta.get("lp", "")
    captured_tokens: List[str] = []
    jar = http.cookiejar.LWPCookieJar(SESSION_COOKIE_FILE)
    if os.path.exists(SESSION_COOKIE_FILE):
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
        except Exception:
            pass
    ctx = ssl.create_default_context()
    redir_handler = XiaomiRedirectHandler(captured_tokens)
    opener = urllib.request.build_opener(
        redir_handler,
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
    )
    opener.addheaders = [("User-Agent", "Mozilla/5.0"), ("Accept", "application/json, text/plain, */*")]

    deadline = time.time() + 120.0
    while not stop_evt.is_set() and time.time() < deadline:
        try:
            raw = strip_xiaomi_prefix(
                safe_open_ignore_404(opener, lp_url, timeout=25, redirect_handler=redir_handler)
            )
            if not raw.strip():
                continue
            data = json.loads(raw)
            if data.get("code") == 0 and data.get("location"):
                loc = data["location"]
                nonce = data.get("nonce")
                ssecurity = data.get("ssecurity")
                user_id = str(data.get("userId", ""))
                pass_token = data.get("passToken", "")
                tok = complete_callback_location(opener, jar, loc, nonce, ssecurity, redir_handler)

                # Also pre-authorize `sid=unlockApi` using a clean CookieJar + fresh QR `passToken` so Tab 3 Native Unlocker
                # works immediately while the phone is in Fastboot mode without needing any 2FA code!
                try:
                    unl_jar = http.cookiejar.LWPCookieJar()
                    unl_captured: List[str] = []
                    unl_redir = XiaomiRedirectHandler(unl_captured)
                    unl_opener = urllib.request.build_opener(
                        unl_redir,
                        urllib.request.HTTPCookieProcessor(unl_jar),
                        urllib.request.HTTPSHandler(context=ctx),
                    )
                    cookie_hdr = f"userId={user_id}; passToken={pass_token}" if pass_token else ""
                    unl_opener.addheaders = [
                        ("User-Agent", "XiaomiPCSuite"),
                        ("Accept", "application/json, text/plain, */*"),
                    ]
                    u_req = urllib.request.Request(
                        "https://account.xiaomi.com/pass/serviceLogin?sid=unlockApi&_json=true",
                        headers={"Cookie": cookie_hdr} if cookie_hdr else {},
                    )
                    u_raw = strip_xiaomi_prefix(
                        safe_open_ignore_404(
                            unl_opener,
                            u_req,
                            timeout=12,
                            redirect_handler=unl_redir,
                        )
                    )
                    u_json = json.loads(u_raw)
                    if u_json.get("location") and u_json.get("ssecurity") and u_json.get("nonce") is not None:
                        complete_callback_location(
                            unl_opener, unl_jar, u_json["location"], u_json["nonce"], u_json["ssecurity"], unl_redir
                        )
                        u_stoken = extract_token_from_jar(unl_jar, unl_captured)
                        if u_stoken:
                            with open(UNLOCK_SESSION_FILE, "w", encoding="utf-8") as uf:
                                json.dump(
                                    {
                                        "ssecurity": u_json["ssecurity"],
                                        "userId": str(u_json.get("userId") or user_id),
                                        "serviceToken": u_stoken,
                                        "saved_at": time.time(),
                                    },
                                    uf,
                                )
                except Exception:
                    pass

                try:
                    jar.save(ignore_discard=True, ignore_expires=True)
                except Exception:
                    pass
                if tok:
                    save_token(tok)
                    return True, tok
                return False, "QR scan succeeded, but `new_bbs_serviceToken` was not returned."
        except socket.timeout:
            continue
        except Exception:
            time.sleep(1.0)

    return False, "QR Code login timed out or was cancelled."


def get_ntp_offset() -> Tuple[float, str]:
    """
    Queries atomic NTP servers via UDP port 123 and returns (offset_seconds, server_name).
    true_utc_time = time.time() + offset_seconds
    """
    ntp_epoch_delta = 2208988800
    packet = b"\x1b" + 47 * b"\0"

    for server in NTP_SERVERS:
        offsets = []
        for _ in range(3):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(1.8)
                    t1 = time.time()
                    sock.sendto(packet, (server, 123))
                    data, _ = sock.recvfrom(1024)
                    t4 = time.time()
                    if len(data) >= 48:
                        unpacked = struct.unpack("!12I", data[:48])
                        tx_sec = unpacked[10] - ntp_epoch_delta
                        tx_frac = unpacked[11] / float(2**32)
                        server_time = tx_sec + tx_frac
                        rtt = t4 - t1
                        offset = server_time - (t1 + rtt / 2.0)
                        offsets.append(offset)
            except Exception:
                continue
        if offsets:
            return sum(offsets) / len(offsets), server

    return 0.0, "Local System Clock (NTP unreachable)"


def measure_api_rtt(token: str = "", samples: int = 3) -> float:
    """Measures average HTTP RTT (in seconds) over an active TLS connection to sgp-api.buy.mi.com."""
    rtts = []
    ctx = ssl.create_default_context()
    headers = build_headers(token) if token else {"User-Agent": "okhttp/4.12.0", "Connection": "keep-alive"}
    try:
        conn = http.client.HTTPSConnection(API_HOST, 443, timeout=5, context=ctx)
        conn.connect()
        for _ in range(samples):
            t0 = time.perf_counter()
            conn.request("GET", STATE_PATH, headers=headers)
            resp = conn.getresponse()
            resp.read()
            t1 = time.perf_counter()
            rtts.append(t1 - t0)
        conn.close()
    except Exception:
        pass
    if rtts:
        return sum(rtts) / len(rtts)
    return 0.200


def query_account_state(token: str) -> Tuple[str, str, Optional[dict]]:
    """
    Queries `/bbs/api/global/user/bl-switch/state`.
    Returns (status_tag, human_message, raw_json_dict)
    where status_tag is one of: 'APPROVED', 'ELIGIBLE', 'WAIT', 'AGE_LIMIT', 'EXPIRED', 'ERROR'.
    """
    cleaned = clean_token_string(token)
    if not cleaned:
        return ("ERROR", "No token provided.", None)

    ctx = ssl.create_default_context()
    headers = build_headers(cleaned)
    try:
        conn = http.client.HTTPSConnection(API_HOST, 443, timeout=10, context=ctx)
        conn.request("GET", STATE_PATH, headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", errors="replace")
        conn.close()
        data = json.loads(raw)
    except Exception as e:
        return ("ERROR", f"Network error while checking account state: {e}", None)

    code = data.get("code")
    if code == 100004:
        return (
            "EXPIRED",
            "Error 100004: Your `new_bbs_serviceToken` cookie is expired or invalid. Please log in again.",
            data,
        )
    if code != 0:
        return ("ERROR", f"API returned code {code}: {data.get('msg') or raw}", data)

    inner = data.get("data", {}) or {}
    is_pass = inner.get("is_pass")
    button_state = inner.get("button_state")
    deadline = inner.get("deadline_format", "N/A")

    if is_pass == 1:
        return (
            "APPROVED",
            f"ALREADY APPROVED for unlocking! (Valid until {deadline} GMT+8).\n"
            "Go to Settings -> Developer Options -> Mi Unlock Status on your phone (using Mobile Data) "
            "and tap 'Add account and device'.",
            data,
        )
    if is_pass == 4:
        if button_state == 1:
            return (
                "ELIGIBLE",
                "ELIGIBLE & READY! Your account meets Xiaomi's requirements and is ready for the 00:00 GMT+8 quota.",
                data,
            )
        if button_state == 2:
            return (
                "WAIT",
                f"Temporarily restricted / quota cooldown until {deadline} (GMT+8). "
                "(Still worth testing 'Add account and device' in Developer Options!).",
                data,
            )
        if button_state == 3:
            return (
                "AGE_LIMIT",
                "Account Age Restriction: Xiaomi reports this account has been in Global Community for less than 30 days.",
                data,
            )

    return (
        "INFO",
        f"Account state: is_pass={is_pass}, button_state={button_state}, deadline={deadline}",
        data,
    )


def get_next_midnight_beijing(now_ntp: float) -> datetime.datetime:
    now_bj = datetime.datetime.fromtimestamp(now_ntp, tz=BEIJING_TZ)
    tomorrow = now_bj.date() + datetime.timedelta(days=1)
    return datetime.datetime(
        tomorrow.year, tomorrow.month, tomorrow.day, 0, 0, 0, tzinfo=BEIJING_TZ
    )


def parse_apply_result(raw_line: str) -> bool:
    return '"apply_result":1' in raw_line.replace(" ", "")


def send_single_apply(
    shot_id: int,
    target_ntp_ts: float,
    midnight_ntp_ts: float,
    ntp_offset: float,
    token: str,
    device_id: str,
    results_list: list,
    stop_event: threading.Event,
    log_cb: Optional[Callable[[str], None]] = None,
):
    """
    Pre-connects TLS, enables TCP_NODELAY, warms full upstream HTTP/1.1 Keep-Alive
    to `bbs/api/global` at T-3.5s, then spin-waits for millisecond precision and
    fires POST `/bbs/api/global/apply/bl-auth` (up to 2 waves per connection).
    """
    ctx = ssl.create_default_context()
    headers = build_headers(token, device_id)
    body = '{"is_retry":true}'.encode("utf-8")

    while not stop_event.is_set():
        now_ntp = time.time() + ntp_offset
        rem = target_ntp_ts - now_ntp
        if rem <= 3.5:
            break
        time.sleep(min(rem - 3.5, 0.2))

    if stop_event.is_set():
        return

    conn = http.client.HTTPSConnection(API_HOST, 443, timeout=10, context=ctx)
    try:
        conn.connect()
        if conn.sock:
            conn.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.request("GET", STATE_PATH, headers=headers)
        warm_resp = conn.getresponse()
        warm_resp.read()
    except Exception as e:
        msg = f"[Shot #{shot_id}] TLS pre-warm failed: {e}"
        results_list.append((str(shot_id), msg))
        if log_cb:
            log_cb(msg)
        return

    while not stop_event.is_set():
        now_ntp = time.time() + ntp_offset
        rem = target_ntp_ts - now_ntp
        if rem <= 0:
            break
        if rem > 0.015:
            time.sleep(rem * 0.5)

    for wave in (1, 2):
        if stop_event.is_set():
            break
        send_ts = time.time() + ntp_offset
        if wave == 2 and (send_ts - midnight_ntp_ts) > 1.8:
            break
        send_dt = datetime.datetime.fromtimestamp(send_ts, tz=BEIJING_TZ)
        label = f"{shot_id}.{wave}"
        try:
            conn.request("POST", APPLY_PATH, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", errors="replace")
            recv_ts = time.time() + ntp_offset
            recv_dt = datetime.datetime.fromtimestamp(recv_ts, tz=BEIJING_TZ)
            line = (
                f"[Shot #{label}] Sent @ {send_dt.strftime('%H:%M:%S.%f')[:-3]} GMT+8 | "
                f"Recv @ {recv_dt.strftime('%H:%M:%S.%f')[:-3]} GMT+8 | "
                f"HTTP {resp.status}: {raw}"
            )
            results_list.append((label, line))
            if log_cb:
                log_cb(line)
            if parse_apply_result(raw):
                stop_event.set()
                break
        except Exception as e:
            err_line = f"[Shot #{label}] Request error: {e}"
            results_list.append((label, err_line))
            if log_cb:
                log_cb(err_line)
            break

    try:
        conn.close()
    except Exception:
        pass


def compute_burst_offsets(strategy: str, one_way_delay: float, custom_ms: float = -800.0) -> List[float]:
    """
    Returns 6 shot offsets (in seconds relative to 00:00:00.000 GMT+8) based on strategy:
    - 'queue'  : Smart Pre-Midnight Queue Compensation (-1.45s to -0.18s)
    - 'ping'   : Exact Ping-Compensated Arrival (+15ms to +250ms after 00:00:00)
    - 'custom' : Centered around user's custom millisecond offset
    """
    if strategy == "ping":
        return [
            -one_way_delay + 0.015,
            -one_way_delay + 0.055,
            -one_way_delay + 0.095,
            -one_way_delay + 0.140,
            -one_way_delay + 0.190,
            -one_way_delay + 0.250,
        ]
    if strategy == "custom":
        base = custom_ms / 1000.0
        return [
            base - 0.150,
            base - 0.075,
            base,
            base + 0.075,
            base + 0.150,
            base + 0.250,
        ]
    # Default: 'queue' (Smart Pre-Midnight Queue-Compensated Spread)
    return [
        -1.450,
        -1.150,
        -0.850,
        -0.600,
        -0.380,
        -0.180,
    ]


# ============================================================================
# BUILT-IN ADB, FASTBOOT, DRIVER FIXER & MI UNLOCK ENGINE
# ============================================================================

def get_base_dir() -> str:
    """Returns directory containing bundled assets (supports PyInstaller _MEIPASS)."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return getattr(sys, "_MEIPASS")
    return os.path.dirname(os.path.abspath(__file__))


def get_writable_dir() -> str:
    """Returns writable directory next to executable or script."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def ensure_platform_tools() -> str:
    """
    Ensures `adb` and `fastboot` exist locally. Checks:
    1. PyInstaller bundled `_MEIPASS/platform-tools`
    2. Local `./platform-tools` next to script/exe
    3. System PATH
    4. Auto-downloads official Google Android Platform-Tools if missing!
    Returns the directory path containing `adb` and `fastboot` (or empty if using PATH).
    """
    exe_ext = ".exe" if sys.platform == "win32" else ""
    candidates = [
        os.path.join(get_base_dir(), "platform-tools"),
        os.path.join(get_writable_dir(), "platform-tools"),
    ]
    for pt_dir in candidates:
        adb_bin = os.path.join(pt_dir, f"adb{exe_ext}")
        fb_bin = os.path.join(pt_dir, f"fastboot{exe_ext}")
        if os.path.isfile(adb_bin) and os.path.isfile(fb_bin):
            return pt_dir

    if shutil.which("adb") and shutil.which("fastboot"):
        return ""

    # Auto-download official Google platform-tools into writable directory
    import io
    import zipfile

    os_tag = "windows" if sys.platform == "win32" else ("darwin" if sys.platform == "darwin" else "linux")
    url = f"https://dl.google.com/android/repository/platform-tools-latest-{os_tag}.zip"
    target_root = get_writable_dir()
    pt_dest = os.path.join(target_root, "platform-tools")
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(url, timeout=60, context=ctx) as resp:
            zip_bytes = resp.read()
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.extractall(target_root)
        if sys.platform != "win32":
            for bname in ("adb", "fastboot"):
                bpath = os.path.join(pt_dest, bname)
                if os.path.exists(bpath):
                    os.chmod(bpath, 0o755)
        return pt_dest
    except Exception:
        return ""


def resolve_tool_binary(tool_name: str) -> str:
    """Resolves `adb` or `fastboot` to built-in binary path or auto-downloads it."""
    exe_ext = ".exe" if sys.platform == "win32" else ""
    pt_dir = ensure_platform_tools()
    if pt_dir:
        candidate = os.path.join(pt_dir, f"{tool_name}{exe_ext}")
        if os.path.isfile(candidate):
            return candidate
    found = shutil.which(tool_name)
    return found or tool_name


def run_tool_cmd(args: List[str], timeout: float = 8.0) -> Tuple[int, str]:
    cmd = list(args)
    if cmd and cmd[0] in ("adb", "fastboot"):
        cmd[0] = resolve_tool_binary(cmd[0])
    try:
        creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            creationflags=creation_flags,
        )
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        return proc.returncode, out.strip()
    except FileNotFoundError:
        return -1, f"'{args[0]}' could not be found or auto-downloaded."
    except Exception as e:
        return -2, f"Command error: {e}"


def inspect_connected_device() -> str:
    """Scans both ADB and Fastboot using built-in platform-tools."""
    adb_path = resolve_tool_binary("adb")
    fb_path = resolve_tool_binary("fastboot")
    report = [
        f"[*] Using Built-In ADB      : {adb_path}",
        f"[*] Using Built-In Fastboot : {fb_path}\n",
        "=== ADB DEVICE CHECK ===",
    ]
    code, adb_out = run_tool_cmd(["adb", "devices", "-l"])
    if code == -1:
        report.append(f"  [!] {adb_out}")
    else:
        lines = [
            ln.strip()
            for ln in adb_out.splitlines()
            if ln.strip() and not ln.startswith("List of") and not ln.startswith("* daemon")
        ]
        if not lines:
            report.append("  [-] No ADB device detected.")
            report.append("      -> On phone: Enable Developer Options -> USB Debugging, then plug in USB.")
        else:
            for ln in lines:
                report.append(f"  [+] Connected: {ln}")
            _, model = run_tool_cmd(["adb", "shell", "getprop", "ro.product.marketname"])
            _, codename = run_tool_cmd(["adb", "shell", "getprop", "ro.product.device"])
            _, miui_ver = run_tool_cmd(["adb", "shell", "getprop", "ro.mi.os.version.name"])
            _, android_ver = run_tool_cmd(["adb", "shell", "getprop", "ro.build.version.release"])
            _, unlocked_prop = run_tool_cmd(["adb", "shell", "getprop", "ro.boot.flash.locked"])
            lock_str = (
                "LOCKED (1)"
                if unlocked_prop == "1"
                else ("UNLOCKED (0)" if unlocked_prop == "0" else unlocked_prop)
            )
            report.append(f"      Market Name   : {model or 'Unknown'}")
            report.append(f"      Codename      : {codename or 'Unknown'}")
            report.append(f"      HyperOS Build : {miui_ver or 'Unknown'} (Android {android_ver or '?'})")
            report.append(f"      Bootloader    : {lock_str}")

    report.append("\n=== FASTBOOT DEVICE CHECK ===")
    fcode, fb_out = run_tool_cmd(["fastboot", "devices"])
    if fcode == -1:
        report.append(f"  [!] {fb_out}")
    elif not fb_out.strip():
        report.append("  [-] No device in Fastboot mode.")
    else:
        report.append(f"  [+] Fastboot Device: {fb_out.strip()}")
        _, prod = run_tool_cmd(["fastboot", "getvar", "product"])
        _, unl = run_tool_cmd(["fastboot", "getvar", "unlocked"])
        _, anti = run_tool_cmd(["fastboot", "getvar", "anti"])
        _, tok = run_tool_cmd(["fastboot", "getvar", "token"])
        for label, val in [("product", prod), ("unlocked", unl), ("anti", anti), ("token", tok)]:
            cleaned_val = " | ".join(
                [l.strip() for l in val.splitlines() if "Finished." not in l and l.strip()]
            )
            report.append(f"      {label:<10}: {cleaned_val}")

    return "\n".join(report)


def read_fastboot_device_token() -> Tuple[str, str, str]:
    """
    Reads (product, token_str, raw_output) from a connected Fastboot device.
    Supports both Hex and Base64 tokens across:
    - `fastboot getvar token`
    - `fastboot oem get_token` (MediaTek / POCO X7 Pro `rodin` / HyperOS 2)
    - `fastboot getvar all` fallback
    """
    import re

    _, prod_out = run_tool_cmd(["fastboot", "getvar", "product"], timeout=5.0)
    product = ""
    for line in prod_out.splitlines():
        if "product:" in line.lower():
            product = line.split(":", 1)[1].strip()
            break

    raw_logs: List[str] = []

    def parse_token_lines(text: str) -> str:
        parts: List[str] = []
        for raw_ln in text.splitlines():
            ln = raw_ln.strip()
            if not ln or "finished." in ln.lower() or "failed" in ln.lower() or "error" in ln.lower():
                continue
            # Case 1: `(bootloader) token: <val>` or `token: <val>`
            m = re.search(r"token:\s*([A-Za-z0-9+/=_.-]+)", ln, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                if val and val.lower() not in ("no", "yes", "none", "null"):
                    parts.append(val)
                continue
            # Case 2: `(bootloader) <long_hex_or_base64_chunk>`
            if ln.lower().startswith("(bootloader)"):
                after = ln.split(")", 1)[1].strip()
                if re.fullmatch(r"[A-Za-z0-9+/=]{12,}", after):
                    parts.append(after)
        return "".join(parts)

    # 1. Try `fastboot getvar token`
    _, var_out = run_tool_cmd(["fastboot", "getvar", "token"], timeout=5.0)
    raw_logs.append(f"[getvar token] -> {var_out}")
    token_str = parse_token_lines(var_out)

    # 2. Try `fastboot oem get_token` (MediaTek / HyperOS 2)
    if not token_str:
        _, oem_out = run_tool_cmd(["fastboot", "oem", "get_token"], timeout=5.0)
        raw_logs.append(f"[oem get_token] -> {oem_out}")
        token_str = parse_token_lines(oem_out)

    # 3. Try `fastboot oem get_identifier_token`
    if not token_str:
        _, id_out = run_tool_cmd(["fastboot", "oem", "get_identifier_token"], timeout=5.0)
        raw_logs.append(f"[oem get_identifier_token] -> {id_out}")
        token_str = parse_token_lines(id_out)

    return product, token_str, "\n".join(raw_logs)


def inspect_fastboot_token_details() -> str:
    """Reads detailed Fastboot bootloader unlock variables (token, product, anti, unlocked)."""
    fcode, fb_out = run_tool_cmd(["fastboot", "devices"])
    if fcode != 0 or not fb_out.strip():
        return (
            "=== FASTBOOT UNLOCK TOKEN & ARB INSPECTOR ===\n"
            "[-] No phone detected in Fastboot mode.\n\n"
            "How to enter Fastboot Mode:\n"
            "  • Either click 'Reboot to Fastboot' while connected via ADB (USB Debugging ON), OR\n"
            "  • Hold Volume Down + Power button on your Xiaomi/POCO phone until FASTBOOT appears."
        )

    lines = ["=== FASTBOOT UNLOCK TOKEN & ARB INSPECTOR ===", f"Connected Device : {fb_out.strip()}\n"]
    for var in ("product", "serialno", "unlocked", "anti", "version-bootloader"):
        _, out = run_tool_cmd(["fastboot", "getvar", var], timeout=5.0)
        cleaned = " | ".join([l.strip() for l in out.splitlines() if "Finished." not in l and l.strip()])
        lines.append(f"  • {var:<18} : {cleaned}")

    _, token_str, raw_debug = read_fastboot_device_token()
    lines.append(f"  • {'token':<18} : {token_str or '(Empty)'}")
    if not token_str:
        lines.append("\n--- Raw Bootloader Token Output ---")
        lines.append(raw_debug)
    lines.append(
        "\nNote: Your Fastboot `token` above is what Xiaomi's unlock server signs after your 72-hour waiting period."
    )
    return "\n".join(lines)


# ============================================================================
# PURE-PYTHON AES-128-CBC & NATIVE XIAOMI BOOTLOADER UNLOCK ENGINE
# ============================================================================

# Standard AES S-Box & Inverse S-Box for zero-dependency AES-128-CBC
_AES_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_AES_INV_SBOX = [0] * 256
for _i, _v in enumerate(_AES_SBOX):
    _AES_INV_SBOX[_v] = _i

_RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p


def _aes128_expand_key(key: bytes) -> List[List[int]]:
    w = [list(key[i : i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = [_AES_SBOX[temp[(j + 1) % 4]] for j in range(4)]
            temp[0] ^= _RCON[i // 4]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])
    return [sum(w[r * 4 : (r + 1) * 4], []) for r in range(11)]


def _aes128_encrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    s = [block[i] ^ round_keys[0][i] for i in range(16)]
    for r in range(1, 10):
        s = [_AES_SBOX[b] for b in s]
        s = [
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11],
        ]
        for c in range(4):
            i = c * 4
            a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
            t = a0 ^ a1 ^ a2 ^ a3
            s[i] ^= t ^ _xtime(a0 ^ a1)
            s[i + 1] ^= t ^ _xtime(a1 ^ a2)
            s[i + 2] ^= t ^ _xtime(a2 ^ a3)
            s[i + 3] ^= t ^ _xtime(a3 ^ a0)
        s = [s[i] ^ round_keys[r][i] for i in range(16)]
    s = [_AES_SBOX[b] for b in s]
    s = [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11],
    ]
    return bytes([s[i] ^ round_keys[10][i] for i in range(16)])


def _aes128_decrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    s = [block[i] ^ round_keys[10][i] for i in range(16)]
    for r in range(9, 0, -1):
        s = [
            s[0], s[13], s[10], s[7],
            s[4], s[1], s[14], s[11],
            s[8], s[5], s[2], s[15],
            s[12], s[9], s[6], s[3],
        ]
        s = [_AES_INV_SBOX[b] for b in s]
        s = [s[i] ^ round_keys[r][i] for i in range(16)]
        for c in range(4):
            i = c * 4
            a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
            s[i] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
            s[i + 1] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
            s[i + 2] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
            s[i + 3] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)
    s = [
        s[0], s[13], s[10], s[7],
        s[4], s[1], s[14], s[11],
        s[8], s[5], s[2], s[15],
        s[12], s[9], s[6], s[3],
    ]
    s = [_AES_INV_SBOX[b] for b in s]
    return bytes([s[i] ^ round_keys[0][i] for i in range(16)])


def aes128_cbc_encrypt(data: bytes, key: bytes, iv: bytes = b"0102030405060708") -> bytes:
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len] * pad_len)
    rks = _aes128_expand_key(key[:16])
    out = bytearray()
    prev = iv[:16]
    for i in range(0, len(padded), 16):
        blk = bytes([padded[i + j] ^ prev[j] for j in range(16)])
        enc = _aes128_encrypt_block(blk, rks)
        out.extend(enc)
        prev = enc
    return bytes(out)


def aes128_cbc_decrypt(data: bytes, key: bytes, iv: bytes = b"0102030405060708") -> bytes:
    rks = _aes128_expand_key(key[:16])
    out = bytearray()
    prev = iv[:16]
    for i in range(0, len(data), 16):
        cur = data[i : i + 16]
        dec = _aes128_decrypt_block(cur, rks)
        out.extend([dec[j] ^ prev[j] for j in range(16)])
        prev = cur
    if out:
        pad_len = out[-1]
        if 1 <= pad_len <= 16:
            return bytes(out[:-pad_len])
    return bytes(out)


MI_UNLOCK_HMAC_KEY = b"2tBeoEyJTunmWUGq7bQH2Abn0k2NhhurOaqBfyxCuLVgn4AVj7swcawe53uDUno"


class UnlockSessionExpiredError(RuntimeError):
    """Raised when Xiaomi's unlock server rejects a cached `sid=unlockApi` session (e.g., HTTP 401)."""


def login_xiaomi_unlock_api(
    user: str,
    password: str,
    code_prompt_cb: Optional[Callable[[str], Optional[str]]] = None,
    force_refresh: bool = False,
) -> Tuple[bool, Dict[str, str], str]:
    """
    Authenticates with Xiaomi Passport for `sid=unlockApi` to obtain
    `ssecurity`, `userId`, and `serviceToken` for `unlock.update.intl.miui.com`.
    """
    import re

    # Check if we already have a fresh cached `sid=unlockApi` session from QR login or earlier login
    if not force_refresh and os.path.exists(UNLOCK_SESSION_FILE):
        try:
            with open(UNLOCK_SESSION_FILE, "r", encoding="utf-8") as uf:
                cached = json.load(uf)
            saved_at = float(cached.get("saved_at", 0) or 0)
            is_fresh = saved_at > 0 and (time.time() - saved_at) < (6 * 3600)
            if is_fresh and cached.get("ssecurity") and cached.get("userId") and cached.get("serviceToken"):
                return (
                    True,
                    cached,
                    "Loaded active `sid=unlockApi` session from QR/Saved Login (no 2FA needed!).",
                )
        except Exception:
            pass
        try:
            os.remove(UNLOCK_SESSION_FILE)
        except Exception:
            pass

    # Extract passToken/userId/deviceId from `xiaomi_session.txt` if available,
    # then use a CLEAN isolated CookieJar so stale `unlockApi_slh` / `serviceToken`
    # cookies never suppress `ssecurity` / `nonce` on `serviceLogin`.
    saved_pass_token = ""
    saved_user_id = ""
    saved_device_id = ""
    if os.path.exists(SESSION_COOKIE_FILE):
        try:
            old_jar = http.cookiejar.LWPCookieJar(SESSION_COOKIE_FILE)
            old_jar.load(ignore_discard=True, ignore_expires=True)
            for c in old_jar:
                if c.name == "passToken" and c.value:
                    saved_pass_token = c.value
                elif c.name == "userId" and c.value:
                    saved_user_id = c.value
                elif c.name == "deviceId" and c.value:
                    saved_device_id = c.value
        except Exception:
            pass

    captured_tokens: List[str] = []
    jar = http.cookiejar.LWPCookieJar()
    ctx = ssl.create_default_context()
    redir_handler = XiaomiRedirectHandler(captured_tokens)
    opener = urllib.request.build_opener(
        redir_handler,
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
    )
    opener.addheaders = [
        ("User-Agent", "XiaomiPCSuite"),
        ("Accept", "application/json, text/plain, */*"),
    ]

    sid = "unlockApi"
    init_url = f"https://account.xiaomi.com/pass/serviceLogin?sid={sid}&_json=true"
    pass_cookie_parts = []
    if saved_pass_token:
        pass_cookie_parts.append(f"passToken={saved_pass_token}")
    if saved_user_id:
        pass_cookie_parts.append(f"userId={saved_user_id}")
    if saved_device_id:
        pass_cookie_parts.append(f"deviceId={saved_device_id}")
    init_headers = {"Cookie": "; ".join(pass_cookie_parts)} if pass_cookie_parts else {}
    try:
        init_req = urllib.request.Request(init_url, headers=init_headers)
        raw_s1 = strip_xiaomi_prefix(safe_open_ignore_404(opener, init_req, timeout=12, redirect_handler=redir_handler))
        step1 = json.loads(raw_s1)

        # If `passToken` from Tab 1 / QR login is valid, `step1` immediately
        # returns `ssecurity`, `nonce`, and `location` with ZERO 2FA!
        if step1.get("code") == 0 and step1.get("ssecurity") and step1.get("location"):
            step2 = step1
        else:
            if not user or not password:
                return (
                    False,
                    {},
                    "Saved unlock session expired and `passToken` needs fresh sign-in.\n"
                    "    Please sign in again on Tab 1 (QR Code or Email & Password), then retry.",
                )
            qs = step1.get("qs", f"%3Fsid%3D{sid}%26_json%3Dtrue")
            sign = step1.get("_sign", "")
            callback = step1.get("callback", "https://unlock.update.miui.com/sts")

            pwd_hash = hashlib.md5(password.encode("utf-8")).hexdigest().upper()
            form_data = urllib.parse.urlencode(
                {
                    "_json": "true",
                    "qs": qs,
                    "callback": callback,
                    "_sign": sign,
                    "sid": sid,
                    "user": user.strip(),
                    "hash": pwd_hash,
                }
            ).encode("utf-8")
            auth_req = urllib.request.Request(
                "https://account.xiaomi.com/pass/serviceLoginAuth2",
                data=form_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            raw_s2 = strip_xiaomi_prefix(
                safe_open_ignore_404(opener, auth_req, timeout=12, redirect_handler=redir_handler)
            )
            step2 = json.loads(raw_s2)

            notif_url = step2.get("notificationUrl")
            if notif_url and code_prompt_cb:
                if notif_url.startswith("/"):
                    notif_url = "https://account.xiaomi.com" + notif_url
                safe_open_ignore_404(opener, notif_url, timeout=12, redirect_handler=redir_handler)
                parsed_notif = urllib.parse.urlparse(notif_url)
                context_val = urllib.parse.parse_qs(parsed_notif.query).get("context", [""])[0]
                list_url = "https://account.xiaomi.com/identity/list?" + urllib.parse.urlencode(
                    {"sid": sid, "context": context_val, "_locale": "en_US"}
                )
                safe_open_ignore_404(opener, list_url, timeout=12, redirect_handler=redir_handler)

                def get_ick() -> str:
                    for c in jar:
                        if c.name == "ick":
                            return c.value
                    return ""

                # Always call `sendEmailTicket` FIRST (never `sendPhoneTicket` first, because
                # `sendPhoneTicket` triggers a 60s cooldown that blocks `sendEmailTicket`, and the
                # phone is in Fastboot mode so it cannot display incoming SMS!)
                s_url = "https://account.xiaomi.com/identity/auth/sendEmailTicket?" + urllib.parse.urlencode(
                    {
                        "_dc": str(int(time.time() * 1000)),
                        "sid": sid,
                        "context": context_val,
                        "mask": "0",
                        "_locale": "en_US",
                    }
                )
                s_req = urllib.request.Request(
                    s_url,
                    data=urllib.parse.urlencode(
                        {"retry": "0", "icode": "", "_json": "true", "ick": get_ick()}
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                s_raw = strip_xiaomi_prefix(
                    safe_open_ignore_404(opener, s_req, timeout=10, redirect_handler=redir_handler)
                )
                s_note = "Status: Requested 6-digit code via Gmail."
                try:
                    sj = json.loads(s_raw)
                    if sj.get("code") == 0:
                        s_note = "Status: Xiaomi confirmed NEW 6-digit code was just sent to your Gmail!"
                    else:
                        s_note = f"Status from Xiaomi: {sj}"
                except Exception:
                    pass

                otp = code_prompt_cb(
                    f"Xiaomi Unlock Server (`sid=unlockApi`) 2FA Verification\n"
                    f"{s_note}\n\n"
                    f"Enter the 6-digit code sent to your Gmail ({user}):"
                )
                if not otp:
                    return False, {}, "2FA verification cancelled."

                # Try verifying against Phone (`_flag=4`) first, then Email (`_flag=8`)
                floc = None
                for flag_v, ver_ep in (
                    ("4", "https://account.xiaomi.com/identity/auth/verifyPhone"),
                    ("8", "https://account.xiaomi.com/identity/auth/verifyEmail"),
                ):
                    v_url = f"{ver_ep}?" + urllib.parse.urlencode(
                        {"_flag": flag_v, "_json": "true", "sid": sid, "context": context_val, "mask": "0", "_locale": "en_US"}
                    )
                    v_req = urllib.request.Request(
                        v_url,
                        data=urllib.parse.urlencode(
                            {"_flag": flag_v, "ticket": otp.strip(), "trust": "true", "_json": "true", "ick": get_ick()}
                        ).encode("utf-8"),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    v_raw = strip_xiaomi_prefix(
                        safe_open_ignore_404(opener, v_req, timeout=12, redirect_handler=redir_handler)
                    )
                    try:
                        v_json = json.loads(v_raw)
                        floc = v_json.get("location") or v_json.get("finish_loc")
                        if floc or v_json.get("code") == 0:
                            break
                    except Exception:
                        pass

                if floc:
                    if floc.startswith("/"):
                        floc = "https://account.xiaomi.com" + floc
                    safe_open_ignore_404(opener, floc, timeout=12, redirect_handler=redir_handler)
                    raw_s2 = strip_xiaomi_prefix(
                        safe_open_ignore_404(opener, init_url, timeout=12, redirect_handler=redir_handler)
                    )
                    step2 = json.loads(raw_s2)

        ssecurity = step2.get("ssecurity") or redir_handler.last_ssecurity
        nonce = step2.get("nonce") if step2.get("nonce") is not None else redir_handler.last_nonce
        location = step2.get("location")
        user_id = str(step2.get("userId", ""))
        if not user_id:
            for c in jar:
                if c.name == "userId" and c.value:
                    user_id = c.value
                    break

        if not ssecurity or nonce is None or not location:
            return False, {}, f"Unlock API login failed (code={step2.get('code')}: {step2.get('desc')})"

        complete_callback_location(opener, jar, location, nonce, ssecurity, redir_handler)
        service_token = extract_token_from_jar(jar, captured_tokens)
        if not service_token:
            return False, {}, "Could not extract `serviceToken` from `unlock.update.miui.com/sts`."

        session_data = {
            "ssecurity": ssecurity,
            "userId": user_id,
            "serviceToken": service_token,
            "saved_at": time.time(),
        }
        try:
            with open(UNLOCK_SESSION_FILE, "w", encoding="utf-8") as uf:
                json.dump(session_data, uf)
        except Exception:
            pass

        return (
            True,
            session_data,
            "Authenticated with Xiaomi Unlock Server (`sid=unlockApi`).",
        )
    except Exception as e:
        return False, {}, f"Unlock API auth error: {e}"


def call_mi_unlock_endpoint(
    host: str,
    path: str,
    params_raw: dict,
    ssecurity: str,
    user_id: str,
    service_token: str,
    device_id_pc: str,
) -> dict:
    """Signs, AES-128-CBC encrypts, sends, and decrypts a Xiaomi Unlock Server API call."""
    import binascii
    import hmac

    ssecurity_key = base64.b64decode(ssecurity)
    iv = b"0102030405060708"
    params: Dict[str, object] = dict(params_raw)
    params["sid"] = "miui_unlocktool_client"

    if "data" in params and isinstance(params["data"], dict):
        json_str = json.dumps(params["data"])
        params["data"] = base64.b64encode(json_str.encode("utf-8")).decode("utf-8")

    param_order = sorted(params.keys())
    sign_params = "&".join(f"{k}={params[k]}" for k in param_order)
    sign_str = f"POST\n{path}\n{sign_params}"
    sign_hash_hex = (
        binascii.hexlify(hmac.new(MI_UNLOCK_HMAC_KEY, sign_str.encode("utf-8"), hashlib.sha1).digest())
        .decode("utf-8")
        .encode("utf-8")
    )
    current_sign = base64.b64encode(aes128_cbc_encrypt(sign_hash_hex, ssecurity_key, iv)).decode("utf-8")

    encoded_params: List[str] = []
    post_params: Dict[str, str] = {}
    for k in param_order:
        val_bytes = str(params[k]).encode("utf-8")
        encrypted = base64.b64encode(aes128_cbc_encrypt(val_bytes, ssecurity_key, iv)).decode("utf-8")
        encoded_params.append(f"{k}={encrypted}")
        post_params[k] = encrypted

    encoded_params.extend([f"sign={current_sign}", ssecurity])
    sha1_input = f"POST&{path}&{'&'.join(encoded_params)}"
    signature = base64.b64encode(hashlib.sha1(sha1_input.encode("utf-8")).digest()).decode("utf-8")

    post_params["sign"] = current_sign
    post_params["signature"] = signature

    qs = urllib.parse.urlencode(post_params)
    headers = {
        "User-Agent": "XiaomiPCSuite",
        "Cookie": f"userId={user_id};serviceToken={service_token};deviceId={device_id_pc}",
    }

    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, 443, timeout=15, context=ctx)
    conn.request("POST", f"{path}?{qs}", headers=headers)
    resp = conn.getresponse()
    raw_resp = resp.read().decode("utf-8", errors="replace").strip()
    conn.close()

    if resp.status in (401, 403):
        raise UnlockSessionExpiredError(
            f"HTTP {resp.status} {resp.reason} from `{path}` (cached Xiaomi Unlock session expired)."
        )
    if not raw_resp:
        raise UnlockSessionExpiredError(
            f"Empty response (HTTP {resp.status} {resp.reason}) from `{path}` — session may have expired."
        )
    if resp.status >= 300:
        raise RuntimeError(f"HTTP {resp.status} {resp.reason} from `{path}`: {raw_resp[:180]}")

    # Decrypt response body (base64 -> AES-128-CBC -> base64 -> UTF-8 JSON)
    try:
        dec_stage1 = aes128_cbc_decrypt(base64.b64decode(raw_resp), ssecurity_key, iv)
        dec_json_bytes = base64.b64decode(dec_stage1)
        return json.loads(dec_json_bytes.decode("utf-8", errors="replace"))
    except Exception as exc:
        raise RuntimeError(
            f"Unexpected response from Xiaomi Unlock Server (HTTP {resp.status}, {len(raw_resp)} chars): {exc}"
        ) from exc


def run_native_bootloader_unlocker(
    user: str,
    password: str,
    log_cb: Callable[[str], None],
    code_prompt_cb: Optional[Callable[[str], Optional[str]]] = None,
    confirm_unlock_cb: Optional[Callable[[str], bool]] = None,
) -> None:
    """
    Complete Native Xiaomi Fastboot Bootloader Unlocker:
    1. Checks connected Fastboot device & reads `product` and `token`.
    2. Logs into `sid=unlockApi` on Xiaomi Passport.
    3. Queries `unlock.update.intl.miui.com` (`/api/v2/nonce` + `/api/v2/unlock/device/clear` + `/api/v3/ahaUnlock`).
    4. Reports remaining wait hours (e.g., 72h timer) OR flashes `encryptData` to unlock!
    """
    import random

    log_cb("=== NATIVE XIAOMI FASTBOOT BOOTLOADER UNLOCKER ===")
    fcode, fb_out = run_tool_cmd(["fastboot", "devices"])
    if fcode != 0 or not fb_out.strip():
        log_cb(
            "[-] No device detected in Fastboot mode.\n"
            "    Please connect your phone in Fastboot mode (Volume Down + Power) first."
        )
        return

    product, device_token, raw_tok_log = read_fastboot_device_token()
    log_cb(f"[+] Fastboot Device : {fb_out.strip()}")
    log_cb(f"[+] Product Name    : {product or 'Unknown'}")
    log_cb(f"[+] Device Token    : {device_token or 'Empty'}")

    if not product or not device_token:
        log_cb("[!] Could not read `product` or `token` from Fastboot device.")
        log_cb("--- Raw Fastboot Token Output ---")
        log_cb(raw_tok_log)
        if "timed out" in raw_tok_log.lower():
            log_cb(
                "\n[TIP] Your phone's Fastboot USB session froze/timed out (very common on MediaTek VID_0E8D&PID_201C\n"
                "      if the phone sat idle in Fastboot or via a USB 3.0 port/hub):\n"
                "  1. Unplug the USB cable, hold Volume Down + Power (~10s) to enter a FRESH Fastboot screen.\n"
                "  2. Click 'Fix Windows Fastboot USB / Ryzen Bug' above once (patches MediaTek + Qualcomm USB3).\n"
                "  3. Replug into a direct motherboard port (USB 2.0 preferred) and click Unlock immediately!"
            )
        return

    if (
        not user
        and not password
        and not os.path.exists(SESSION_COOKIE_FILE)
        and not os.path.exists(UNLOCK_SESSION_FILE)
    ):
        log_cb(
            "[!] Please enter your Xiaomi Email/Phone/ID and Password in Tab 1 (Method A) first\n"
            "    so the Native Unlocker can sign the cryptographic `sid=unlockApi` request."
        )
        return

    host = "unlock.update.intl.miui.com"
    res = None
    for attempt in (1, 2):
        log_cb(
            "[*] Authenticating with Xiaomi Unlock Server (`sid=unlockApi`)..."
            if attempt == 1
            else "[*] Refreshing expired Xiaomi Unlock Server session (`sid=unlockApi`)..."
        )
        ok, session, auth_msg = login_xiaomi_unlock_api(
            user,
            password,
            code_prompt_cb=code_prompt_cb,
            force_refresh=(attempt == 2),
        )
        log_cb(f"    {auth_msg}")
        if not ok:
            return

        ssecurity = session["ssecurity"]
        user_id = session["userId"]
        service_token = session["serviceToken"]
        dev_id_cookie = "wb_" + hashlib.md5(user_id.encode("utf-8")).hexdigest()[:12]
        pc_id = hashlib.md5(dev_id_cookie.encode("utf-8")).hexdigest()

        try:
            log_cb(f"[*] Requesting cryptographic nonce from `{host}/api/v2/nonce`...")
            r_val = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=16))
            nonce_resp = call_mi_unlock_endpoint(
                host,
                "/api/v2/nonce",
                {"r": r_val},
                ssecurity,
                user_id,
                service_token,
                dev_id_cookie,
            )
            if nonce_resp.get("code") != 0 or not nonce_resp.get("nonce"):
                log_cb(f"[!] Failed to obtain server nonce: {nonce_resp}")
                return

            server_nonce = nonce_resp["nonce"]
            log_cb(f"[+] Received server nonce ({len(server_nonce)} chars). Querying `/api/v2/unlock/device/clear`...")

            clear_resp = call_mi_unlock_endpoint(
                host,
                "/api/v2/unlock/device/clear",
                {"appId": "1", "data": {"product": product}, "nonce": server_nonce},
                ssecurity,
                user_id,
                service_token,
                dev_id_cookie,
            )
            if clear_resp.get("notice"):
                log_cb(f"[*] Device Notice   : {clear_resp.get('notice')}")

            log_cb("[*] Requesting bootloader unlock authorization (`/api/v3/ahaUnlock`)...")
            aha_data = {
                "clientId": "2",
                "clientVersion": "7.6.727.43",
                "deviceInfo": {
                    "boardVersion": "",
                    "deviceName": "",
                    "product": product,
                    "socId": "",
                },
                "deviceToken": device_token,
                "language": "en",
                "operate": "unlock",
                "pcId": pc_id,
                "region": "",
                "uid": user_id,
            }
            res = call_mi_unlock_endpoint(
                host,
                "/api/v3/ahaUnlock",
                {"appId": "1", "data": aha_data, "nonce": server_nonce},
                ssecurity,
                user_id,
                service_token,
                dev_id_cookie,
            )
            break
        except UnlockSessionExpiredError as exp_err:
            log_cb(f"[!] {exp_err}")
            try:
                if os.path.exists(UNLOCK_SESSION_FILE):
                    os.remove(UNLOCK_SESSION_FILE)
            except Exception:
                pass
            if attempt == 2:
                log_cb("[!] Session still rejected after refresh. Please sign in again on Tab 1 and retry.")
                return
        except Exception as e:
            log_cb(f"[!] Error communicating with Xiaomi Unlock Server: {e}")
            return

    if res is None:
        return

    code = res.get("code")
    desc = res.get("description") or res.get("descEN") or res.get("descCN") or str(res)

    if code == 0 and res.get("encryptData"):
        enc_hex = res["encryptData"]
        log_cb("\n" + "=" * 60)
        log_cb("  [READY TO UNLOCK] Xiaomi Server Signed Your Unlock Token!")
        log_cb("=" * 60)
        if confirm_unlock_cb:
            proceed = confirm_unlock_cb(
                "Xiaomi's server approved and signed your unlock token!\n\n"
                "⚠️ WARNING: Proceeding will UNLOCK the bootloader and FACTORY RESET (wipe all data on) your phone.\n\n"
                "Do you want to flash the unlock token and unlock your phone right now?"
            )
            if not proceed:
                log_cb("[*] Unlock cancelled by user (signed token was NOT flashed; your data is untouched).")
                return

        bin_path = os.path.join(get_writable_dir(), "unlock_token.bin")
        with open(bin_path, "wb") as bf:
            bf.write(bytes.fromhex(enc_hex))

        log_cb("[*] Staging signed 256-byte token via `fastboot stage`...")
        _, stage_out = run_tool_cmd(["fastboot", "stage", bin_path], timeout=15.0)
        log_cb(f"    {stage_out}")
        log_cb("[*] Executing `fastboot oem unlock`...")
        _, unl_out = run_tool_cmd(["fastboot", "oem", "unlock"], timeout=20.0)
        log_cb(f"    {unl_out}")
        try:
            os.remove(bin_path)
        except Exception:
            pass
    elif code == 20036:
        hours = (res.get("data") or {}).get("waitHour", "?")
        days = round(float(hours) / 24.0, 1) if str(hours).isdigit() else "?"
        log_cb("\n" + "=" * 60)
        log_cb(f"  [WAITING PERIOD ACTIVE] Remaining Wait Time: {hours} Hours (~{days} Days)")
        log_cb("=" * 60)
        log_cb(f"  Server Message: {desc}")
        log_cb("  Do NOT tap 'Add account and device' again — just wait until the hours above reach 0!")
    else:
        log_cb(f"\n[!] Xiaomi Unlock Server Response (Code {code}):\n    {desc}\n    Raw: {res}")


def apply_windows_fastboot_usb_fix() -> str:
    """
    Creates and runs an elevated Windows USB Fastboot Fix script (`fix_fastboot_usb.bat`)
    that patches the Windows USB 3.0 / AMD Ryzen Fastboot disconnect issue (`SkipBOSDescriptorQuery`)
    and opens Windows Device Manager / Optional Driver updates.
    """
    if sys.platform != "win32":
        return "Windows Fastboot USB fix is only needed on Windows OS."

    bat_path = os.path.join(get_writable_dir(), "fix_fastboot_usb.bat")
    bat_content = r"""@echo off
echo ================================================================
echo   Xiaomi / POCO / MediaTek Fastboot USB 3.0 ^& Ryzen Registry Fix
echo ================================================================
for %%K in (18D1D00D0100 0E8D201C0100 0E8D201C0404 0E8D00030100 2717FF080223 2717FF480223) do (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbflags\%%K" /v "osvc" /t REG_BINARY /d "0000" /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbflags\%%K" /v "SkipContainerIdQuery" /t REG_BINARY /d "01000000" /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbflags\%%K" /v "SkipBOSDescriptorQuery" /t REG_BINARY /d "01000000" /f >nul 2>&1
)
echo.
echo [+] Applied Fastboot USB 3.0 / Ryzen stability flags for Qualcomm (18D1:D00D),
echo     MediaTek (0E8D:201C), and Xiaomi (2717:FF08/FF48)!
echo [*] Unplug your phone, reboot into a fresh Fastboot screen, and replug USB.
echo [*] Opening Windows Update Optional Drivers page (if any Kedacom/Android Bootloader driver is pending)...
start ms-settings:windowsupdate-optionalupdates
pause
"""
    with open(bat_path, "w", encoding="utf-8") as f:
        f.write(bat_content)

    try:
        subprocess.Popen(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f'Start-Process -FilePath "{bat_path}" -Verb RunAs',
            ]
        )
        return (
            "=== WINDOWS FASTBOOT USB DRIVER & RYZEN FIX ===\n"
            "[+] Launched Administrator USB Fix script (`fix_fastboot_usb.bat`).\n"
            "    Click 'Yes' on the Windows UAC prompt to apply the Fastboot USB 3.0 registry fix.\n"
            "    It will also open Windows Optional Updates so you can install 'Android Bootloader Interface' if needed."
        )
    except Exception as e:
        return f"Created `{bat_path}`, please right-click it and choose 'Run as administrator'. ({e})"


def launch_or_download_mi_unlock(log_cb: Optional[Callable[[str], None]] = None) -> None:
    """
    Checks if Xiaomi's official Mi Unlock tool (`miflash_unlock.exe`) exists in `./mi-unlock/`.
    If not, automatically downloads and extracts it from Xiaomi's official CDN and launches it.
    """
    import io
    import zipfile

    mi_dir = os.path.join(get_writable_dir(), "mi-unlock")
    exe_path = os.path.join(mi_dir, "miflash_unlock.exe")
    if not os.path.isfile(exe_path):
        # Search subdirectories inside mi-unlock
        if os.path.isdir(mi_dir):
            for root_d, _, files in os.walk(mi_dir):
                if "miflash_unlock.exe" in files:
                    exe_path = os.path.join(root_d, "miflash_unlock.exe")
                    break

    if not os.path.isfile(exe_path):
        url = "https://miuirom.Xiaomi.com/rom/u1106245679/7.6.727.43/miflash_unlock_en_7.6.727.43.zip"
        if log_cb:
            log_cb(
                "=== OFFICIAL MI UNLOCK TOOL ===\n"
                "[*] Downloading official Xiaomi Mi Unlock v7.6.727.43 (~90 MB)...\n"
                f"    Source: {url}\n"
                "    Please wait 15-30 seconds while it downloads and extracts into `./mi-unlock/`..."
            )
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=180, context=ctx) as resp:
                zip_data = resp.read()
            os.makedirs(mi_dir, exist_ok=True)
            with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                zf.extractall(mi_dir)
            for root_d, _, files in os.walk(mi_dir):
                if "miflash_unlock.exe" in files:
                    exe_path = os.path.join(root_d, "miflash_unlock.exe")
                    break
        except Exception as e:
            if log_cb:
                log_cb(
                    f"[!] Automatic download failed ({e}).\n"
                    "    Opening official Mi Unlock download page in browser..."
                )
            webbrowser.open("https://en.miui.com/unlock/download_en.html")
            return

    if os.path.isfile(exe_path):
        try:
            os.startfile(exe_path)  # type: ignore[attr-defined]
            if log_cb:
                log_cb(
                    "=== OFFICIAL MI UNLOCK TOOL ===\n"
                    f"[+] Launched `{exe_path}`!\n"
                    "    Log in with your Mi Account, connect your phone in Fastboot mode, and click Unlock."
                )
        except Exception as e:
            if log_cb:
                log_cb(f"[!] Extracted to `{exe_path}`, please launch it manually ({e}).")


def install_adb_fastboot_drivers(log_cb: Optional[Callable[[str], None]] = None) -> str:
    """
    Installs official Xiaomi and Google ADB & Fastboot USB drivers on Windows.
    Automatically ensures the driver files exist (downloading if missing), then launches
    an elevated Administrator script using `pnputil /add-driver ... /install` and `MiUsbDriver.exe`.
    """
    if sys.platform != "win32":
        return "ADB & Fastboot driver installer is only required for Windows OS (Linux/macOS include kernel drivers)."

    mi_dir = os.path.join(get_writable_dir(), "mi-unlock")
    inf_path = os.path.join(mi_dir, "driver", "win10", "android_winusb.inf")
    usb_exe = os.path.join(mi_dir, "MiUsbDriver.exe")
    d64_exe = os.path.join(mi_dir, "driver_install_64.exe")

    if not os.path.isfile(inf_path):
        if log_cb:
            log_cb("[*] Driver package not found locally. Auto-downloading official driver bundle (~83 MB)...")
        launch_or_download_mi_unlock(log_cb)

    bat_path = os.path.join(get_writable_dir(), "install_drivers.bat")
    bat_content = """@echo off
echo ================================================================
echo   Xiaomi / POCO Official ADB ^& Fastboot USB Driver Installer
echo ================================================================
echo.
cd /d "%~dp0"

echo [*] Step 1: Installing Xiaomi ^& Android USB Drivers via Windows PnPUtil...
if exist "%~dp0mi-unlock\\driver\\win10\\android_winusb.inf" (
    pnputil /add-driver "%~dp0mi-unlock\\driver\\win10\\android_winusb.inf" /install
    echo [+] PnPUtil driver registration finished.
) else (
    echo [!] INF file not found at: %~dp0mi-unlock\\driver\\win10\\android_winusb.inf
)

echo.
echo [*] Step 2: Running Xiaomi Official Driver Installer Wizard...
if exist "%~dp0mi-unlock\\MiUsbDriver.exe" (
    start "" /wait "%~dp0mi-unlock\\MiUsbDriver.exe"
) else if exist "%~dp0mi-unlock\\driver_install_64.exe" (
    start "" /wait "%~dp0mi-unlock\\driver_install_64.exe"
)

echo.
echo [*] Step 3: Opening Windows Device Manager to verify connection...
start devmgmt.msc

echo.
echo ================================================================
echo [+] USB Driver Installation Complete!
echo     If your phone is in Fastboot mode, it should now appear as:
echo     "Android Bootloader Interface" or "Kedacom USB Device".
echo ================================================================
pause
"""
    with open(bat_path, "w", encoding="utf-8") as f:
        f.write(bat_content)

    try:
        subprocess.Popen(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f'Start-Process -FilePath "{bat_path}" -Verb RunAs',
            ]
        )
        return (
            "=== OFFICIAL ADB & FASTBOOT USB DRIVER INSTALLER ===\n"
            "[+] Launched Administrator Driver Installer (`install_drivers.bat`).\n"
            "    1. Click 'Yes' on the Windows UAC elevation prompt.\n"
            "    2. Windows PnPUtil will install `android_winusb.inf` into your Windows Driver Store.\n"
            "    3. The Xiaomi Driver Wizard will run to ensure USB communication is 100% stable."
        )
    except Exception as e:
        return f"Created `{bat_path}`, please right-click and 'Run as administrator' ({e})."


# ============================================================================
# DARK-MODE DESKTOP GUI (TKINTER)
# ============================================================================

def launch_gui() -> None:
    import tkinter as tk
    from tkinter import messagebox, simpledialog, ttk

    BG_DARK = "#0f172a"
    BG_CARD = "#1e293b"
    BG_INPUT = "#0b1120"
    FG_TEXT = "#f8fafc"
    FG_MUTED = "#94a3b8"
    ACCENT = "#ff6700"      # Xiaomi/POCO Orange
    ACCENT_BLUE = "#38bdf8"
    SUCCESS = "#22c55e"
    WARN = "#f59e0b"
    DANGER = "#ef4444"

    root = tk.Tk()
    root.title(f"{APP_NAME} v{APP_VERSION} — Xiaomi HyperOS Eligibility & Fastboot Servicing Utility")
    root.geometry("920x700")
    root.minsize(860, 650)
    root.configure(bg=BG_DARK)

    # Set Window Taskbar & Titlebar Icon
    for icon_candidate in (
        os.path.join(get_base_dir(), "icon.ico"),
        os.path.join(get_writable_dir(), "icon.ico"),
    ):
        if os.path.isfile(icon_candidate):
            try:
                root.iconbitmap(icon_candidate)
                break
            except Exception:
                pass

    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass

    style.configure("TNotebook", background=BG_DARK, borderwidth=0)
    style.configure(
        "TNotebook.Tab",
        background=BG_CARD,
        foreground=FG_MUTED,
        padding=(18, 10),
        font=("Segoe UI", 10, "bold"),
        borderwidth=0,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", ACCENT)],
        foreground=[("selected", "#ffffff")],
    )

    # Top Header Bar
    header = tk.Frame(root, bg=BG_CARD, padx=20, pady=12)
    header.pack(fill="x")
    tk.Label(
        header,
        text=f"⚡ {APP_NAME}",
        bg=BG_CARD,
        fg=ACCENT,
        font=("Segoe UI", 16, "bold"),
    ).pack(side="left")
    tk.Label(
        header,
        text="Xiaomi & POCO HyperOS Bootloader Eligibility & ADB/Fastboot Utility",
        bg=BG_CARD,
        fg=FG_MUTED,
        font=("Segoe UI", 10),
        padx=12,
    ).pack(side="left")

    status_pill = tk.Label(
        header,
        text="STATUS: UNCHECKED",
        bg="#334155",
        fg=FG_TEXT,
        font=("Segoe UI", 9, "bold"),
        padx=10,
        pady=4,
    )
    status_pill.pack(side="right")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=14, pady=10)

    tab_auth = tk.Frame(notebook, bg=BG_DARK)
    tab_sniper = tk.Frame(notebook, bg=BG_DARK)
    tab_device = tk.Frame(notebook, bg=BG_DARK)
    tab_console = tk.Frame(notebook, bg=BG_DARK)

    notebook.add(tab_auth, text="  1. Account & Login  ")
    notebook.add(tab_sniper, text="  2. Scheduled Eligibility Window (00:00 GMT+8)  ")
    notebook.add(tab_device, text="  3. ADB / Fastboot & Native Unlocker  ")
    notebook.add(tab_console, text="  4. Interactive CMD / ADB / Fastboot Console  ")

    # Shared State Variables
    token_var = tk.StringVar(value=load_saved_token())
    email_var = tk.StringVar()
    pass_var = tk.StringVar()
    show_token_var = tk.BooleanVar(value=False)
    strategy_var = tk.StringVar(value="queue")
    custom_ms_var = tk.StringVar(value="-850")
    ntp_info_var = tk.StringVar(value="Not synced yet")
    rtt_info_var = tk.StringVar(value="Not measured yet")
    countdown_var = tk.StringVar(value="00:00:00")
    beijing_clock_var = tk.StringVar(value="--:--:-- GMT+8")

    sniper_running = {"active": False, "stop_event": threading.Event()}
    calib = {"ntp_offset": 0.0, "one_way": 0.105}

    def update_status_badge(tag: str, message: str):
        colors = {
            "APPROVED": SUCCESS,
            "ELIGIBLE": SUCCESS,
            "WAIT": WARN,
            "AGE_LIMIT": DANGER,
            "EXPIRED": DANGER,
            "ERROR": DANGER,
        }
        status_pill.configure(text=f"ACCOUNT: {tag}", bg=colors.get(tag, "#334155"))
        auth_status_box.configure(state="normal")
        auth_status_box.delete("1.0", "end")
        auth_status_box.insert("end", f"[{tag}] {message}\n")
        auth_status_box.configure(state="disabled")

    # ------------------------------------------------------------------------
    # TAB 1: ACCOUNT & LOGIN
    # ------------------------------------------------------------------------
    auth_container = tk.Frame(tab_auth, bg=BG_DARK, padx=14, pady=10)
    auth_container.pack(fill="both", expand=True)

    # Method A: Direct Xiaomi Account Login
    card_login = tk.Frame(auth_container, bg=BG_CARD, padx=16, pady=12)
    card_login.pack(fill="x", pady=(0, 10))
    tk.Label(
        card_login,
        text="Method A — Direct Xiaomi Account Login (Auto-Extracts Token)",
        bg=BG_CARD,
        fg=ACCENT_BLUE,
        font=("Segoe UI", 11, "bold"),
    ).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 8))

    tk.Label(card_login, text="Email / Phone / Mi ID:", bg=BG_CARD, fg=FG_TEXT, font=("Segoe UI", 9)).grid(
        row=1, column=0, sticky="w", padx=(0, 8)
    )
    tk.Entry(
        card_login,
        textvariable=email_var,
        bg=BG_INPUT,
        fg=FG_TEXT,
        insertbackground=FG_TEXT,
        relief="flat",
        width=28,
        font=("Consolas", 10),
    ).grid(row=1, column=1, sticky="w", padx=(0, 16), ipady=4)

    tk.Label(card_login, text="Password:", bg=BG_CARD, fg=FG_TEXT, font=("Segoe UI", 9)).grid(
        row=1, column=2, sticky="w", padx=(0, 8)
    )
    tk.Entry(
        card_login,
        textvariable=pass_var,
        show="*",
        bg=BG_INPUT,
        fg=FG_TEXT,
        insertbackground=FG_TEXT,
        relief="flat",
        width=24,
        font=("Consolas", 10),
    ).grid(row=1, column=3, sticky="w", ipady=4)

    def on_direct_login():
        u = email_var.get().strip()
        p = pass_var.get()
        if not u or not p:
            messagebox.showwarning("Missing Credentials", "Please enter your Xiaomi Email/Phone/ID and Password.")
            return
        btn_login.configure(state="disabled", text="Signing in...")

        def ask_2fa_code_threadsafe(prompt_msg: str) -> Optional[str]:
            evt = threading.Event()
            holder: Dict[str, Optional[str]] = {"code": None}

            def _ask():
                holder["code"] = simpledialog.askstring(
                    "Xiaomi 2FA Verification Code",
                    prompt_msg,
                    parent=root,
                )
                evt.set()

            root.after(0, _ask)
            evt.wait()
            return holder["code"]

        def worker():
            ok, result_str, verify_url = login_xiaomi_passport(u, p, code_prompt_cb=ask_2fa_code_threadsafe)

            def done():
                btn_login.configure(state="normal", text="Sign In & Extract Token")
                if ok:
                    token_var.set(result_str)
                    tag, msg, _ = query_account_state(result_str)
                    update_status_badge(tag, f"Token extracted automatically via Direct Login!\n{msg}")
                    messagebox.showinfo("Login Successful", "Successfully extracted & saved `new_bbs_serviceToken`!")
                else:
                    update_status_badge("ERROR", result_str)
                    if verify_url:
                        if messagebox.askyesno(
                            "Security Verification Required",
                            f"{result_str}\n\nOpen Xiaomi login page in your browser now?",
                        ):
                            webbrowser.open(verify_url)
                    else:
                        messagebox.showerror("Login Failed", result_str)

            root.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    btn_login = tk.Button(
        card_login,
        text="Sign In & Extract Token",
        command=on_direct_login,
        bg=ACCENT,
        fg="#ffffff",
        activebackground="#e05a00",
        activeforeground="#ffffff",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=12,
        pady=5,
        cursor="hand2",
    )
    btn_login.grid(row=1, column=4, padx=(12, 6))

    def on_qr_login():
        btn_qr.configure(state="disabled", text="Loading QR...")

        def init_worker():
            ok, meta, png_bytes, err = start_xiaomi_qr_session(PASSPORT_SID)

            def show_qr_modal():
                btn_qr.configure(state="normal", text="📱 Sign In via QR")
                if not ok:
                    messagebox.showerror("QR Login Error", err)
                    return

                qr_win = tk.Toplevel(root)
                qr_win.title("Scan Xiaomi QR Code (No Email/SMS Code Needed)")
                qr_win.geometry("420x440")
                qr_win.configure(bg=BG_CARD)
                qr_win.transient(root)

                stop_qr = threading.Event()

                def on_close_qr():
                    stop_qr.set()
                    qr_win.destroy()

                qr_win.protocol("WM_DELETE_WINDOW", on_close_qr)

                tk.Label(
                    qr_win,
                    text="Scan with Your Xiaomi / POCO Phone",
                    bg=BG_CARD,
                    fg=ACCENT,
                    font=("Segoe UI", 12, "bold"),
                    pady=8,
                ).pack()

                tk.Label(
                    qr_win,
                    text=(
                        "On your phone: Go to Settings -> Xiaomi Account\n"
                        "and tap the QR Scanner icon in the top-right corner!"
                    ),
                    bg=BG_CARD,
                    fg=FG_TEXT,
                    font=("Segoe UI", 9),
                ).pack(pady=(0, 10))

                b64_png = base64.b64encode(png_bytes)
                qr_img = tk.PhotoImage(data=b64_png)
                img_lbl = tk.Label(qr_win, image=qr_img, bg="#ffffff", padx=10, pady=10)
                img_lbl.image = qr_img  # type: ignore[attr-defined]
                img_lbl.pack(pady=6)

                qr_status_lbl = tk.Label(
                    qr_win,
                    text="Waiting for you to scan QR code on phone...",
                    bg=BG_CARD,
                    fg=ACCENT_BLUE,
                    font=("Segoe UI", 9, "bold"),
                    pady=8,
                )
                qr_status_lbl.pack()

                def poll_worker():
                    success, tok_or_err = poll_xiaomi_qr_login(meta, stop_qr)

                    def finish():
                        if stop_qr.is_set():
                            return
                        stop_qr.set()
                        try:
                            qr_win.destroy()
                        except Exception:
                            pass
                        if success:
                            token_var.set(tok_or_err)
                            tag, msg, _ = query_account_state(tok_or_err)
                            update_status_badge(
                                tag,
                                f"Logged in via QR Code! Session & Token saved.\n{msg}",
                            )
                            messagebox.showinfo(
                                "QR Login Successful",
                                "Successfully signed in via QR Code and saved both `token.txt` and `xiaomi_session.txt`!",
                            )
                        else:
                            update_status_badge("ERROR", tok_or_err)

                    root.after(0, finish)

                threading.Thread(target=poll_worker, daemon=True).start()

            root.after(0, show_qr_modal)

        threading.Thread(target=init_worker, daemon=True).start()

    btn_qr = tk.Button(
        card_login,
        text="📱 Sign In via QR",
        command=on_qr_login,
        bg="#0284c7",
        fg="#ffffff",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=10,
        pady=5,
        cursor="hand2",
    )
    btn_qr.grid(row=1, column=5, padx=(0, 4))

    # Method B: Browser Login & Cookie Helper
    card_browser = tk.Frame(auth_container, bg=BG_CARD, padx=16, pady=12)
    card_browser.pack(fill="x", pady=(0, 10))
    tk.Label(
        card_browser,
        text="Method B — Browser Login (Best for Google Sign-In / 2FA Accounts)",
        bg=BG_CARD,
        fg=ACCENT_BLUE,
        font=("Segoe UI", 11, "bold"),
    ).pack(anchor="w")
    tk.Label(
        card_browser,
        text=(
            "1. Click 'Open Xiaomi Community Global' below and sign in.\n"
            "2. Press F12 -> Application -> Cookies -> https://c.mi.com -> copy `new_bbs_serviceToken`.\n"
            "3. Paste it into Method C below and click 'Save & Verify Eligibility'."
        ),
        bg=BG_CARD,
        fg=FG_MUTED,
        justify="left",
        font=("Segoe UI", 9),
        pady=4,
    ).pack(anchor="w")
    tk.Button(
        card_browser,
        text="🌐 Open Xiaomi Community Global (c.mi.com/global)",
        command=lambda: webbrowser.open("https://c.mi.com/global"),
        bg="#334155",
        fg=FG_TEXT,
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=12,
        pady=4,
        cursor="hand2",
    ).pack(anchor="w", pady=(4, 0))

    # Method C: Manual Token Entry & Verification
    card_token = tk.Frame(auth_container, bg=BG_CARD, padx=16, pady=12)
    card_token.pack(fill="x", pady=(0, 10))
    tk.Label(
        card_token,
        text="Method C — Manual `new_bbs_serviceToken` Cookie & Account Verification",
        bg=BG_CARD,
        fg=ACCENT_BLUE,
        font=("Segoe UI", 11, "bold"),
    ).pack(anchor="w", pady=(0, 6))

    tok_row = tk.Frame(card_token, bg=BG_CARD)
    tok_row.pack(fill="x")
    tok_entry = tk.Entry(
        tok_row,
        textvariable=token_var,
        show="*" if not show_token_var.get() else "",
        bg=BG_INPUT,
        fg=FG_TEXT,
        insertbackground=FG_TEXT,
        relief="flat",
        font=("Consolas", 10),
    )
    tok_entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))

    def toggle_token_mask():
        tok_entry.configure(show="" if show_token_var.get() else "*")

    tk.Checkbutton(
        tok_row,
        text="Show",
        variable=show_token_var,
        command=toggle_token_mask,
        bg=BG_CARD,
        fg=FG_MUTED,
        selectcolor=BG_INPUT,
        activebackground=BG_CARD,
        activeforeground=FG_TEXT,
    ).pack(side="left", padx=(0, 8))

    def on_verify_token():
        tok = clean_token_string(token_var.get())
        if not tok:
            messagebox.showwarning("No Token", "Please paste your `new_bbs_serviceToken` or sign in above.")
            return
        token_var.set(tok)
        save_token(tok)

        def worker():
            tag, msg, _ = query_account_state(tok)
            root.after(0, lambda: update_status_badge(tag, msg))

        threading.Thread(target=worker, daemon=True).start()

    tk.Button(
        tok_row,
        text="✔ Save & Verify Eligibility",
        command=on_verify_token,
        bg=SUCCESS,
        fg="#ffffff",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=14,
        pady=5,
        cursor="hand2",
    ).pack(side="left")

    # Account Status Output Box
    auth_status_box = tk.Text(
        auth_container,
        height=5,
        bg=BG_INPUT,
        fg=FG_TEXT,
        font=("Consolas", 10),
        relief="flat",
        padx=12,
        pady=10,
         state="disabled",
    )
    auth_status_box.pack(fill="both", expand=True)

    # ------------------------------------------------------------------------
    # TAB 2: SCHEDULED ELIGIBILITY WINDOW (00:00:00 GMT+8)
    # ------------------------------------------------------------------------
    sniper_container = tk.Frame(tab_sniper, bg=BG_DARK, padx=14, pady=10)
    sniper_container.pack(fill="both", expand=True)

    top_stats = tk.Frame(sniper_container, bg=BG_DARK)
    top_stats.pack(fill="x", pady=(0, 10))

    # Countdown Card
    card_clock = tk.Frame(top_stats, bg=BG_CARD, padx=18, pady=12)
    card_clock.pack(side="left", fill="both", expand=True, padx=(0, 8))
    tk.Label(card_clock, text="COUNTDOWN TO 00:00:00 GMT+8", bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9, "bold")).pack(
        anchor="w"
    )
    tk.Label(card_clock, textvariable=countdown_var, bg=BG_CARD, fg=ACCENT, font=("Consolas", 26, "bold")).pack(
        anchor="w", pady=2
    )
    tk.Label(card_clock, textvariable=beijing_clock_var, bg=BG_CARD, fg=FG_TEXT, font=("Consolas", 10)).pack(
        anchor="w"
    )

    # Network Telemetry Card
    card_net = tk.Frame(top_stats, bg=BG_CARD, padx=18, pady=12)
    card_net.pack(side="left", fill="both", expand=True)
    tk.Label(
        card_net, text="ATOMIC NTP & SINGAPORE API TELEMETRY", bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9, "bold")
    ).pack(anchor="w")
    tk.Label(card_net, textvariable=ntp_info_var, bg=BG_CARD, fg=FG_TEXT, font=("Consolas", 10), pady=2).pack(
        anchor="w"
    )
    tk.Label(card_net, textvariable=rtt_info_var, bg=BG_CARD, fg=FG_TEXT, font=("Consolas", 10), pady=2).pack(
        anchor="w"
    )

    def calibrate_network(log_to_box: bool = True):
        def worker():
            off, srv = get_ntp_offset()
            rtt = measure_api_rtt(clean_token_string(token_var.get()))
            calib["ntp_offset"] = off
            calib["one_way"] = rtt / 2.0

            def done():
                ntp_info_var.set(f"NTP Server : {srv} ({off:+.4f}s)")
                rtt_info_var.set(f"Xiaomi RTT : {rtt*1000:.1f} ms (One-way: {rtt*500:.1f} ms)")
                if log_to_box:
                    append_sniper_log(
                        f"[*] Calibrated NTP ({srv}: {off:+.4f}s) | Xiaomi API RTT: {rtt*1000:.1f}ms"
                    )

            root.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    tk.Button(
        card_net,
        text="🔄 Recalibrate NTP & Ping Now",
        command=lambda: calibrate_network(True),
        bg="#334155",
        fg=FG_TEXT,
        relief="flat",
        font=("Segoe UI", 8, "bold"),
        padx=10,
        pady=3,
        cursor="hand2",
    ).pack(anchor="w", pady=(4, 0))

    # Timing Strategy Card
    card_strat = tk.Frame(sniper_container, bg=BG_CARD, padx=16, pady=10)
    card_strat.pack(fill="x", pady=(0, 10))
    tk.Label(
        card_strat,
        text="NTP Timing Strategy (Pre-Warmed TCP_NODELAY Keep-Alive Connections):",
        bg=BG_CARD,
        fg=ACCENT_BLUE,
        font=("Segoe UI", 10, "bold"),
    ).pack(anchor="w", pady=(0, 4))

    strat_row = tk.Frame(card_strat, bg=BG_CARD)
    strat_row.pack(fill="x")
    tk.Radiobutton(
        strat_row,
        text="Smart Pre-Midnight Queue Offset (-1450ms to -180ms) [Recommended]",
        variable=strategy_var,
        value="queue",
        bg=BG_CARD,
        fg=FG_TEXT,
        selectcolor=BG_INPUT,
        activebackground=BG_CARD,
    ).pack(side="left", padx=(0, 14))
    tk.Radiobutton(
        strat_row,
        text="Exact Ping-Compensated (+15ms to +250ms)",
        variable=strategy_var,
        value="ping",
        bg=BG_CARD,
        fg=FG_TEXT,
        selectcolor=BG_INPUT,
        activebackground=BG_CARD,
    ).pack(side="left", padx=(0, 14))
    tk.Radiobutton(
        strat_row,
        text="Custom Offset (ms):",
        variable=strategy_var,
        value="custom",
        bg=BG_CARD,
        fg=FG_TEXT,
        selectcolor=BG_INPUT,
        activebackground=BG_CARD,
    ).pack(side="left")
    tk.Entry(
        strat_row,
        textvariable=custom_ms_var,
        width=8,
        bg=BG_INPUT,
        fg=FG_TEXT,
        insertbackground=FG_TEXT,
        relief="flat",
        font=("Consolas", 10),
    ).pack(side="left", padx=6, ipady=2)

    # Action Buttons
    action_row = tk.Frame(sniper_container, bg=BG_DARK)
    action_row.pack(fill="x", pady=(0, 8))

    sniper_log = tk.Text(
        sniper_container,
        bg=BG_INPUT,
        fg="#e2e8f0",
        font=("Consolas", 9),
        relief="flat",
        padx=12,
        pady=10,
        state="disabled",
    )
    sniper_log.pack(fill="both", expand=True)

    def append_sniper_log(line: str):
        def _do():
            sniper_log.configure(state="normal")
            sniper_log.insert("end", line + "\n")
            sniper_log.see("end")
            sniper_log.configure(state="disabled")

        root.after(0, _do)

    def toggle_arm_sniper():
        tok = clean_token_string(token_var.get())
        if not tok:
            messagebox.showwarning("Token Required", "Please configure your token in Tab 1 first.")
            return
        if sniper_running["active"]:
            sniper_running["active"] = False
            sniper_running["stop_event"].set()
            btn_arm.configure(text="🚀 Schedule Request for 00:00:00 GMT+8", bg=ACCENT)
            append_sniper_log("[!] Scheduler disarmed by user.")
            return

        save_token(tok)
        sniper_running["active"] = True
        sniper_running["stop_event"] = threading.Event()
        btn_arm.configure(text="⏹ Cancel Scheduled Request (Waiting...)", bg=DANGER)

        try:
            cms = float(custom_ms_var.get().strip())
        except ValueError:
            cms = -850.0
        offsets = compute_burst_offsets(strategy_var.get(), calib["one_way"], cms)
        off_str = ", ".join([f"{o*1000:+.0f}ms" for o in offsets])
        append_sniper_log(f"[*] ARMED! Strategy='{strategy_var.get()}' | 6 Request Offsets: [{off_str}]")

        def sniper_worker():
            stop_evt = sniper_running["stop_event"]
            now_ntp = time.time() + calib["ntp_offset"]
            target_dt = get_next_midnight_beijing(now_ntp)
            target_ts = target_dt.timestamp()
            recalibrated = False

            while not stop_evt.is_set() and sniper_running["active"]:
                now_ntp = time.time() + calib["ntp_offset"]
                rem = target_ts - now_ntp
                if rem <= 60.0 and not recalibrated:
                    recalibrated = True
                    off, srv = get_ntp_offset()
                    rtt = measure_api_rtt(tok)
                    calib["ntp_offset"] = off
                    calib["one_way"] = rtt / 2.0
                    append_sniper_log(
                        f"[*] T-60s Recalibration: NTP={off:+.4f}s ({srv}), RTT={rtt*1000:.1f}ms"
                    )
                if rem <= 10.0:
                    break
                time.sleep(0.25)

            if stop_evt.is_set() or not sniper_running["active"]:
                return

            try:
                cms_val = float(custom_ms_var.get().strip())
            except ValueError:
                cms_val = -850.0
            final_offsets = compute_burst_offsets(strategy_var.get(), calib["one_way"], cms_val)
            append_sniper_log("[*] T-10s: Preparing 6 HTTP/1.1 Keep-Alive TLS connections...")

            results = []
            threads = []
            dev_id = generate_device_id(tok)
            for idx, off_sec in enumerate(final_offsets, start=1):
                shot_ts = target_ts + off_sec
                t = threading.Thread(
                    target=send_single_apply,
                    args=(
                        idx,
                        shot_ts,
                        target_ts,
                        calib["ntp_offset"],
                        tok,
                        dev_id,
                        results,
                        stop_evt,
                        append_sniper_log,
                    ),
                    daemon=True,
                )
                threads.append(t)
                t.start()

            for t in threads:
                t.join(timeout=20.0)

            with open(LOG_FILE, "a", encoding="utf-8") as lf:
                lf.write(f"--- Scheduled Window Results ({datetime.datetime.now().isoformat()}) ---\n")
                for _, line in results:
                    lf.write(line + "\n")
                lf.write("\n")

            approved = any(parse_apply_result(line) for _, line in results)
            if approved:
                append_sniper_log("\n[SUCCESS] ELIGIBILITY GRANTED (`apply_result: 1`)!")
                append_sniper_log(
                    "-> On your phone: Settings -> Developer Options -> Mi Unlock Status -> 'Add account and device'."
                )
            else:
                append_sniper_log("\n[*] Scheduled window complete. Re-checking account state (& verify 'Add account and device' on phone!)...")
                tag, msg, _ = query_account_state(tok)
                append_sniper_log(f"    [{tag}] {msg}")
                root.after(0, lambda: update_status_badge(tag, msg))

            def reset_btn():
                sniper_running["active"] = False
                btn_arm.configure(text="🚀 Schedule Request for 00:00:00 GMT+8", bg=ACCENT)

            root.after(0, reset_btn)

        threading.Thread(target=sniper_worker, daemon=True).start()

    def fire_test_now():
        tok = clean_token_string(token_var.get())
        if not tok:
            messagebox.showwarning("Token Required", "Please configure your token in Tab 1 first.")
            return
        save_token(tok)
        append_sniper_log("[*] Sending immediate single test request to /bbs/api/global/apply/bl-auth...")

        def worker():
            res = []
            evt = threading.Event()
            now_t = time.time() + calib["ntp_offset"]
            send_single_apply(
                1,
                now_t,
                now_t,
                calib["ntp_offset"],
                tok,
                generate_device_id(tok),
                res,
                evt,
                append_sniper_log,
            )
            tag, msg, _ = query_account_state(tok)
            root.after(0, lambda: update_status_badge(tag, msg))

        threading.Thread(target=worker, daemon=True).start()

    btn_arm = tk.Button(
        action_row,
        text="🚀 Schedule Request for 00:00:00 GMT+8",
        command=toggle_arm_sniper,
        bg=ACCENT,
        fg="#ffffff",
        relief="flat",
        font=("Segoe UI", 10, "bold"),
        padx=18,
        pady=7,
        cursor="hand2",
    )
    btn_arm.pack(side="left", padx=(0, 10))

    tk.Button(
        action_row,
        text="⚡ Fire Test Request Right Now",
        command=fire_test_now,
        bg="#334155",
        fg=FG_TEXT,
        relief="flat",
        font=("Segoe UI", 10, "bold"),
        padx=14,
        pady=7,
        cursor="hand2",
    ).pack(side="left")

    # ------------------------------------------------------------------------
    # TAB 3: ADB / FASTBOOT & NATIVE BOOTLOADER UNLOCKER
    # ------------------------------------------------------------------------
    dev_container = tk.Frame(tab_device, bg=BG_DARK, padx=14, pady=8)
    dev_container.pack(fill="both", expand=True)

    # Prominent Notice Banner for USB Debugging & Fastboot Mode
    usb_notice = tk.Frame(dev_container, bg="#1e3a5f", padx=12, pady=8)
    usb_notice.pack(fill="x", pady=(0, 8))
    tk.Label(
        usb_notice,
        text=(
            "⚠️ REQUIRED ON PHONE:\n"
            "• For ADB commands: Enable Developer Options -> 'USB Debugging' + 'OEM Unlocking' (and tap 'Allow' on phone).\n"
            "• For Fastboot / Native Unlocker: Put your phone into Fastboot Mode (Hold Volume Down + Power)."
        ),
        bg="#1e3a5f",
        fg="#e0f2fe",
        justify="left",
        anchor="w",
        wraplength=840,
        font=("Segoe UI", 9, "bold"),
    ).pack(fill="x", anchor="w")

    dev_btn_row1 = tk.Frame(dev_container, bg=BG_DARK)
    dev_btn_row1.pack(fill="x", pady=(0, 6))

    dev_btn_row2 = tk.Frame(dev_container, bg=BG_DARK)
    dev_btn_row2.pack(fill="x", pady=(0, 6))

    dev_btn_row3 = tk.Frame(dev_container, bg=BG_DARK)
    dev_btn_row3.pack(fill="x", pady=(0, 8))

    dev_output = tk.Text(
        dev_container,
        bg=BG_INPUT,
        fg="#e2e8f0",
        font=("Consolas", 10),
        relief="flat",
        padx=14,
        pady=12,
    )
    dev_output.pack(fill="both", expand=True)

    def write_dev_output(text: str):
        def _write():
            dev_output.delete("1.0", "end")
            dev_output.insert("end", text + "\n")

        root.after(0, _write)

    def append_dev_output(line: str):
        def _app():
            dev_output.insert("end", line + "\n")
            dev_output.see("end")

        root.after(0, _app)

    def on_scan_device():
        write_dev_output("[*] Scanning USB buses using built-in ADB & Fastboot...")
        threading.Thread(
            target=lambda: write_dev_output(inspect_connected_device()),
            daemon=True,
        ).start()

    def on_adb_cmd(args: List[str], label: str):
        write_dev_output(f"[*] Running `{args[0]}` ({label})...")

        def worker():
            _, out = run_tool_cmd(args)
            write_dev_output(f"=== {label} ===\n{out or 'Command sent successfully.'}")

        threading.Thread(target=worker, daemon=True).start()

    def on_native_unlock():
        write_dev_output("")
        u = email_var.get().strip()
        p = pass_var.get()

        def ask_2fa_ts(prompt_msg: str) -> Optional[str]:
            evt = threading.Event()
            holder: Dict[str, Optional[str]] = {"code": None}

            def _ask():
                holder["code"] = simpledialog.askstring("Xiaomi 2FA Code", prompt_msg, parent=root)
                evt.set()

            root.after(0, _ask)
            evt.wait()
            return holder["code"]

        def confirm_unlock_ts(prompt_msg: str) -> bool:
            evt = threading.Event()
            holder = {"yes": False}

            def _ask():
                holder["yes"] = bool(
                    messagebox.askyesno("Confirm Bootloader Unlock (Wipes Data)", prompt_msg, parent=root)
                )
                evt.set()

            root.after(0, _ask)
            evt.wait()
            return holder["yes"]

        threading.Thread(
            target=lambda: run_native_bootloader_unlocker(
                u, p, append_dev_output, code_prompt_cb=ask_2fa_ts, confirm_unlock_cb=confirm_unlock_ts
            ),
            daemon=True,
        ).start()

    # Row 1: ADB & Fastboot Device / Mode Controls
    tk.Button(
        dev_btn_row1,
        text="🔍 Scan Phone (ADB & Fastboot)",
        command=on_scan_device,
        bg=ACCENT,
        fg="#ffffff",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=10,
        pady=5,
        cursor="hand2",
    ).pack(side="left", padx=(0, 6))

    tk.Button(
        dev_btn_row1,
        text="📲 Open Developer Options",
        command=lambda: on_adb_cmd(
            ["adb", "shell", "am", "start", "-a", "android.settings.APPLICATION_DEVELOPMENT_SETTINGS"],
            "Open Developer Options",
        ),
        bg="#334155",
        fg=FG_TEXT,
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=10,
        pady=5,
        cursor="hand2",
    ).pack(side="left", padx=(0, 6))

    tk.Button(
        dev_btn_row1,
        text="🔁 Reboot to Fastboot",
        command=lambda: on_adb_cmd(["adb", "reboot", "bootloader"], "Reboot to Fastboot Mode"),
        bg="#334155",
        fg=FG_TEXT,
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=10,
        pady=5,
        cursor="hand2",
    ).pack(side="left", padx=(0, 6))

    tk.Button(
        dev_btn_row1,
        text="🛠️ Reboot to Recovery",
        command=lambda: on_adb_cmd(["adb", "reboot", "recovery"], "Reboot to Recovery Mode"),
        bg="#334155",
        fg=FG_TEXT,
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=10,
        pady=5,
        cursor="hand2",
    ).pack(side="left", padx=(0, 6))

    tk.Button(
        dev_btn_row1,
        text="▶️ Fastboot Reboot System",
        command=lambda: on_adb_cmd(["fastboot", "reboot"], "Fastboot Reboot to System"),
        bg="#334155",
        fg=FG_TEXT,
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=10,
        pady=5,
        cursor="hand2",
    ).pack(side="left")

    # Row 2: Official Drivers & Official Xiaomi Mi Unlock Tool
    tk.Button(
        dev_btn_row2,
        text="📥 1-Click Install ADB & Fastboot Drivers",
        command=lambda: threading.Thread(
            target=lambda: write_dev_output(install_adb_fastboot_drivers(append_dev_output)), daemon=True
        ).start(),
        bg="#0891b2",
        fg="#ffffff",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=12,
        pady=5,
        cursor="hand2",
    ).pack(side="left", padx=(0, 6))

    tk.Button(
        dev_btn_row2,
        text="🩹 Fix Windows Fastboot USB / Ryzen Bug",
        command=lambda: threading.Thread(
            target=lambda: write_dev_output(apply_windows_fastboot_usb_fix()), daemon=True
        ).start(),
        bg="#334155",
        fg=FG_TEXT,
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=12,
        pady=5,
        cursor="hand2",
    ).pack(side="left", padx=(0, 6))

    tk.Button(
        dev_btn_row2,
        text="🔓 Open / Download Official Mi Unlock Tool",
        command=lambda: threading.Thread(
            target=lambda: launch_or_download_mi_unlock(append_dev_output), daemon=True
        ).start(),
        bg="#4f46e5",
        fg="#ffffff",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=12,
        pady=5,
        cursor="hand2",
    ).pack(side="left")

    # Row 3: Fastboot Info & Native Built-In Unlocker
    tk.Button(
        dev_btn_row3,
        text="🔑 Read Fastboot Unlock Token & ARB",
        command=lambda: threading.Thread(
            target=lambda: write_dev_output(inspect_fastboot_token_details()), daemon=True
        ).start(),
        bg="#0284c7",
        fg="#ffffff",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=12,
        pady=6,
        cursor="hand2",
    ).pack(side="left", padx=(0, 8))

    tk.Button(
        dev_btn_row3,
        text="⚡ Check Wait Timer / Unlock Bootloader Now (Native)",
        command=on_native_unlock,
        bg=SUCCESS,
        fg="#ffffff",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=14,
        pady=6,
        cursor="hand2",
    ).pack(side="left")

    # ------------------------------------------------------------------------
    # TAB 4: INTERACTIVE CMD / ADB / FASTBOOT CONSOLE
    # ------------------------------------------------------------------------
    cmd_container = tk.Frame(tab_console, bg=BG_DARK, padx=14, pady=10)
    cmd_container.pack(fill="both", expand=True)

    tk.Label(
        cmd_container,
        text=(
            "💻 Built-In Command Terminal — Run any `adb`, `fastboot`, or Windows command "
            "(Note: Enable 'USB Debugging' in Developer Options on your phone for `adb` commands!)."
        ),
        bg=BG_DARK,
        fg=ACCENT_BLUE,
        font=("Segoe UI", 9, "bold"),
    ).pack(anchor="w", pady=(0, 6))

    # Quick Command Chips
    chips_row = tk.Frame(cmd_container, bg=BG_DARK)
    chips_row.pack(fill="x", pady=(0, 8))
    tk.Label(chips_row, text="Quick Commands:", bg=BG_DARK, fg=FG_MUTED, font=("Segoe UI", 9)).pack(
        side="left", padx=(0, 6)
    )

    cmd_input_var = tk.StringVar()
    cmd_history: List[str] = []
    hist_idx = {"pos": 0}

    cmd_console_out = tk.Text(
        cmd_container,
        bg=BG_INPUT,
        fg="#a7f3d0",
        font=("Consolas", 10),
        relief="flat",
        padx=12,
        pady=10,
    )

    def append_console(text: str):
        def _do():
            cmd_console_out.insert("end", text + "\n")
            cmd_console_out.see("end")

        root.after(0, _do)

    def execute_custom_command(raw_cmd: Optional[str] = None):
        import shlex

        cmdline = (raw_cmd if raw_cmd is not None else cmd_input_var.get()).strip()
        if not cmdline:
            return
        if raw_cmd is not None:
            cmd_input_var.set(cmdline)
        if not cmd_history or cmd_history[-1] != cmdline:
            cmd_history.append(cmdline)
        hist_idx["pos"] = len(cmd_history)
        cmd_input_var.set("")

        append_console(f"\n> {cmdline}")

        def worker():
            parts = shlex.split(cmdline, posix=(sys.platform != "win32"))
            if parts and parts[0].lower() in ("adb", "fastboot", "adb.exe", "fastboot.exe"):
                tool = "adb" if "adb" in parts[0].lower() else "fastboot"
                parts[0] = tool
                _, out = run_tool_cmd(parts, timeout=20.0)
                append_console(out or "(Command completed with no output)")
            else:
                try:
                    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                    proc = subprocess.run(
                        cmdline,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=20.0,
                        encoding="utf-8",
                        errors="replace",
                        creationflags=creation_flags,
                    )
                    out = ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip()
                    append_console(out or "(Command completed with no output)")
                except Exception as e:
                    append_console(f"[Error] {e}")

        threading.Thread(target=worker, daemon=True).start()

    for preset in (
        "adb devices -l",
        "fastboot devices",
        "fastboot oem get_token",
        "fastboot getvar all",
        "adb reboot bootloader",
        "fastboot reboot",
    ):
        tk.Button(
            chips_row,
            text=preset,
            command=lambda c=preset: execute_custom_command(c),
            bg="#1e293b",
            fg=FG_TEXT,
            relief="flat",
            font=("Consolas", 8, "bold"),
            padx=8,
            pady=3,
            cursor="hand2",
        ).pack(side="left", padx=(0, 5))

    tk.Button(
        chips_row,
        text="🗑️ Clear",
        command=lambda: cmd_console_out.delete("1.0", "end"),
        bg="#334155",
        fg=FG_TEXT,
        relief="flat",
        font=("Segoe UI", 8, "bold"),
        padx=8,
        pady=3,
        cursor="hand2",
    ).pack(side="right")

    input_bar = tk.Frame(cmd_container, bg=BG_CARD, padx=10, pady=8)
    input_bar.pack(fill="x", pady=(0, 8))
    tk.Label(input_bar, text="PS / ADB >", bg=BG_CARD, fg=ACCENT, font=("Consolas", 10, "bold")).pack(
        side="left", padx=(0, 8)
    )
    cmd_entry = tk.Entry(
        input_bar,
        textvariable=cmd_input_var,
        bg=BG_INPUT,
        fg="#ffffff",
        insertbackground="#ffffff",
        relief="flat",
        font=("Consolas", 10),
    )
    cmd_entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))

    def on_hist_up( _event):
        if cmd_history and hist_idx["pos"] > 0:
            hist_idx["pos"] -= 1
            cmd_input_var.set(cmd_history[hist_idx["pos"]])
        return "break"

    def on_hist_down(_event):
        if cmd_history and hist_idx["pos"] < len(cmd_history) - 1:
            hist_idx["pos"] += 1
            cmd_input_var.set(cmd_history[hist_idx["pos"]])
        elif hist_idx["pos"] >= len(cmd_history) - 1:
            hist_idx["pos"] = len(cmd_history)
            cmd_input_var.set("")
        return "break"

    cmd_entry.bind("<Return>", lambda _e: execute_custom_command())
    cmd_entry.bind("<Up>", on_hist_up)
    cmd_entry.bind("<Down>", on_hist_down)

    tk.Button(
        input_bar,
        text="▶ Run Command",
        command=lambda: execute_custom_command(),
        bg=ACCENT,
        fg="#ffffff",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=14,
        pady=5,
        cursor="hand2",
    ).pack(side="left")

    cmd_console_out.pack(fill="both", expand=True)
    append_console(
        f"HyperOS Fastboot Toolkit Interactive Console (ADB & Fastboot Ready)\n"
        f"Type any `adb`, `fastboot`, or system command below and press Enter.\n"
        + "-" * 72
    )

    write_dev_output(
        "=== XIAOMI / POCO HYPEROS UNLOCK CHECKLIST ===\n"
        "1. Use Tab 1 & Tab 2 to authorize your Mi Account at 00:00:00 GMT+8.\n"
        "2. On your phone: Turn Wi-Fi OFF, turn Mobile Data ON.\n"
        "3. Go to Settings -> Additional Settings -> Developer Options -> Mi Unlock Status.\n"
        "4. Tap 'Add account and device' ONCE -> wait for 'Added successfully'.\n"
        "   (Do NOT tap it again or log out during the 72-hour waiting period!).\n"
        "5. After 72 hours, click 'Reboot Phone to Fastboot' above and run Mi Unlock."
    )

    # Live 200ms UI Clock Tick
    def tick_clocks():
        now_ntp = time.time() + calib["ntp_offset"]
        bj_now = datetime.datetime.fromtimestamp(now_ntp, tz=BEIJING_TZ)
        target_dt = get_next_midnight_beijing(now_ntp)
        rem = max(0.0, target_dt.timestamp() - now_ntp)
        hrs, r = divmod(int(rem), 3600)
        mins, secs = divmod(r, 60)
        ms = int((rem - int(rem)) * 10)
        countdown_var.set(f"{hrs:02d}:{mins:02d}:{secs:02d}.{ms}")
        beijing_clock_var.set(f"Beijing Time: {bj_now.strftime('%Y-%m-%d %H:%M:%S')} GMT+8")
        root.after(150, tick_clocks)

    # Bottom Footer Bar
    footer_bar = tk.Frame(root, bg=BG_CARD, padx=16, pady=5)
    footer_bar.pack(side="bottom", fill="x")
    tk.Label(
        footer_bar,
        text=f"Developer: {AUTHOR_NAME}   |   LinkedIn: {AUTHOR_LINKEDIN}   |   Email: {AUTHOR_EMAIL}",
        bg=BG_CARD,
        fg=FG_MUTED,
        font=("Segoe UI", 9),
    ).pack(side="left")

    # Initial startup checks
    calibrate_network(log_to_box=True)
    if token_var.get():
        on_verify_token()
    tick_clocks()
    root.mainloop()


# ============================================================================
# INTERACTIVE TERMINAL CLI ENGINE
# ============================================================================

def run_cli(auto_mode: bool = False) -> None:
    print("=" * 76)
    print(f"  {APP_NAME} v{APP_VERSION} — Xiaomi HyperOS Eligibility & Fastboot Utility")
    print(f"  Developer: {AUTHOR_NAME} | Email: {AUTHOR_EMAIL}")
    print("=" * 76)

    token = load_saved_token()
    if token and auto_mode:
        print(f"[*] Loaded saved token from {TOKEN_FILE} ({token[:10]}...{token[-6:]})")
    else:
        while True:
            print("\nSelect Authentication Method:")
            if token:
                print(f"  [1] Use saved token from {TOKEN_FILE} ({token[:10]}...{token[-6:]}) [Default]")
            print("  [2] Direct Xiaomi Login (Enter Email / Phone / Mi ID & Password)")
            print("  [3] Open Browser Login (c.mi.com/global) & Paste `new_bbs_serviceToken`")
            print("  [4] Paste `new_bbs_serviceToken` manually")
            print("  [5] ADB / Fastboot Phone Checker")
            default_opt = "1" if token else "2"
            ans = input(f"\nChoice [{default_opt}]: ").strip() or default_opt

            if ans == "1" and token:
                break
            elif ans == "2":
                user = input("  Xiaomi Email / Phone / Mi Account ID: ").strip()
                pwd = getpass.getpass("  Xiaomi Account Password (hidden): ")
                print("  [*] Authenticating with Xiaomi Passport (sid=18n_bbs_global)...")
                ok, res, verify_url = login_xiaomi_passport(
                    user,
                    pwd,
                    code_prompt_cb=lambda msg: input(f"\n  [2FA] {msg} "),
                )
                if ok:
                    token = res
                    print(f"  [+] Successfully extracted & saved token to {TOKEN_FILE}!")
                    break
                else:
                    print(f"  [!] {res}")
                    if verify_url:
                        print(f"  [*] Opening verification URL: {verify_url}")
                        webbrowser.open(verify_url)
            elif ans == "3":
                print("  [*] Opening https://c.mi.com/global in your default browser...")
                webbrowser.open("https://c.mi.com/global")
                print("  After logging in, press F12 -> Application -> Cookies -> https://c.mi.com")
                raw = input("  Paste `new_bbs_serviceToken` value here: ").strip()
                token = clean_token_string(raw)
                if token:
                    save_token(token)
                    break
            elif ans == "4":
                raw = input("  Paste `new_bbs_serviceToken` value here: ").strip()
                token = clean_token_string(raw)
                if token:
                    save_token(token)
                    break
            elif ans == "5":
                print("\n" + inspect_connected_device())

    tag, msg, _ = query_account_state(token)
    print("\n" + "=" * 68)
    print(f"  ACCOUNT STATUS: [{tag}]")
    print(f"  {msg}")
    print("=" * 68)

    if tag == "EXPIRED":
        sys.exit(1)

    print("\n[*] Syncing clock with atomic NTP servers...")
    ntp_offset, ntp_srv = get_ntp_offset()
    print(f"    NTP Server : {ntp_srv} ({ntp_offset:+.4f}s)")

    print("[*] Measuring network latency (RTT) to Xiaomi Singapore API...")
    rtt = measure_api_rtt(token)
    one_way = rtt / 2.0
    print(f"    Avg RTT    : {rtt*1000:.1f} ms (One-way: {one_way*1000:.1f} ms)")

    now_ntp = time.time() + ntp_offset
    target_bj_dt = get_next_midnight_beijing(now_ntp)
    target_ts = target_bj_dt.timestamp()
    local_target_dt = datetime.datetime.fromtimestamp(target_ts)

    print("\n" + "-" * 68)
    print(f"  Target Reset (Beijing) : {target_bj_dt.strftime('%Y-%m-%d %H:%M:%S.000')} GMT+8")
    print(f"  Target Reset (Local)   : {local_target_dt.strftime('%Y-%m-%d %H:%M:%S.000')} Local Time")
    print("-" * 68)

    if auto_mode:
        action = "1"
        strategy = "queue"
    else:
        print("\nChoose Action:")
        print("  [1] Wait & Run Scheduled NTP Window at 00:00:00 GMT+8 (Recommended)")
        print("  [2] Run Immediate Eligibility Request Check")
        print("  [3] Inspect Connected Phone (ADB / Fastboot)")
        action = input("\nSelect [1/2/3] (default 1): ").strip() or "1"
        strategy = "queue"

    if action == "3":
        print("\n" + inspect_connected_device())
        return
    if action == "2":
        print("\n[*] Sending single eligibility check request...")
        results = []
        stop_evt = threading.Event()
        now_t = time.time() + ntp_offset
        send_single_apply(1, now_t, now_t, ntp_offset, token, generate_device_id(token), results, stop_evt, print)
        return

    print("\n[*] Scheduled for 00:00:00.000 GMT+8 precision window!")
    print("    Keep this terminal open and prevent your PC from sleeping.\n")

    recalibrated = False
    while True:
        now_ntp = time.time() + ntp_offset
        remaining = target_ts - now_ntp
        if remaining <= 60.0 and not recalibrated:
            recalibrated = True
            new_off, srv = get_ntp_offset()
            if srv != "Local System Clock (NTP unreachable)":
                ntp_offset = new_off
            rtt = measure_api_rtt(token)
            one_way = rtt / 2.0
            print(f"\n[*] T-60s Recalibration: NTP={ntp_offset:+.4f}s ({srv}), RTT={rtt*1000:.1f}ms")

        if remaining <= 10.0:
            break

        bj_now = datetime.datetime.fromtimestamp(now_ntp, tz=BEIJING_TZ)
        hrs, rem = divmod(int(remaining), 3600)
        mins, secs = divmod(rem, 60)
        sys.stdout.write(
            f"\r  [Beijing Time: {bj_now.strftime('%H:%M:%S')}] Countdown to 00:00 GMT+8 Window: {hrs:02d}:{mins:02d}:{secs:02d} "
        )
        sys.stdout.flush()
        time.sleep(0.5)

    burst_offsets = compute_burst_offsets(strategy, one_way)
    print("\n\n[*] T-10s! Pre-warming 6 TCP_NODELAY TLS Keep-Alive connections...")
    results = []
    threads = []
    stop_event = threading.Event()
    dev_id = generate_device_id(token)
    for idx, off in enumerate(burst_offsets, start=1):
        shot_ts = target_ts + off
        t = threading.Thread(
            target=send_single_apply,
            args=(idx, shot_ts, target_ts, ntp_offset, token, dev_id, results, stop_event, print),
            daemon=True,
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=20.0)

    with open(LOG_FILE, "a", encoding="utf-8") as lf:
        lf.write(f"--- Scheduled Window Results ({datetime.datetime.now().isoformat()}) ---\n")
        for _, line in results:
            lf.write(line + "\n")
        lf.write("\n")

    print("\n[*] Re-checking account state...")
    tag, msg, _ = query_account_state(token)
    print(f"  [{tag}] {msg}")


def main():
    if "--cli" in sys.argv or "--auto" in sys.argv:
        run_cli(auto_mode=("--auto" in sys.argv))
    else:
        try:
            launch_gui()
        except Exception as e:
            print(f"[*] GUI unavailable ({e}), falling back to Terminal CLI mode...\n")
            run_cli(auto_mode=False)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Exited by user.")
