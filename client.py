"""
RCS Client — Slot-based mode.

Checks captcha locally (parallel), sends ALL captcha accounts to server's
persistent worker pool, polls results continuously. Workers grab accounts
one-by-one with zero idle time.
"""
import base64 as b64mod
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import sys
import time
from datetime import datetime

from colorama import init, Fore, Style
init()

try:
    from curl_cffi import requests as cffi_requests
    def _new_session():
        return cffi_requests.Session(impersonate="chrome")
except ImportError:
    import requests as _fallback_requests
    def _new_session():
        return _fallback_requests.Session()

# ── Config ──
if getattr(sys, 'frozen', False):
    _SCRIPT_DIR = os.path.dirname(sys.executable)
else:
    _SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_CONFIG_PATH = os.path.join(_SCRIPT_DIR, "config.json")
_ACCOUNTS_PATH = os.path.join(_SCRIPT_DIR, "accounts.txt")
_LOOP_DELAY = 60
_POLL_TIMEOUT = 600
_CHECK_THREADS = 20

# ── Colors ──
_RST = Style.RESET_ALL
_DIM = Style.DIM
_BLD = Style.BRIGHT
_GRN = Fore.LIGHTGREEN_EX
_RED = Fore.LIGHTRED_EX
_CYN = Fore.LIGHTCYAN_EX
_YLW = Fore.LIGHTYELLOW_EX
_GRY = Fore.LIGHTBLACK_EX


def _ts():
    return datetime.now().strftime("%H:%M:%S")


def _log(msg):
    print(f"  {_ts()}  {msg}")


def _load_config():
    if not os.path.isfile(_CONFIG_PATH):
        print(f"  {_RED}config.json not found{_RST}")
        sys.exit(1)
    with open(_CONFIG_PATH, "r") as f:
        return json.load(f)


def _load_accounts():
    if not os.path.isfile(_ACCOUNTS_PATH):
        return []
    with open(_ACCOUNTS_PATH, "r") as f:
        return [line.strip() for line in f if line.strip()]


def _sanitize(err):
    """Remove server details from error messages."""
    s = str(err)
    for block in ["127.0.0.1:8000", "127.0.0.1", "localhost:8000", "localhost",
                   "http://", "https://", "curl:", "Failed to connect",
                   "Connection refused", "trycloudflare.com"]:
        s = s.replace(block, "***")
    return s.strip()[:80]


def _extract_cookie(line):
    """Extract .ROBLOSECURITY cookie from account line. Handles: cookie, user:pass:cookie"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # user:pass:cookie format — extract cookie (last segment after :)
    if "_|WARNING:-" in line:
        # Find the actual cookie start
        idx = line.find("_|WARNING:-")
        return line[idx:]
    if len(line) > 50:
        return line
    return None


def _account_name(line):
    """Get display name from account line. Handles: cookie, user:pass:cookie"""
    line = line.strip()
    # user:pass:cookie — use username
    if "_|WARNING:-" not in line and ":" in line:
        return line.split(":")[0]
    # Cookie format: _|WARNING:-USERID-USERID-USERID|...
    if "_|WARNING:-" in line:
        idx = line.find("_|WARNING:-")
        uid_part = line[idx:].split("|")[0].replace("_|WARNING:-", "")
        segments = uid_part.split("-")
        if len(segments) >= 2:
            return segments[-1][:12]
        return uid_part[:12]
    return line[:12]


def _check_captcha(cookie, place_id):
    """Check if account has captcha by joining game."""
    s = _new_session()
    s.cookies.set(".ROBLOSECURITY", cookie, domain=".roblox.com")

    try:
        r = s.post("https://auth.roblox.com/v2/logout", timeout=10)
        csrf = r.headers.get("x-csrf-token", "")
        if not csrf:
            return False, {}
        s.headers["x-csrf-token"] = csrf

        r2 = s.post(
            "https://gamejoin.roblox.com/v1/join-game",
            json={"placeId": place_id, "isTeleport": False},
            timeout=10,
        )

        if r2.status_code == 403:
            ctype = r2.headers.get("rblx-challenge-type", "")
            raw_b64 = r2.headers.get("rblx-challenge-metadata", "")
            if "captcha" in ctype.lower() or raw_b64:
                return True, _extract_meta(r2.headers)

        if r2.status_code == 200:
            try:
                body = r2.json()
            except Exception:
                body = {}
            if body.get("status") == 2:
                return True, _extract_meta(r2.headers)

        return False, {}
    except Exception:
        pass
    return False, {}


def _get_csrf(session):
    """Get CSRF token."""
    try:
        r = session.post("https://auth.roblox.com/v2/login", timeout=5)
        return r.headers.get("x-csrf-token", "")
    except Exception:
        return ""


def _extract_meta(headers):
    raw = headers.get("rblx-challenge-metadata", "")
    if not raw:
        return {}
    try:
        raw_json = json.loads(b64mod.b64decode(raw))
    except Exception:
        raw_json = {}
    return {
        "challenge_type": headers.get("rblx-challenge-type", ""),
        "challenge_id": headers.get("rblx-challenge-id", ""),
        "raw_metadata_b64": raw,
        "unified_captcha_id": raw_json.get("unifiedCaptchaId", ""),
        "data_exchange_blob": raw_json.get("dataExchangeBlob", ""),
        "action_type": raw_json.get("actionType", "Generic"),
    }


# ── Server communication ──

def _submit_accounts(cfg, accounts):
    """Submit accounts to server's persistent pool. Returns (account_ids, id_to_cookie mapping)."""
    url = cfg["server_url"].rstrip("/") + "/api/submit"
    try:
        r = _new_session().post(url, json={"accounts": accounts},
                                headers={"X-API-Key": cfg["api_key"]}, timeout=15)
    except Exception as e:
        return None, None, _sanitize(e)

    if r.status_code == 429:
        return None, None, "rate limited - wait a few seconds"
    if r.status_code == 402:
        return None, None, "insufficient balance"
    if r.status_code == 401:
        return None, None, "invalid api key"
    if r.status_code == 503:
        return None, None, "service stopped"
    if r.status_code != 200:
        return None, None, f"error {r.status_code}"

    data = r.json()
    account_ids = data.get("account_ids", [])

    # Build mapping: account_id -> cookie display name
    id_to_name = {}
    for i, aid in enumerate(account_ids):
        if i < len(accounts):
            id_to_name[aid] = _account_name(accounts[i])
        else:
            id_to_name[aid] = aid[:12]

    return account_ids, id_to_name, None


def _poll_results(cfg, account_ids, session=None):
    """Poll results for specific account_ids."""
    url = cfg["server_url"].rstrip("/") + "/api/results"
    ids_str = ",".join(account_ids)
    s = session or _new_session()
    try:
        r = s.get(url, params={"ids": ids_str},
                  headers={"X-API-Key": cfg["api_key"]}, timeout=10)
        if r.status_code == 200:
            return r.json().get("results", {})
    except Exception:
        pass
    return {}


def _check_balance(cfg):
    try:
        r = _new_session().get(cfg["server_url"].rstrip("/") + "/balance",
                               headers={"X-API-Key": cfg["api_key"]}, timeout=10)
        if r.status_code == 200:
            return r.json().get("balance", 0)
    except Exception:
        pass
    return -1


def _check_server(cfg):
    """Quick check if server is reachable."""
    try:
        r = _new_session().get(cfg["server_url"].rstrip("/") + "/health", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def main():
    cfg = _load_config()
    place_id = cfg.get("place_id", 13379208636)

    print()
    print(f"  {_BLD}{_CYN}RCS Client{_RST}  {_GRY}slot-based mode{_RST}")
    print()

    # Check server
    if not _check_server(cfg):
        print(f"  {_RED}Server unreachable. Make sure server is running.{_RST}")
        print()
        time.sleep(5)
        return

    balance = _check_balance(cfg)
    if balance < 0:
        bal_str = "unreachable"
        bal_col = _RED
    else:
        bal_str = f"{balance} pts"
        bal_col = _GRN if balance > 10 else (_YLW if balance > 0 else _RED)
    print(f"  Balance:  {bal_col}{bal_str}{_RST}")
    print()

    round_num = 0
    while True:
        round_num += 1
        print(f"  {_BLD}{_CYN}Round {round_num}{_RST}  {_GRY}{_ts()}{_RST}")

        accounts = _load_accounts()
        if not accounts:
            _log(f"{_YLW}No accounts. Waiting {_LOOP_DELAY}s...{_RST}")
            time.sleep(_LOOP_DELAY)
            continue

        _log(f"{len(accounts)} accounts loaded")

        # Step 1: Check captcha locally
        _log(f"{_BLD}Checking accounts for captcha...{_RST}")
        captcha_accounts = []
        clean_count = 0
        error_count = 0

        def _check_one(acct):
            cookie = _extract_cookie(acct)
            if not cookie:
                return acct, False, "bad cookie"
            try:
                has_captcha, meta = _check_captcha(cookie, place_id)
                if has_captcha and meta.get("challenge_id"):
                    return acct, True, None
                return acct, False, None
            except Exception as e:
                return acct, False, str(e)

        with ThreadPoolExecutor(max_workers=_CHECK_THREADS) as pool:
            futures = {pool.submit(_check_one, acct): acct for acct in accounts}
            for future in as_completed(futures):
                acct, has_captcha, err = future.result()
                if err:
                    error_count += 1
                elif has_captcha:
                    captcha_accounts.append(acct)
                else:
                    clean_count += 1

        _log(f"{_GRN}{clean_count} clean{_RST}, {_YLW}{len(captcha_accounts)} captcha{_RST}, {_RED}{error_count} errors{_RST}")

        if not captcha_accounts:
            _log(f"{_YLW}No captcha accounts. Waiting {_LOOP_DELAY}s...{_RST}")
            print()
            time.sleep(_LOOP_DELAY)
            continue

        # Step 2: Submit captcha accounts to server pool
        _log(f"{_BLD}Submitting {len(captcha_accounts)} accounts to pool...{_RST}")
        account_ids, id_to_name, err = _submit_accounts(cfg, captcha_accounts)
        if err:
            _log(f"  {_RED}{err}{_RST}")
            print()
            time.sleep(_LOOP_DELAY)
            continue

        if not account_ids:
            _log(f"  {_RED}No accounts accepted by server{_RST}")
            print()
            time.sleep(_LOOP_DELAY)
            continue

        _log(f"  {_GRN}{len(account_ids)} accounts queued{_RST}")

        # Step 3: Poll results continuously
        pending = set(account_ids)
        total_solved = 0
        total_failed = 0
        total_clean = 0
        start_time = time.time()
        poll_session = _new_session()

        while pending:
            if time.time() - start_time > _POLL_TIMEOUT:
                _log(f"  {_RED}Poll timeout ({_POLL_TIMEOUT}s) - {len(pending)} accounts still pending{_RST}")
                break

            results = _poll_results(cfg, list(pending), session=poll_session)

            for aid in list(pending):
                r = results.get(aid, {})
                status = r.get("status", "queued")

                if status in ("solved", "failed", "clean"):
                    pending.discard(aid)
                    reason = r.get("reason", "")
                    name = id_to_name.get(aid, aid[:12])

                    if status == "solved":
                        total_solved += 1
                        print(f"    {_ts()}  {name}  {_GRN}solved{_RST}  {_GRY}{reason}{_RST}")
                    elif status == "failed":
                        total_failed += 1
                        print(f"    {_ts()}  {name}  {_RED}failed{_RST}  {_GRY}{reason[:60]}{_RST}")
                    elif status == "clean":
                        total_clean += 1
                        print(f"    {_ts()}  {name}  {_GRN}clean{_RST}  {_GRY}{reason}{_RST}")

            if pending:
                time.sleep(2)

        elapsed_total = time.time() - start_time
        print(f"  {_BLD}Done{_RST}: {_GRN}{total_solved} solved{_RST}, {_RED}{total_failed} failed{_RST}, {_GRN}{total_clean} clean{_RST}, {_GRY}{elapsed_total:.0f}s{_RST}")

        # Show updated balance
        balance = _check_balance(cfg)
        if balance >= 0:
            bal_col = _GRN if balance > 10 else (_YLW if balance > 0 else _RED)
            print(f"  Balance:  {bal_col}{balance} pts{_RST}")

        print(f"  {_GRY}Next round in {_LOOP_DELAY}s...{_RST}")
        print()
        time.sleep(_LOOP_DELAY)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {_GRY}Stopped.{_RST}")
