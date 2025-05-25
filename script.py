#!/usr/bin/env python3
"""
router_wan_admin.py
-------------------

Automates a nuisance specific to the VSOL V2802RH for Hathway ISP:

• Logs in to the web UI
• Ensures the Status page still shows the connection that we want to delete
• Deletes the phantom WAN entry (same as running `delClick(<idx>)` in the
  router’s JavaScript console)

------------------------------------------------------------------------
USAGE

    python router_wan_admin.py \
        --url http://192.168.1.1 \
        --user admin \
        --password mySecret \
        --index 2

All flags are optional; see --help for details.

------------------------------------------------------------------------
"""

import argparse
import re
import sys
from typing import Tuple

import requests
import urllib3

# ───────────────────────────────────────────────────────────── constants ──

DEFAULTS = {
    "url": "http://192.168.1.1",
    "user": "admin",
    "password": "admin",
    "index": 2,  # WAN profile number to delete
}

# Mimic the router’s preferred browser string
UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0"
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ────────────────────────────────────────────────────── helper functions ──


def login(session: requests.Session, base_url: str, username: str, password: str) -> None:
    """POST /login.cgi and leave cookies in *session*."""
    resp = session.post(
        f"{base_url}/login.cgi",
        data={
            "username": username,
            "password": password,
            # value is ignored on login, any constant OK
            "submit.htm?login.htm": "0",
        },
        timeout=10,
        verify=False,
        headers={
            "Referer": f"{base_url}/login.htm",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    resp.raise_for_status()
    print("✓ Logged in")


def tr069_present(session: requests.Session, base_url: str) -> bool:
    """Return True if ‘TR069’ appears anywhere in /status.htm (case-insensitive)."""
    r = session.get(f"{base_url}/status.htm", timeout=10, verify=False)
    r.raise_for_status()
    found = bool(re.search(r"TR069", r.text, flags=re.I))
    print(f"{'✓' if found else '✗'} TR069 marker {'found' if found else 'NOT found'}")
    return found


def _extract_nonce(html: str) -> Tuple[str, str]:
    """
    Pull the hidden one-time field from wan.htm, e.g.
        <input type="hidden" name="submit.htm?wan.htm" value="2285932">
    Returns (field_name, field_value).
    """
    m = re.search(
        r'<input[^>]+name=["\'](?P<name>submit\.htm\?wan\.htm)["\'][^>]+'
        r'value=["\'](?P<val>[^"\']+)',
        html,
        flags=re.I,
    )
    if not m:
        raise RuntimeError("Unable to locate nonce in wan.htm – firmware changed?")
    return m.group("name"), m.group("val")


def delete_wan_entry(session: requests.Session, base_url: str, idx: int) -> None:
    """Emulate delClick(idx) to remove a WAN profile."""
    print("→ Fetching wan.htm …")
    page = session.get(f"{base_url}/wan.htm", timeout=10, verify=False)
    page.raise_for_status()
    nonce_name, nonce_val = _extract_nonce(page.text)
    print(f"   Nonce {nonce_name}={nonce_val}")

    payload = {
        "action": 0,  # 0 = delete
        "idx": idx,
        "connid": "",
        nonce_name: nonce_val,
    }

    print(f"→ Deleting WAN entry idx={idx} …")
    resp = session.post(
        f"{base_url}/form2WanAdsl.cgi",
        data=payload,
        timeout=10,
        verify=False,
        headers={
            "Referer": f"{base_url}/wan.htm",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    resp.raise_for_status()
    print(f"✓ Entry {idx} removed – HTTP {resp.status_code}")


# ──────────────────────────────────────────────────────────── main flow ──


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Auto-delete Hathway’s phantom WAN profile on VSOL V2802RH"
    )
    parser.add_argument("--url", default=DEFAULTS["url"], help="Base URL of router")
    parser.add_argument("-u", "--user", default=DEFAULTS["user"], help="Username")
    parser.add_argument("-p", "--password", default=DEFAULTS["password"], help="Password")
    parser.add_argument(
        "-i",
        "--index",
        type=int,
        default=DEFAULTS["index"],
        help="WAN profile index to delete",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # One Session keeps cookies/headers
    sess = requests.Session()
    sess.headers.update(
        {
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8,"
                "application/signed-exchange;v=b3;q=0.7"
            ),
            "Accept-Language": "en-IN,en-US;q=0.9,en;q=0.8",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "DNT": "1",
            "Origin": args.url,
            "Pragma": "no-cache",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": UA,
        }
    )

    try:
        login(sess, args.url, args.user, args.password)

        if not tr069_present(sess, args.url):
            print("Status page does not contain 'TR069' – aborting")
            sys.exit(1)

        delete_wan_entry(sess, args.url, args.index)

    except (requests.RequestException, RuntimeError) as err:
        print(f"ERROR: {err}")
        sys.exit(2)


if __name__ == "__main__":
    main()