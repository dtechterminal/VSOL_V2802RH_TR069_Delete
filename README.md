# router_wan_admin

> **Target hardware:** **VSOL V2802RH** (Broadcom/TrendChip firmware)  
> **Target ISP quirk:** Hathway India – spawns a hidden WAN profile even when CWMP / TR-069 is disabled.

This tiny Python CLI script automates the tedious “delete the ghost WAN
connection” routine:

1. **Logs in** to the router’s web UI.  
2. **Verifies** the *Status* page still contains the string **`TR069`**  
   (fails fast if it doesn’t – handy sanity check).  
3. **Deletes** the phantom WAN entry by POST-ing the same form the firmware’s
   JavaScript calls with `delClick(<idx>)`.  
4. **Done** – no more opening DevTools after every reboot or link flap.

Everything is **pure std-lib + `requests` + `urllib3`** (no BeautifulSoup).

---

## ⚠️ One-time router preparation

The V2802RH shows a numeric CAPTCHA on its login page.  
To let the script log in non-interactively you **must disable that CAPTCHA**:

1. **Telnet or serial** into the router’s shell.  
2. Run:

   ```shell
   flash set VALIDATE_CODE_SWITCH 0
3.	Reboot the router once. The login screen will now skip the CAPTCHA.

Do this exactly once; afterwards the script can authenticate normally.

⸻

## Why this exists

On a VSOL V2802RH being used with Hathway, plugging the fibre back in causes
the firmware to create an extra WAN interface that:

	•	Isn’t listed on the WAN-edit page.
	•	Does appear on Status as soon as CWMP / TR-069 wakes up again.
	•	Breaks normal connectivity unless you manually delete it with delClick(2);.

router_wan_admin.py automates that exact cleanup.

⸻

## Requirements

Dependency	Version	Install with
    
    Python	≥ 3.8	—
    requests	latest	pip install requests
    urllib3	latest	installed together with requests

The script uses verify=False, mirroring curl --insecure.
If your router presents a real TLS cert, remove that option.

⸻

## Installation

    git clone https://github.com/dtechterminal/VSOL_V2802RH_TR069_Delete.git
    cd VSOL_V2802RH_TR069_Delete
    python3 -m venv venv && source venv/bin/activate
    pip install requests    # urllib3 comes along


⸻

## Quick start

python router_wan_admin.py \
  --url      http://192.168.1.1 \
  --user     admin \
  --password mySecret \
  --index    2

Typical output:

    ✓ Logged in
    ✓ TR069 marker found
    → Fetching wan.htm …
    Nonce submit.htm?wan.htm=2285932
    → Deleting WAN entry idx=2 …
    ✓ Entry 2 removed – HTTP 200


⸻

## Updating router details

Default values live in DEFAULTS inside the script:

        DEFAULTS = {
            "url": "http://192.168.1.1",  # change to your router’s management IP
            "user": "admin",              # your login
            "password": "admin",          # your password
            "index": 2                    # WAN profile number to delete
        }

Either edit those or override them on the command-line, as shown above.
Unsure which index the ghost entry takes? Check Status first—the order
matches the JavaScript call.

Run python router_wan_admin.py --help for the full flag list.

⸻

How it works

        1.	POST /login.cgi – reproduces the original cURL; cookies stay in a
    requests.Session.
        2.	GET /status.htm – quick search for “TR069”; aborts if missing.
        3.	GET /wan.htm – scrapes the hidden nonce
    <input name="submit.htm?wan.htm" value="…"> with a regex.
        4.	POST /form2WanAdsl.cgi – sends
    action=0 & idx=<index> & connid= & <nonce field> – identical to
    delClick().

No external parsers, no brittle DOM walking.

⸻

Caveats & tips
	•	Firmware updates might rename the hidden field; tweak the regex in
_extract_nonce() if needed.
	•	TLS verification is disabled; run only on trusted local networks.
	•	Comment out the TR-069 check if you don’t care about that guard.# VSOL_V2802RH_TR069_Delete
# VSOL_V2802RH_TR069_Delete
