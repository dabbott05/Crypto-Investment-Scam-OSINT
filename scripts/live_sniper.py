import os
import sys
import websocket
import json
import datetime
import time
import re
import tldextract
from pathlib import Path
from zoneinfo import ZoneInfo

LOG_DIR = Path.home() / "scam_logs"
LOG_DIR.mkdir(exist_ok=True)

# pointing at the server running certstream firehose
CERTSTREAM_URL = "ws://127.0.0.1:8080/"


# regex alternation is faster than a Python for-loop over keywords
# because the matching engine runs in C — \b ensures whole-word matches only
CRYPTO_REGEX = re.compile(
    r"\b(crypto|bitcoin|btc|eth|usdt|tether|mining|defi|staking|coin|wallet|token|hash|miner|mine|trc|trx|cash|secure|bit|top|stellar|ripple)\b"
)
ACTION_REGEX = re.compile(
    r"\b(invest|trade|trading|profit|earn|yield|stake|swap|exchange|capital|fund|fx|option|market|broker|asset|prime|apex|global|wealth|daily|roi)\b"
)
TRUST_REGEX = re.compile(
    r"\b(legit|secure|trust|official|verified|real|guarantee|guaranteed|instant)\b"
)

# tuples are better than lists and the .endswith() method accepts tuples
# TLDs only trigger when combined with at least one keyword match (see is_highly_suspicious)
HIGH_RISK_TLDS = (
    ".top",
    ".xyz",
    ".live",
    ".pro",
    ".site",
    ".ltd",
    ".trade",
    ".online",
    ".cc",
    ".cloud",
    ".io",
    ".ai",
    ".vip",
)

MEDIUM_RISK_TLDS = (
    ".icu",
    ".buzz",
    ".sbs",
    ".click",
    ".app",
    ".crypto",
)

cert_count = 0
seen_urls = {} # O(1) - no duplicates


# accepts the full domain and the suffix seperately
def is_highly_suspicious(search_target, domain_suffix):
    is_high_risk = domain_suffix in HIGH_RISK_TLDS
    is_medium_risk = domain_suffix in MEDIUM_RISK_TLDS
    
    has_crypto = bool(CRYPTO_REGEX.search(search_target))
    has_action = bool(ACTION_REGEX.search(search_target))

    if has_crypto and has_action:
        return True

    has_trust = bool(TRUST_REGEX.search(search_target))

    if has_trust and has_action:
        return True
    if is_high_risk and (has_crypto or has_action or has_trust):
        return True
    if is_medium_risk and (has_crypto and has_trust):
        return True

    return False


def on_message(ws, message):
    global cert_count
    try:
        data = json.loads(message)
        if data.get("message_type") != "certificate_update":
            return
        
        # prints a dot every 500 certs - helpful for debugging and gives a sense of scale
        cert_count += 1
        if cert_count % 500 == 0:
            print(".", end="", flush=True)

        for domain in data["data"]["leaf_cert"]["all_domains"]:
            clean_domain = domain.replace("*.", "").lower()

            extracted = tldextract.extract(clean_domain)
            
            if not extracted.suffix:
                continue
            
            domain_suffix = f".{extracted.suffix}"
            root_domain = f"{extracted.domain}{domain_suffix}"
            
            search_target = f"{extracted.subdomain}.{extracted.domain}" if extracted.subdomain else extracted.domain

            if is_highly_suspicious(search_target, domain_suffix):
                
                strict_url = f"https://{root_domain}/"

                if strict_url in seen_urls:
                    continue
                seen_urls[strict_url] = True
                
                if len(seen_urls) > 5000:
                    oldest_url = next(iter(seen_urls))
                    del seen_urls[oldest_url]

                today = datetime.datetime.now(tz=ZoneInfo("US/Central")).strftime("%Y-%m-%d")
                daily_filename = LOG_DIR / f"targets_{today}.txt"

                print(f"\n[*] Target Locked: {strict_url}")
                with open(daily_filename, "a") as file:
                    file.write(f"{strict_url}\n")

    except Exception as e:
        print(f"\n[-] Error processing message: {e}", flush=True)


def on_error(ws, error):
    print(f"\n[-] ERROR: {error}")


def on_close(ws, close_status_code, close_msg):
    print("\n[-] Connection closed.")


def on_open(ws):
    print("\n[+] Connected directly to local Pi Firehose loopback!\n")


if __name__ == "__main__":
    # load today's targets into seen_urls so restarts don't produce duplicates
    today = datetime.datetime.now(tz=ZoneInfo("US/Central")).strftime("%Y-%m-%d")
    daily_filename = LOG_DIR / f"targets_{today}.txt"
    if os.path.exists(daily_filename):
        with open(daily_filename, "r") as f:
            lines = f.read().splitlines()[-5000:]
            for url in lines:
                if url:
                    seen_urls[url] = True
        print(f"[*] Loaded {len(seen_urls)} existing targets for dedup.")

    print("[*] Starting Autonomous Pi Sniper ...")
    try:
        while True:
            ws = websocket.WebSocketApp(
                CERTSTREAM_URL,
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close,
            )
            ws.run_forever()
            print("\n[*] Reconnecting in 5 seconds...", flush=True)
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Exiting.")
        sys.exit(0)
