import os
import sys
import requests
import urllib3
import random
import socket
import re
import datetime
import threading
from zoneinfo import ZoneInfo
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# load .env
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# proxy :
# this is configured for an oxylab dedicated datacenter proxy - i have 5 ips with 1 port each
# but if you use a different proxy provider read proper configuration documentation or ask
# AI to configure your proxy settings for you - many providers have different formats for config
GATEWAY = os.getenv("OXY_GATEWAY", "ddc.oxylabs.io")
PROXY_USER = os.getenv("PROXY_USER")
PROXY_PASS = os.getenv("PROXY_PASS")
PORT_POOL = [os.getenv(f"OXY_PORT_{i}") for i in range(1, 6)]
PORT_POOL = [p for p in PORT_POOL if p]

if not all([PROXY_USER, PROXY_PASS]) or not PORT_POOL:
    print("[-] Bad credentials or ports in .env. Exiting.")
    sys.exit(1)

# logging
LOG_DIR = Path.home() / "scam_logs"
LOG_DIR.mkdir(exist_ok=True)

today = datetime.datetime.now(tz=ZoneInfo("US/Central")).strftime("%Y-%m-%d")

INPUT_FILE = LOG_DIR / f"targets_{today}.txt"
OUTPUT_FILE = LOG_DIR / f"confirmed_{today}.txt"

CRYPTO_REGEX = re.compile(r"\b(bitcoin|btc|ethereum|eth|usdt|tether|bnb|trx|tron|solana|litecoin|dogecoin|crypto|blockchain|mining|staking|defi|wallet|token|hash|miner)\b", re.IGNORECASE)
HYIP_REGEX = re.compile(r"\b(daily\s+roi|investment\s+plan|guaranteed\s+profit|passive\s+income|earn\s+daily|referral\s+bonus|minimum\s+deposit|instant\s+withdrawal|compound\s+interest|high\s+yield|roi\s+calculator|deposit\s+now|start\s+earning|join\s+now\s+and\s+earn|guaranteed\s+return|forex\s+trading|copy\s+trading|auto\s+trading)\b", re.IGNORECASE)
SCAM_STRUCTURE_REGEX = re.compile(r'(?:referral\s+bonus|affiliate\s+program|level\s+[1-5]\s+commission|binary\s+income|matching\s+bonus|mining\s+hashrate\s+packages|payout\s+history\s+table|recent\s+deposits\s+ticker)', re.IGNORECASE)
PLAN_TIER_REGEX = re.compile(r"\b(plan\s+[A-E]|plan\s+[1-5]|silver\s+plan|gold\s+plan|diamond\s+plan|vip\s+plan|investment\s+tier|premium\s+plan)\b", re.IGNORECASE)

seen_urls = set()
write_lock = threading.Lock()

if OUTPUT_FILE.exists():
    with open(OUTPUT_FILE, "r") as f:
        seen_urls.update(line.strip() for line in f if line.strip())

def normalize_url(target):
    base = target.split("//")[-1].rstrip("/") if "://" in target else target.rstrip("/")
    return f"https://{base}/"

def get_random_proxy():
    port = random.choice(PORT_POOL)
    proxy_url = f"http://{PROXY_USER}:{PROXY_PASS}@{GATEWAY}:{port}"
    return {"http": proxy_url, "https": proxy_url}

def check_html_and_save(target):
    strict_url = normalize_url(target)
    if strict_url in seen_urls: return

    # quick check to filter out domains that don't resolve before we waste time on HTTP requests
    domain = strict_url.split("//")[-1].rstrip("/")
    try:
        socket.gethostbyname(domain)
    except socket.gaierror: # domain doesn't resolve ? skip it !
        return

    try:
        proxies = get_random_proxy()
        response = requests.get(
            strict_url,
            proxies=proxies,
            timeout=(5, 10),
            verify=False,
            headers={"User-Agent": "Mozilla/5.0"},
            stream=True
        )
        
        # site has to be alive for us to pull the sites data
        if response.status_code == 200:
            html_body = ""
            
            # get only the first 75 kb of the HTML
            for chunk in response.iter_content(chunk_size=75000):
                if chunk:
                    html_body = chunk.decode("utf-8", errors="ignore").lower()
                    break
            
            response.close()
            
            crypto_hits = len(set(CRYPTO_REGEX.findall(html_body)))
            hyip_hits = len(set(HYIP_REGEX.findall(html_body)))
            struct_hits = len(set(SCAM_STRUCTURE_REGEX.findall(html_body)))
            plan_hits = len(set(PLAN_TIER_REGEX.findall(html_body)))
            
            title_match = re.search(r"<title[^>]*>(.*?)</title>", html_body[:2000], re.DOTALL)
            title = title_match.group(1).strip() if title_match else ""
            title_confirmed = bool(title and CRYPTO_REGEX.search(title) and HYIP_REGEX.search(title))

            # this is the logic behind "confirming" a scam website
            if (crypto_hits >= 3 and hyip_hits >= 1 and struct_hits >=1) or (crypto_hits >= 4 and struct_hits >= 1) or (plan_hits >= 2 and struct_hits >= 1 and crypto_hits >= 2) or (crypto_hits >= 3 and hyip_hits >=1 and plan_hits>= 1) or title_confirmed:
                
                # thread safety
                with write_lock:
                    with open(OUTPUT_FILE, "a") as f:
                        f.write(f"{strict_url}\n")
                    seen_urls.add(strict_url)
                
                print(f"[+] SCAM CONFIRMED: {strict_url} | crypto_hits={crypto_hits} | hyip_hits={hyip_hits} | struct_hits={struct_hits}")
    except:
        pass

if __name__ == "__main__":
    if not os.path.exists(INPUT_FILE):
        print(f"[-] Input file not found: {INPUT_FILE}. The sniper might not have caught anything today.")
        sys.exit(0)

    with open(INPUT_FILE, "r") as f:
        targets = [line.strip() for line in f if line.strip()]
    
    new_targets = [t for t in targets if normalize_url(t) not in seen_urls]
    print(f"[*] Starting scan: {len(new_targets)} targets using Port Rotation on {GATEWAY}...")

    with ThreadPoolExecutor(max_workers=9) as executor:
            futures = [executor.submit(check_html_and_save, t) for t in new_targets]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[!!!] Worker thread crashed: {e}", flush=True)
    print("\n[+] Scan Complete.")
    print("\n[+] Time Finished : " + datetime.datetime.now(tz=ZoneInfo("US/Central")).strftime("%Y-%m-%d %H:%M:%S"))
