import websocket
import json
import os
import datetime
import time

# Pointing to the Go server running on the exact same Pi
CERTSTREAM_URL = "ws://127.0.0.1:8080/" 

CRYPTO_BASE = ['crypto', 'btc', 'eth', 'usdt', 'coin', 'bit', 'hash', 'token']
ACTION_BASE = ['invest', 'earn', 'profit', 'mine', 'mining', 'yield', 'roi', 'trade', 'double']
TRUST_BASE = ['legit', 'elite', 'global', 'capital', 'wealth', 'fund', 'prime', 'secure']
HIGH_RISK_TLDS = ['.top', '.vip', '.cc', '.ltd', '.pro', '.live']

cert_count = 0
seen_urls = set()

# TODO : make these sets
def is_highly_suspicious(domain):
    has_crypto = any(word in domain for word in CRYPTO_BASE)
    has_action = any(word in domain for word in ACTION_BASE)
    has_trust  = any(word in domain for word in TRUST_BASE)
    
    if (has_crypto and has_action) or (has_trust and has_action): return True
    if any(domain.endswith(tld) for tld in HIGH_RISK_TLDS) and (has_crypto or has_action or has_trust): return True
    return False

def on_message(ws, message):
    global cert_count
    try:
        data = json.loads(message)
        if data.get('message_type') != "certificate_update": return
            
        cert_count += 1
        if cert_count % 100 == 0: print(".", end="", flush=True)
            
        for domain in data['data']['leaf_cert']['all_domains']:
            clean_domain = domain.replace('*.', '').lower()
            
            if is_highly_suspicious(clean_domain):
                strict_url = f"https://{clean_domain}/"
                if strict_url in seen_urls: continue
                seen_urls.add(strict_url)
                
                today = datetime.datetime.now().strftime("%Y-%m-%d")
                daily_filename = f"/home/lild/scam_logs/targets_{today}.txt"
                
                print(f"\n[*] Target Locked: {strict_url} -> Saving to {daily_filename}")
                with open(daily_filename, "a") as file:
                    file.write(f"{strict_url}\n")
        time.sleep(0.001) # this helps with performance . feel free to delete if you are running on a nicer computer
    except Exception: pass

def on_error(ws, error): print(f"\n[-] ERROR: {error}")
def on_close(ws, close_status_code, close_msg): print("\n[-] Connection closed.")
def on_open(ws): print(f"\n[+] Connected directly to local Pi Firehose loopback!\n")

if __name__ == "__main__":
    print("[*] Starting Autonomous Pi Sniper...")
    ws = websocket.WebSocketApp(CERTSTREAM_URL, on_open=on_open, on_message=on_message, on_error=on_error, on_close=on_close)
    ws.run_forever()
