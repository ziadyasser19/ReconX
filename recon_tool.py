#!/usr/bin/env python3
"""
AI-Automated Reconnaissance and Enumeration Tool
Author: Ziad Khafaga
Faculty of Computer Studies - Arab Open University Egypt
TM471: Final Year Project 
"""

import socket
import subprocess
import sys
import json
import re
import threading
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def install_and_import(package, import_name=None):
    import_name = import_name or package
    try:
        __import__(import_name)
    except ImportError:
        print(f"[*] Installing {package}...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", package,
             "--break-system-packages", "-q"],
            check=True, capture_output=True
        )

for pkg, imp in [("requests", "requests"), ("colorama", "colorama")]:
    install_and_import(pkg, imp)

import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()
from colorama import Fore, Style, init
init(autoreset=True)


# The BANNER  Ziaad kahafagaaa
def print_banner():
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║      ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗                    ║
║      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║                    ║
║      ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║                    ║
║      ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║                    ║
║      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║                    ║
║      ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝                    ║
║                                                                      ║
║        AI-Automated Reconnaissance & Enumeration Tool                ║
║                                                                      ║
║  {Fore.YELLOW}Author  : Ziad Khafaga{Fore.CYAN}                                               ║
║  {Fore.YELLOW}One command = 6 functions{Fore.CYAN}                                 ║
║                                                              ║
║                                                                      ║
║  {Fore.RED}[!] For authorized targets ONLY — Ethical use strictly required{Fore.CYAN}     ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)



def section(title):
    print(f"\n{Fore.CYAN}{'─'*60}")
    print(f"{Fore.CYAN}  {title}")
    print(f"{Fore.CYAN}{'─'*60}{Style.RESET_ALL}")

def ok(msg):   print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def info(msg): print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} {msg}")
def warn(msg): print(f"  {Fore.RED}[-]{Style.RESET_ALL} {msg}")

def resolve_target(target):
    target = target.strip().rstrip("/")
    target = re.sub(r"^https?://", "", target)
    try:
        ipaddress.ip_address(target)
        try:
            hostname = socket.gethostbyaddr(target)[0]
        except Exception:
            hostname = target
        return hostname, target
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(target)
        return target, ip
    except socket.gaierror as e:
        print(f"{Fore.RED}[!] Cannot resolve '{target}': {e}{Style.RESET_ALL}")
        sys.exit(1)

def get_base_url(domain):
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=6, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
            if r.status_code < 500:
                return f"{scheme}://{domain}"
        except Exception:
            pass
    return f"http://{domain}"


# 1Subdomain Enumeration
SUBDOMAINS = [
    "www","mail","ftp","remote","blog","webmail","server","ns1","ns2",
    "smtp","secure","vpn","m","shop","api","dev","stage","test",
    "portal","admin","cdn","assets","static","media","images","docs",
    "app","beta","mx","mx1","mx2","chat","help","support","status",
    "login","dashboard","cloud","backup","git","gitlab","jira","wiki",
    "jenkins","staging","uat","demo","internal","intranet","corp",
]

def subdomain_enum(domain, threads=30):
    section("SUBDOMAIN ENUMERATION")
    found = []
    lock  = threading.Lock()

    def check(sub):
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            with lock:
                ok(f"{host:<45}  ->  {ip}")
                found.append({"subdomain": host, "ip": ip})
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=threads) as ex:
        ex.map(check, SUBDOMAINS)

    if not found:
        info("No subdomains discovered.")
    return found


# 2Port Scanning
COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    993:"IMAPS", 995:"POP3S", 1433:"MSSQL", 3306:"MySQL", 3389:"RDP",
    5432:"PostgreSQL", 5900:"VNC", 6379:"Redis", 8080:"HTTP-Alt",
    8443:"HTTPS-Alt", 8888:"HTTP-Alt2", 27017:"MongoDB",
    11211:"Memcached", 2049:"NFS", 161:"SNMP", 389:"LDAP",
    636:"LDAPS", 1521:"Oracle", 5000:"Flask/Dev", 4443:"HTTPS-Alt2",
    9200:"Elasticsearch", 9300:"Elasticsearch-Cluster",
    5601:"Kibana", 2375:"Docker", 2376:"Docker-TLS",
}

def grab_banner(ip, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                return s.recv(1024).decode(errors="ignore").strip()[:120]
            except Exception:
                return ""
    except Exception:
        return ""

def port_scan(ip, timeout=1, threads=100):
    section(f"PORT SCAN -- {ip}")
    open_ports = []
    lock       = threading.Lock()

    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    service = COMMON_PORTS.get(port, "Unknown")
                    banner  = grab_banner(ip, port)
                    with lock:
                        msg = f"Port {port:<6} OPEN  [{service}]"
                        if banner:
                            msg += f"  -> {banner[:60]}"
                        ok(msg)
                        open_ports.append({"port": port, "service": service, "banner": banner})
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=threads) as ex:
        ex.map(check_port, list(COMMON_PORTS.keys()))

    open_ports.sort(key=lambda x: x["port"])
    if not open_ports:
        info("No common ports found open.")
    return open_ports


def detect_web_tech(domain):
    section("WEB TECHNOLOGY DETECTION")
    results = {"headers": {}, "technologies": [], "status": None, "url": ""}
    try:
        url = get_base_url(domain)
        r   = requests.get(url, timeout=8, allow_redirects=True,
                           headers={"User-Agent": "Mozilla/5.0"}, verify=False)
        results["status"] = r.status_code
        results["url"]    = r.url
        ok(f"URL: {r.url}  |  Status: {r.status_code}")

        for h in ["Server","X-Powered-By","X-Generator","CF-Ray","X-Varnish",
                  "X-Frame-Options","Strict-Transport-Security",
                  "Content-Security-Policy","X-Content-Type-Options","Via"]:
            val = r.headers.get(h)
            if val:
                ok(f"  Header -> {h}: {val[:100]}")
                results["headers"][h] = val

        body     = r.text[:10000]
        combined = (body + str(r.headers)).lower()
        fingerprints = {
            "WordPress" : ["wp-content","wp-includes"],
            "Joomla"    : ["joomla","com_content"],
            "Drupal"    : ["drupal"],
            "React"     : ["__react","reactdom"],
            "Vue.js"    : ["vue.js","__vue__"],
            "Angular"   : ["ng-version","angular.min.js"],
            "jQuery"    : ["jquery.min.js"],
            "Bootstrap" : ["bootstrap.min.css"],
            "Laravel"   : ["laravel","xsrf-token"],
            "Django"    : ["csrfmiddlewaretoken"],
            "ASP.NET"   : ["__viewstate","asp.net"],
            "PHP"       : [".php","x-powered-by: php"],
            "Nginx"     : ["nginx"],
            "Apache"    : ["apache"],
            "Cloudflare": ["cloudflare","cf-ray"],
            "Next.js"   : ["__next_data__","_next/static"],
            "Shopify"   : ["cdn.shopify.com"],
        }
        for tech, patterns in fingerprints.items():
            if any(p in combined for p in patterns):
                if tech not in results["technologies"]:
                    ok(f"  Tech    -> {tech}")
                    results["technologies"].append(tech)
    except Exception as e:
        warn(f"Web tech detection failed: {e}")
    return results



WAF_SIGNATURES = {
    "Cloudflare"          : ["cloudflare","cf-ray","__cfduid"],
    "AWS WAF"             : ["awswaf","x-amzn-requestid"],
    "Akamai"              : ["akamai","akamaighost","x-akamai-request-id"],
    "Sucuri"              : ["sucuri","x-sucuri-id","x-sucuri-cache"],
    "Imperva / Incapsula" : ["incapsula","visid_incap","incap_ses","x-iinfo"],
    "Barracuda"           : ["barra_counter_session","barracuda_"],
    "F5 BIG-IP ASM"       : ["x-wa-info","bigipserver","ts="],
    "ModSecurity"         : ["mod_security","modsecurity","owasp"],
    "Fortinet FortiWeb"   : ["fortiwafsid","cookiesession1"],
    "Wordfence"           : ["wordfence","wfvt_"],
    "Radware AppWall"     : ["x-sl-compstate","rdwr"],
    "Varnish Cache"       : ["x-varnish"],
}

WAF_PAYLOADS = [
    "/?q=<script>alert(1)</script>",
    "/?id=1' OR '1'='1",
    "/?file=../../../../etc/passwd",
    "/?cmd=;ls",
]

def detect_waf(domain):
    section("WAF DETECTION")
    base_url = get_base_url(domain)
    detected = []
    evidence = {}

   
    try:
        r = requests.get(base_url, timeout=8, verify=False,
                         headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        combined = (str(r.headers) + str(r.cookies) + r.text[:3000]).lower()
        for waf, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in combined:
                    if waf not in detected:
                        detected.append(waf)
                        evidence[waf] = f"passive header/cookie signature: '{sig}'"
                    break
    except Exception as e:
        warn(f"Passive WAF check failed: {e}")

    
    blocked_codes  = {403, 406, 429, 501, 503}
    blocked_count  = 0
    for payload in WAF_PAYLOADS:
        try:
            r = requests.get(base_url + payload, timeout=6, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=False)
            if r.status_code in blocked_codes:
                blocked_count += 1
                combined = (str(r.headers) + r.text[:2000]).lower()
                for waf, sigs in WAF_SIGNATURES.items():
                    for sig in sigs:
                        if sig.lower() in combined and waf not in detected:
                            detected.append(waf)
                            evidence[waf] = f"active block [HTTP {r.status_code}] + signature: '{sig}'"
                            break
        except Exception:
            pass

    # Results
    if detected:
        for waf in detected:
            ok(f"WAF Detected   -> {Fore.RED}{waf}{Style.RESET_ALL}  ({evidence.get(waf, '')})")
    elif blocked_count >= 2:
        generic = "Unknown WAF"
        detected.append(generic)
        ok(f"WAF Detected   -> {Fore.RED}{generic}{Style.RESET_ALL}  "
           f"({blocked_count}/{len(WAF_PAYLOADS)} attack payloads blocked — no vendor signature matched)")
    else:
        info("No WAF detected — target appears unprotected.")

    return {"detected": detected, "evidence": evidence, "blocked_payloads": blocked_count}



SENSITIVE_RE = re.compile(
    r"(admin|backup|config|database|db|secret|private|password|passwd|"
    r"\.env|\.git|\.htaccess|wp-admin|phpmyadmin|install|setup|"
    r"internal|intranet|staging|dev|test|api|v1|v2|token|key)",
    re.IGNORECASE
)

def _fetch_text(url, timeout=8):
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        if r.status_code == 200 and len(r.text) < 500_000:
            return r.text
    except Exception:
        pass
    return None

def parse_robots_and_sitemap(domain):
    section("ROBOTS.TXT & SITEMAP ANALYSIS")
    base_url = get_base_url(domain)
    result   = {
        "robots_paths"   : [],
        "sensitive_paths": [],
        "sitemap_urls"   : [],
        "sitemaps_found" : [],
    }

    # robots.txt module
    robots_text = _fetch_text(f"{base_url}/robots.txt")
    if robots_text:
        ok(f"robots.txt found at {base_url}/robots.txt")
        paths        = []
        sitemap_refs = []
        for line in robots_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":", 1)
            if len(parts) != 2:
                continue
            directive, value = parts[0].strip().lower(), parts[1].strip()
            if not value:
                continue
            if directive in ("disallow", "allow"):
                color = Fore.RED if directive == "disallow" else Fore.GREEN
                label = "DISALLOW" if directive == "disallow" else "ALLOW   "
                print(f"    {color}[{label}]{Style.RESET_ALL} {value}")
                paths.append({"directive": directive, "path": value})
                if SENSITIVE_RE.search(value):
                    result["sensitive_paths"].append(value)
            elif directive == "sitemap":
                sitemap_refs.append(value)

        result["robots_paths"]    = paths
        result["sitemaps_found"] += sitemap_refs

        if result["sensitive_paths"]:
            print(f"\n  {Fore.RED}[!] Sensitive paths disclosed in robots.txt:{Style.RESET_ALL}")
            for sp in result["sensitive_paths"]:
                warn(f"  -> {sp}")
    else:
        info("robots.txt not found.")

    #  Sitemap module
    sitemap_candidates = list(dict.fromkeys(
        result["sitemaps_found"] + [
            f"{base_url}/sitemap.xml",
            f"{base_url}/sitemap_index.xml",
            f"{base_url}/wp-sitemap.xml",
            f"{base_url}/sitemap1.xml",
        ]
    ))

    all_urls = []
    for sm_url in sitemap_candidates:
        sm_text = _fetch_text(sm_url)
        if not sm_text:
            continue
        ok(f"Sitemap found  -> {sm_url}")
       
        urls = re.findall(r"<loc>(.*?)</loc>", sm_text, re.IGNORECASE | re.DOTALL)
        urls = [u.strip() for u in urls]
        nested = re.findall(r"<sitemap>.*?<loc>(.*?)</loc>.*?</sitemap>",
                            sm_text, re.IGNORECASE | re.DOTALL)
        for nsm in nested[:5]:
            nsm_text = _fetch_text(nsm.strip())
            if nsm_text:
                extra = re.findall(r"<loc>(.*?)</loc>", nsm_text, re.IGNORECASE | re.DOTALL)
                urls += [u.strip() for u in extra]
        all_urls = list(dict.fromkeys(urls))
        break   

    result["sitemap_urls"] = all_urls

    if all_urls:
        ok(f"Total URLs in sitemap: {len(all_urls)}")
        sensitive_sm = [u for u in all_urls if SENSITIVE_RE.search(u)]
        if sensitive_sm:
            print(f"\n  {Fore.YELLOW}[!] Sensitive URLs found in sitemap:{Style.RESET_ALL}")
            for su in sensitive_sm[:15]:
                info(f"  -> {su}")
        else:
            for u in all_urls[:8]:
                info(f"  -> {u}")
            if len(all_urls) > 8:
                info(f"  ... and {len(all_urls) - 8} more URLs")
    else:
        info("No sitemap found.")

    return result


# 6 Directory BRute forcee
DIR_WORDLIST = [
    "admin","administrator","login","wp-admin","dashboard","api","api/v1","api/v2",
    "config","setup","install","backup","db","database","test","dev","stage",
    "upload","uploads","files","images","static","assets","media","docs","doc",
    ".git","phpinfo.php","robots.txt","sitemap.xml",".env","wp-config.php",
    "console","phpmyadmin","adminer","manager","panel","portal","user","users",
    "register","logout","wp-login.php","xmlrpc.php","readme.html","license.txt",
    "server-status","web.config","package.json","composer.json",
    ".htaccess",".htpasswd","crossdomain.xml","security.txt",
]

def dir_enum(domain, threads=25):
    section("DIRECTORY & FILE ENUMERATION")
    base_url = get_base_url(domain)
    found    = []
    lock     = threading.Lock()

    def check(path):
        url = f"{base_url}/{path.lstrip('/')}"
        try:
            r = requests.get(url, timeout=5, allow_redirects=False,
                             headers={"User-Agent": "Mozilla/5.0"}, verify=False)
            code = r.status_code
            if code in (200, 201, 301, 302, 403, 401):
                color = (Fore.GREEN if code == 200
                         else Fore.YELLOW if code in (301, 302)
                         else Fore.RED)
                size = len(r.content)
                with lock:
                    print(f"  {color}[{code}]{Style.RESET_ALL} {url:<62} [{size} B]")
                    found.append({"url": url, "status": code, "size": size})
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=threads) as ex:
        ex.map(check, DIR_WORDLIST)

    if not found:
        info("No interesting paths discovered.")
    return found


#  AI Analysis module
def ai_analysis(data: dict) -> str:
    section("AI ANALYSIS & PRIORITIZATION ENGINE")
    findings        = []
    recommendations = []
    risk_score      = 0

    open_ports   = data.get("ports", [])
    subdomains   = data.get("subdomains", [])
    technologies = data.get("web_tech", {}).get("technologies", [])
    headers      = data.get("web_tech", {}).get("headers", {})
    dirs         = data.get("directories", [])
    waf_data     = data.get("waf", {})
    robots_data  = data.get("robots_sitemap", {})


    critical_ports = {
        21:"FTP — clear-text credentials",
        23:"Telnet — clear-text protocol",
        3389:"RDP — brute-force / BlueKeep risk",
        445:"SMB — EternalBlue / ransomware vector",
        3306:"MySQL directly exposed to network",
        5432:"PostgreSQL directly exposed to network",
        27017:"MongoDB — likely unauthenticated",
        6379:"Redis — likely unauthenticated",
        11211:"Memcached — DDoS amplification risk",
        1433:"MSSQL directly exposed to network",
        5900:"VNC — brute-force risk",
        2375:"Docker daemon — unauthenticated API",
        9200:"Elasticsearch — unauthenticated data access",
        5601:"Kibana admin panel exposed",
    }
    for p in open_ports:
        port = p["port"]
        if port in critical_ports:
            findings.append(f"HIGH RISK: Port {port} open — {critical_ports[port]}")
            recommendations.append(f"Firewall port {port}; restrict to trusted IPs only.")
            risk_score += 20
        elif port in (80, 8080, 8888):
            findings.append(f"MEDIUM: Plain HTTP on port {port} — unencrypted traffic.")
            recommendations.append("Enforce HTTPS with a 301 redirect; disable plain HTTP.")
            risk_score += 5

    # WAF analysis
    if data.get("waf") is not None:
        if not waf_data.get("detected"):
            findings.append("HIGH RISK: No WAF detected — application has no perimeter protection layer.")
            recommendations.append("Deploy a WAF (Cloudflare, ModSecurity, AWS WAF) to filter malicious requests.")
            risk_score += 20
        else:
            wafs = ", ".join(waf_data["detected"])
            findings.append(f"INFO: WAF in place ({wafs}) — direct exploitation is harder but not impossible.")
            recommendations.append("Verify WAF rules cover OWASP Top 10; test periodically for bypass techniques.")

    # Robots.txt 
    for sp in robots_data.get("sensitive_paths", []):
        findings.append(f"MEDIUM: Sensitive path disclosed in robots.txt -> {sp}")
        risk_score += 10
    if robots_data.get("sensitive_paths"):
        recommendations.append("Remove sensitive paths from robots.txt — the file is publicly readable by anyone.")

    # Sensitive URLs in sitemap
    sensitive_sm = [u for u in robots_data.get("sitemap_urls", []) if SENSITIVE_RE.search(u)]
    if sensitive_sm:
        findings.append(f"MEDIUM: {len(sensitive_sm)} sensitive URL(s) indexed in sitemap (admin/internal paths).")
        recommendations.append("Audit sitemap.xml; exclude admin, staging, and internal endpoints.")
        risk_score += 8

    # Missing security headers
    missing_hdrs = [h for h in ["Strict-Transport-Security","X-Frame-Options",
                                  "Content-Security-Policy","X-Content-Type-Options"]
                    if h not in headers]
    if missing_hdrs:
        findings.append(f"MEDIUM: Missing security headers: {', '.join(missing_hdrs)}")
        recommendations.append("Add missing HTTP security headers in your web server or application config.")
        risk_score += 10

    # Technology-specific risks
    if "WordPress" in technologies:
        findings.append("MEDIUM: WordPress detected — check for outdated plugins, themes, and core.")
        recommendations.append("Run WPScan; keep WordPress core, plugins, and themes up to date.")
        risk_score += 10
    if "PHP" in technologies:
        findings.append("LOW: PHP exposed — ensure errors are suppressed and version is current.")
        recommendations.append("Set display_errors=Off; hide X-Powered-By; keep PHP patched.")
        risk_score += 5
    if "Django" in technologies:
        findings.append("LOW: Django detected — confirm DEBUG=False in production.")
        recommendations.append("Verify DEBUG=False; harden SECRET_KEY; review ALLOWED_HOSTS setting.")
        risk_score += 5

    # Sensitive directories
    sensitive_patterns = ["/admin","/wp-admin","/phpmyadmin","/.git","/.env",
                          "/wp-config","/adminer","/config","/backup",
                          "/setup","/install","/console","/manager"]
    for d in dirs:
        for sp in sensitive_patterns:
            if sp in d.get("url","").lower():
                code = d["status"]
                sev  = "HIGH RISK" if code == 200 else "MEDIUM"
                findings.append(f"{sev}: Sensitive path accessible -> {d['url']} [HTTP {code}]")
                recommendations.append(f"Block {d['url']} via firewall rule or server config.")
                risk_score += 25 if code == 200 else 10
                break

    
    if len(subdomains) > 5:
        findings.append(f"INFO: {len(subdomains)} subdomains discovered — large attack surface.")
        recommendations.append("Audit every exposed subdomain; apply consistent security posture.")
        risk_score += 5

    if not findings:
        findings = ["No critical issues identified from the scan data."]

    risk_level = ("CRITICAL" if risk_score >= 60 else
                  "HIGH"     if risk_score >= 35 else
                  "MEDIUM"   if risk_score >= 15 else "LOW")
    color_map  = {"CRITICAL": Fore.RED, "HIGH": Fore.RED,
                  "MEDIUM": Fore.YELLOW, "LOW": Fore.GREEN}
    rc = color_map.get(risk_level, Fore.WHITE)

    print(f"\n  {Fore.CYAN}-- Findings -----------------------------------------------{Style.RESET_ALL}")
    for i, f in enumerate(findings, 1):
        flag = Fore.RED if "HIGH" in f else Fore.YELLOW if "MEDIUM" in f else Fore.CYAN
        print(f"  {flag}[{i:02d}]{Style.RESET_ALL} {f}")

    print(f"\n  {Fore.CYAN}-- Recommendations ----------------------------------------{Style.RESET_ALL}")
    for i, r in enumerate(recommendations or ["No specific recommendations."], 1):
        print(f"  {Fore.GREEN}[{i:02d}]{Style.RESET_ALL} {r}")

    print(f"\n  {Fore.CYAN}-- Overall Risk Score -------------------------------------{Style.RESET_ALL}")
    bar_filled = min(risk_score, 100) // 5
    bar = f"{Fore.RED}{'|' * bar_filled}{Fore.WHITE}{'.' * (20 - bar_filled)}{Style.RESET_ALL}"
    print(f"  [{bar}]  {rc}{risk_level} ({risk_score}/100){Style.RESET_ALL}")

    return risk_level


# Report Genrator 
def generate_report(target, data, risk_level):
    section("REPORT GENERATION")
    ts          = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output_file = f"report_{target.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    report = {
        "tool"      : "AI-Automated Reconnaissance & Enumeration Tool",
        "target"    : target,
        "scan_time" : ts,
        "risk_level": risk_level,
        "summary"   : data,
    }
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2, default=str)
    ok(f"JSON report saved -> {output_file}")

    waf_names    = ", ".join(data.get("waf",{}).get("detected",[])) or "None detected"
    robots_count = len(data.get("robots_sitemap",{}).get("robots_paths",[]))
    sitemap_count= len(data.get("robots_sitemap",{}).get("sitemap_urls",[]))

    print(f"\n  {Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}SCAN SUMMARY -- {target}{Style.RESET_ALL}")
    print(f"  {'-'*60}")
    print(f"  Scan time          : {ts}")
    print(f"  Open ports         : {len(data.get('ports', []))}")
    print(f"  Subdomains found   : {len(data.get('subdomains', []))}")
    print(f"  Web technologies   : {', '.join(data.get('web_tech',{}).get('technologies',[]) or ['N/A'])}")
    print(f"  WAF                : {waf_names}")
    print(f"  Robots.txt paths   : {robots_count}")
    print(f"  Sitemap URLs       : {sitemap_count}")
    print(f"  Directories found  : {len(data.get('directories', []))}")
    print(f"  Risk level         : {risk_level}")
    print(f"  {Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

    return output_file


#  input Valdation 
def validate_input(target):
    target = target.strip()
    if not target:
        return False, "Empty target."
    target = re.sub(r"^https?://", "", target).rstrip("/")
    try:
        ipaddress.ip_address(target)
        return True, target
    except ValueError:
        pass
    domain_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if domain_re.match(target):
        return True, target
    return False, f"'{target}' is not a valid domain or IP address."


#   Menu 
def interactive_menu():
    print(f"\n{Fore.CYAN}+-- Scan Modules -----------------------------------------------+{Style.RESET_ALL}")
    print(f"{Fore.CYAN}|{Style.RESET_ALL}  [1] Full Scan   -- all modules                               {Fore.CYAN}|{Style.RESET_ALL}")
    print(f"{Fore.CYAN}|{Style.RESET_ALL}  [2] Quick Scan  -- ports + web tech + WAF                    {Fore.CYAN}|{Style.RESET_ALL}")
    print(f"{Fore.CYAN}|{Style.RESET_ALL}  [3] Recon Only  -- subdomains + robots/sitemap               {Fore.CYAN}|{Style.RESET_ALL}")
    print(f"{Fore.CYAN}|{Style.RESET_ALL}  [4] Web Audit   -- web tech + WAF + dirs + robots/sitemap    {Fore.CYAN}|{Style.RESET_ALL}")
    print(f"{Fore.CYAN}|{Style.RESET_ALL}  [5] Port Scan   -- port scan only                            {Fore.CYAN}|{Style.RESET_ALL}")
    print(f"{Fore.CYAN}|{Style.RESET_ALL}  [6] WAF Check   -- WAF detection only                        {Fore.CYAN}|{Style.RESET_ALL}")
    print(f"{Fore.CYAN}+---------------------------------------------------------------+{Style.RESET_ALL}")
    return input(f"\n{Fore.YELLOW}Select option [1-6]: {Style.RESET_ALL}").strip()


#The main function:
def main():
    import warnings
    warnings.filterwarnings("ignore")

    print_banner()

    while True:
        target = input(f"{Fore.YELLOW}Enter target (domain / IP): {Style.RESET_ALL}").strip()
        valid, result = validate_input(target)
        if valid:
            target = result
            break
        warn(result)

    hostname, ip = resolve_target(target)
    ok(f"Target resolved  ->  {hostname}  [{ip}]")
    print(f"  {Fore.CYAN}Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")

    mode = interactive_menu()

    data = {
        "target": target, "hostname": hostname, "ip": ip,
        "ports": [], "subdomains": [], "web_tech": {},
        "waf": {}, "robots_sitemap": {}, "directories": [],
    }

    if mode in ("1", ""):
        data["subdomains"]     = subdomain_enum(hostname)
        data["ports"]          = port_scan(ip)
        data["web_tech"]       = detect_web_tech(hostname)
        data["waf"]            = detect_waf(hostname)
        data["robots_sitemap"] = parse_robots_and_sitemap(hostname)
        data["directories"]    = dir_enum(hostname)

    elif mode == "2":
        data["ports"]    = port_scan(ip)
        data["web_tech"] = detect_web_tech(hostname)
        data["waf"]      = detect_waf(hostname)

    elif mode == "3":
        data["subdomains"]     = subdomain_enum(hostname)
        data["robots_sitemap"] = parse_robots_and_sitemap(hostname)

    elif mode == "4":
        data["web_tech"]       = detect_web_tech(hostname)
        data["waf"]            = detect_waf(hostname)
        data["robots_sitemap"] = parse_robots_and_sitemap(hostname)
        data["directories"]    = dir_enum(hostname)

    elif mode == "5":
        data["ports"] = port_scan(ip)

    elif mode == "6":
        data["waf"] = detect_waf(hostname)

    else:
        warn("Invalid option — running full scan.")
        data["subdomains"]     = subdomain_enum(hostname)
        data["ports"]          = port_scan(ip)
        data["web_tech"]       = detect_web_tech(hostname)
        data["waf"]            = detect_waf(hostname)
        data["robots_sitemap"] = parse_robots_and_sitemap(hostname)
        data["directories"]    = dir_enum(hostname)

    risk_level = ai_analysis(data)
    generate_report(target, data, risk_level)
    print(f"{Fore.CYAN}[v] Scan complete. Goodbye.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
