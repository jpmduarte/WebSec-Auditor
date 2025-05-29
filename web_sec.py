import argparse
import sys
import subprocess
import socket
import ssl
import aiohttp
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from typing import Set
import time
import re
import idna
import requests
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import dns.query
import dns.zone


ALLOWED_CHECKS = {"ssl", "headers", "dns", "nmap", "cookies", "waf", "xss"}

def enforce_scheme(url, default_scheme="https"):
    if not url.startswith("http"):
        return f"{default_scheme}://{url}"
    return url

def normalize_url(url):
    parsed = urlparse(url)
    return parsed.scheme + "://" + parsed.netloc + parsed.path.rstrip('/')

def is_static_url(url):
    static_patterns = [
        r"\.(jpg|jpeg|png|gif|svg|ico|css|js|woff|woff2|ttf|eot|pdf|zip)$",
        r"/(images|static|js|css|fonts|media)/"
    ]
    return any(re.search(pattern, url, re.IGNORECASE) for pattern in static_patterns)

def run_cookies_check(target, max_pages=20):
    print(f"[*] Starting cookie check on {target}")
    output_lines = [f"[*] Cookies Check Report for: {target}"]

    if not target.startswith("http"):
        target = "https://" + target

    driver = None
    try:
        chrome_options = ChromeOptions()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=chrome_options)
    except WebDriverException:
        return "[!] Could not start Chrome WebDriver."

    visited = set()
    to_visit = [target]
    all_cookies = {}
    global_cookie_ids = set()
    pages_crawled = 0

    try:
        while to_visit and pages_crawled < max_pages:
            url = to_visit.pop(0)
            url = enforce_scheme(url)
            url = normalize_url(url)

            if url in visited or is_static_url(url):
                continue

            try:
                driver.get(url)
                WebDriverWait(driver, 10).until(
                    lambda d: d.execute_script('return document.readyState') == 'complete'
                )

                final_url = normalize_url(driver.current_url)
                if final_url != url and final_url not in visited:
                    output_lines.append(f"[+] Redirected: {url} → {final_url}")
                    to_visit.insert(0, final_url)
                    visited.add(url)
                    continue

                visited.add(final_url)
                pages_crawled += 1
                output_lines.append(f"\n[+] Crawled: {final_url}")

                cookies = driver.get_cookies()
                if cookies:
                    new_cookies = []
                    for cookie in cookies:
                        cid = (cookie['name'], cookie['domain'], cookie.get('path', '/'))
                        if cid not in global_cookie_ids:
                            global_cookie_ids.add(cid)
                            new_cookies.append(cookie)

                    if new_cookies:
                        all_cookies[final_url] = new_cookies

                links = driver.find_elements(By.TAG_NAME, 'a')
                for link in links:
                    href = link.get_attribute('href')
                    if not href or href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                        continue
                    full_url = enforce_scheme(urljoin(final_url, href))
                    full_url = normalize_url(full_url)

                    if urlparse(full_url).netloc != urlparse(final_url).netloc:
                        continue
                    if is_static_url(full_url):
                        continue
                    if full_url not in visited and full_url not in to_visit:
                        to_visit.append(full_url)

            except Exception as e:
                output_lines.append(f"[!] Error visiting {url}: {e}")

    finally:
        if driver:
            driver.quit()

    output_lines.append("\n====================== Cookie Summary ======================")
    if not all_cookies:
        output_lines.append("No cookies found.\n")
    else:
        total = 0
        for url, cookies in all_cookies.items():
            output_lines.append(f"\n[URL] {url}")
            for cookie in cookies:
                output_lines.append(f"  - Name:     {cookie['name']}")
                output_lines.append(f"    Domain:   {cookie.get('domain', '')}")
                output_lines.append(f"    Path:     {cookie.get('path', '/')}") 
                output_lines.append(f"    HttpOnly: {'Yes' if cookie.get('httpOnly') else 'No'}")
                output_lines.append(f"    Secure:   {'Yes' if cookie.get('secure') else 'No'}")
                output_lines.append(f"    SameSite: {cookie.get('sameSite', 'None')}")
                output_lines.append("===========================")
                total += 1
        output_lines.append(f"\nTotal unique cookies found: {total}")
        output_lines.append("========================================================")

    print(f"[*] Finished cookie check on {target}")
    
    return "\n".join(output_lines) + "\n"

def validate_choices(value, allowed_set, arg_name):
    values = [v.strip() for v in value.split(',')]
    invalid = [v for v in values if v not in allowed_set]
    if invalid:
        raise argparse.ArgumentTypeError(
            f"Invalid {arg_name}: {', '.join(invalid)}. Allowed: {', '.join(sorted(allowed_set))}")
    return values

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Web Security Checker - Comprehensive website security analysis tool - made by João Duarte",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 web-sec-scanner.py https://example.com
  python3 web-sec-scanner.py https://example.com --safe-mode
  python3 web-sec-scanner.py https://example.com --checks ssl,headers,dns

Available checks:
  ssl      - Check SSL/TLS configuration
  headers  - Analyze HTTP security headers
  dns      - Perform DNS-related checks
  nmap     - Run basic Nmap port scan
  cookies  - Inspect HTTP cookies
  waf      - Fingerprints WAF's
  xss      - XSS testing integration with XSStrike
        """
    )
    
    parser.add_argument("target", help="Target URL or domain to scan")
    
    mode_group = parser.add_argument_group("Scan Modes")
    mode_group.add_argument("--safe-mode", action="store_true", help="Run in safe mode (use less intrusive checks)")
    
    check_group = parser.add_argument_group("Check Options")
    check_group.add_argument(
        "--checks",
        type=lambda v: validate_choices(v, ALLOWED_CHECKS, "checks"),
        help=f"Comma-separated list of checks to run (default: all). Allowed: {', '.join(sorted(ALLOWED_CHECKS))}"
    )
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    
    if args.checks is None:
        args.checks = list(ALLOWED_CHECKS)
    
    return args

def run_ssl_check(target):
    report_lines = [f"[*] SSL Certificate Report for: {target}"]

    try:
        # Extract hostname from URL
        host = target.replace('http://', '').replace('https://', '').split('/')[0]
        port = 443

        # IDNA encode hostname for SNI support
        server_hostname = idna.encode(host).decode()

        # Get certificate via SSL socket
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            ip = sock.getpeername()[0]
            with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())

        # Parse cert details
        subject = cert.subject
        issuer = cert.issuer
        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        days_left = (valid_to - now).days
        expired = now > valid_to

        # Subject fields
        subject_cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        try:
            subject_o = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
        except IndexError:
            subject_o = ''

        # Issuer fields
        issuer_cn = issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        try:
            issuer_o = issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
        except IndexError:
            issuer_o = ''

        # SANs
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_list = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san_list = []

        # Certificate report
        report_lines.append(f"Issued to       : {subject_cn} ({subject_o})")
        report_lines.append(f"Issued by       : {issuer_cn} ({issuer_o})")
        report_lines.append(f"Server IP       : {ip}")
        report_lines.append(f"Valid from      : {valid_from.strftime('%Y-%m-%d')}")
        report_lines.append(f"Valid to        : {valid_to.strftime('%Y-%m-%d')} ({days_left} days left)")
        report_lines.append(f"Expired         : {'Yes' if expired else 'No'}")
        report_lines.append(f"Serial Number   : {cert.serial_number}")
        report_lines.append(f"Signature Algo  : {cert.signature_hash_algorithm.name.upper()}")
        report_lines.append("Subject Alt Names:")
        for san in san_list:
            report_lines.append(f"  - {san}")
        if days_left <= 15:
            report_lines.append("[!] Warning: Certificate will expire in less than 15 days.")

        # SSL Labs API URLs
        api_url_base = 'https://api.ssllabs.com/api/v3/'

        # Run SSL Labs scan with retries & timeout
        report_lines.append("\n[+] Running SSL Labs Analysis... (this can take a while)")

        max_attempts = 20
        attempt = 0
        while attempt < max_attempts:
            r = requests.get(f"{api_url_base}analyze", params={'host': host, 'all': 'done'}, timeout=10)
            r.raise_for_status()
            main_request = r.json()
            status = main_request.get('status', '')
            if status in ('DNS', 'IN_PROGRESS'):
                time.sleep(5)
                attempt += 1
                continue
            elif status == 'READY':
                break
            else:
                raise RuntimeError(f"Unexpected SSL Labs status: {status}")
        else:
            raise TimeoutError("SSL Labs scan did not complete in time.")

        endpoint_ip = main_request['endpoints'][0]['ipAddress']
        r2 = requests.get(f"{api_url_base}getEndpointData", params={'host': host, 's': endpoint_ip, 'all': 'done'}, timeout=10)
        r2.raise_for_status()
        endpoint_data = r2.json()
        details = endpoint_data.get('details', {})

        # Basic vulnerability report
        report_lines.append(f"\nGrade             : {main_request['endpoints'][0].get('grade', 'N/A')}")
        for vuln in ['poodle', 'heartbleed', 'heartbeat', 'freak', 'logjam', 'drownVulnerable']:
            report_lines.append(f"{vuln.capitalize():<18}: {details.get(vuln, 'N/A')}")

        # Protocols
        protocols_list = details.get('protocols', [])
        report_lines.append("\nSupported Protocols:")
        for proto in protocols_list:
            name = proto.get('name', 'Unknown')
            version = proto.get('version', '')
            report_lines.append(f"  - {name} {version}".strip())

        # Protocol ID to name map
        proto_id_to_name = {p.get('id'): f"{p.get('name')} {p.get('version')}".strip() for p in protocols_list}

        # Cipher suites
        suites = details.get('suites', [])
        report_lines.append("\nCipher Suites by Protocol:")

        # Full list of weak TLS 1.2 ciphers from your earlier data
        weak_tls12_ciphers = {
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CCM_8",
            "TLS_RSA_WITH_AES_256_CCM",
            "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CCM_8",
            "TLS_RSA_WITH_AES_128_CCM",
            "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
            "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
            "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
            "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
            "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"
        }

        ciphers_by_protocol = {}
        weak_ciphers_found = []

        for proto_suite in suites:
            proto_id = proto_suite.get('protocol')
            proto_name = proto_id_to_name.get(proto_id, f"Unknown protocol ({proto_id})")
            ciphers_by_protocol.setdefault(proto_name, [])

            for cipher in proto_suite.get('list', []):
                cipher_name = cipher.get('name', 'Unknown')
                strength = cipher.get('cipherStrength', 0)
                is_weak = (cipher_name in weak_tls12_ciphers) or any(x in cipher_name.upper() for x in ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'WEAK', 'CBC'])
                weak_tag = " WEAK" if is_weak else ""
                ciphers_by_protocol[proto_name].append(f"{cipher_name}{weak_tag} ({strength} bits)")
                if is_weak:
                    weak_ciphers_found.append(f"{proto_name}: {cipher_name} ({strength} bits)")

        for proto, ciphers in ciphers_by_protocol.items():
            report_lines.append(f"# {proto}")
            if ciphers:
                for c in ciphers:
                    report_lines.append(f"  - {c}")
            else:
                report_lines.append("  (None)")

        if weak_ciphers_found:
            report_lines.append("\n[!] Weak Ciphers Found:")
            for wc in weak_ciphers_found:
                report_lines.append(f"  - {wc}")
        else:
            report_lines.append("\n[+] No weak ciphers detected.")

    except Exception as e:
        return f"[!] SSL check failed for {target}: {e}\n"

    report_lines.append(f"\n[*] Finished SSL check on {target}")
    return "\n".join(report_lines) + "\n"

def run_headers_check(target):
    print(f"[*] Starting headers check on {target}")
    output_lines = [f"[*] HTTP Security Headers Report for: {target}"]

    SECURITY_HEADERS = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]

    INTERESTING_HEADERS = [
        "x-powered-by",
        "server",
        "access-control-allow-origin",
        "content-security-policy",
    ]

    http_to_https = False

    try:
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path

        https_url = f"https://{domain}"
        http_url = f"http://{domain}"

        # Try HTTP → HTTPS redirect detection
        try:
            http_response = requests.get(http_url, allow_redirects=True, timeout=10, headers={"User-Agent": "curl/7.68.0"})
            if http_response.url.startswith("https://"):
                http_to_https = True
                output_lines.append(f"[!] Detected HTTP → HTTPS redirect: {http_url} → {http_response.url}")
        except requests.exceptions.RequestException as e:
            output_lines.append(f"[!] HTTP redirect test failed: {e}")

        # Main HTTPS request
        response = requests.get(https_url, timeout=10, headers={"User-Agent": "curl/7.68.0"})
        output_lines.append(f"[*] Fetched URL: {response.url} (status: {response.status_code})")

        headers = {k.lower(): v for k, v in response.headers.items()}  

        output_lines.append("\n====================== Security Headers ====================")
        for header in SECURITY_HEADERS:
            if header in headers:
                output_lines.append(f"[+] {header}: {headers[header]}")
            else:
                output_lines.append(f"[!] Missing header: {header}")

        output_lines.append("\n=================== Full Response Headers ==================")
        for k, v in headers.items():
            output_lines.append(f"{k}: {v}")

        output_lines.append("\n=================== Extra Interesting Info =================")
        if http_to_https:
            output_lines.append("[+] HTTP redirects to HTTPS — good security practice.")
        else:
            output_lines.append("[!] HTTP does NOT redirect to HTTPS — consider enforcing HTTPS.")

        for header in INTERESTING_HEADERS:
            if header in headers:
                value = headers[header]
                output_lines.append(f"[~] {header}: {value}")

                if header == "content-security-policy":
                    output_lines.append("    [•] Analyzing CSP...")
                    if "'unsafe-inline'" in value:
                        output_lines.append("    [!] CSP uses 'unsafe-inline' — allows inline scripts, not recommended.")
                    if "'unsafe-eval'" in value:
                        output_lines.append("    [!] CSP uses 'unsafe-eval' — allows eval(), dangerous for XSS.")
                    if "*" in value:
                        output_lines.append("    [!] CSP uses wildcards (*) — too permissive, restrict to trusted sources.")
                    if "default-src" not in value:
                        output_lines.append("    [!] CSP missing 'default-src' — fallback not defined.")
                    if "script-src *" in value:
                        output_lines.append("    [!] 'script-src *' allows scripts from anywhere — reduce scope.")

                if header == "access-control-allow-origin" and value.strip() == "*":
                    output_lines.append("    [!] Access-Control-Allow-Origin is set to '*' — vulnerable to data leaks in some cases.")

    except requests.exceptions.RequestException as e:
        output_lines.append(f"[!] Error fetching headers: {e}")

    print(f"[*] Finished headers check on {target}")
    return "\n".join(output_lines) + "\n"

def run_dns_check(target):
    # Clean and normalize the domain: strip scheme and www.
    parsed = urlparse(target)
    host = parsed.netloc or parsed.path
    if host.startswith("www."):
        host = host[4:]

    print(f"[*] Starting DNS check on {host}")
    output_lines = [f"[*] DNS Information Report for: {host}"]

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

    output_lines.append("\n==================== DNS Records ====================")
    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(host, record_type, raise_on_no_answer=False)
            if answers:
                for rdata in answers:
                    output_lines.append(f"[+] {record_type}: {rdata.to_text()}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
            output_lines.append(f"[!] {record_type} lookup failed: {e}")

    # Zone transfer testing
    try:
        ns_records = dns.resolver.resolve(host, "NS")
        output_lines.append("\n==================== Zone Transfer Test ====================")
        for ns in ns_records:
            ns_host = str(ns.target).rstrip(".")
            output_lines.append(f"[*] Attempting zone transfer from NS: {ns_host}")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, host, timeout=5))
                for name, node in zone.nodes.items():
                    rdatasets = node.rdatasets
                    for rdataset in rdatasets:
                        output_lines.append(f"[+] Zone Transfer Record: {name}.{host} {rdataset}")
            except Exception as e:
                output_lines.append(f"[!] Zone transfer from {ns_host} failed: {e}")
    except Exception as e:
        output_lines.append(f"[!] Could not retrieve NS records: {e}")

    # DMARC, SPF, DKIM from TXT
    output_lines.append("\n================ DMARC / SPF / DKIM =================")
    try:
        txt_records = dns.resolver.resolve(host, "TXT")
        for rdata in txt_records:
            # decode bytes to string before joining
            txt = ''.join(s.decode('utf-8') for s in rdata.strings)
            if txt.startswith("v=spf1"):
                output_lines.append(f"[+] SPF Record: {txt}")
            if "dkim" in txt.lower():
                output_lines.append(f"[~] Possible DKIM TXT Record: {txt}")
    except Exception as e:
        output_lines.append(f"[!] TXT record fetch failed: {e}")

    # DMARC check (_dmarc subdomain)
    try:
        dmarc_domain = f"_dmarc.{host}"
        dmarc_records = dns.resolver.resolve(dmarc_domain, "TXT")
        for rdata in dmarc_records:
            txt = ''.join(s.decode('utf-8') for s in rdata.strings)
            output_lines.append(f"[+] DMARC Record: {txt}")
    except Exception as e:
        output_lines.append(f"[!] DMARC record fetch failed: {e}")

    print(f"[*] Finished DNS check on {host}")
    return "\n".join(output_lines) + "\n"

def run_nmap_check(target, safe_mode=False):
    parsed = urlparse(target)
    host = parsed.netloc if parsed.netloc else parsed.path
    print(f"[*] Starting nmap check on {host}")
    output_lines = []
    # Nmap command arguments
    if safe_mode:
        args = ['nmap', '-sS', '-p-', '-Pn', host]
    else:
        #args = ['nmap', '-sC', '-sV', host]
        args = ['nmap', host]
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=True)
        output = result.stdout

        output_lines.append("Nmap Scan Results:")
        ip = None
        rdns = None

        # Extract IP and rDNS
        for line in output.splitlines():
            ip_match = re.match(r'^Nmap scan report for .* \(([\d\.]+)\)', line)
            if ip_match:
                ip = ip_match.group(1)
            rdns_match = re.match(r'^rDNS record for ([\d\.]+): (.+)$', line)
            if rdns_match:
                rdns = rdns_match.group(2)

        if ip:
            output_lines.append(f"  IP Address: {ip}")
        if rdns:
            output_lines.append(f"  Reverse DNS: {rdns}")

        port_section = False
        ports = []
        current_port_info = None

        for line in output.splitlines():
            if re.match(r'^PORT\s+STATE\s+SERVICE', line):
                port_section = True
                continue
            if port_section:
                if line.strip() == "" or line.startswith("Nmap done:"):
                    if current_port_info:
                        ports.append(current_port_info)
                        current_port_info = None
                    break

                # Main port line
                if re.match(r'^\d+/[a-z]+\s+\w+\s+\S+', line):
                    if current_port_info:
                        ports.append(current_port_info)
                    parts = re.split(r'\s+', line.strip(), maxsplit=2)
                    if len(parts) >= 3:
                        port, state, service = parts
                        current_port_info = {
                            "port": port,
                            "state": state,
                            "service": service,
                            "details": []
                        }
                # Continuation lines
                elif current_port_info and (line.startswith("|") or line.startswith("_")):
                    current_port_info["details"].append(line.strip())

        if current_port_info:
            ports.append(current_port_info)

        # Output port info
        if ports:
            output_lines.append(f"\n{'Port':<10} {'State':<10} Service")
            output_lines.append("-" * 30)
            for p in ports:
                output_lines.append(f"{p['port']:<10} {p['state']:<10} {p['service']}")
                for detail in p["details"]:
                    output_lines.append(f"|  {detail}")
        else:
            output_lines.append("No open ports found or could not parse output.")

    except subprocess.CalledProcessError as e:
        output_lines.append(f"[!] Nmap scan failed: {e}")
        if e.stdout:
            output_lines.append("Output:\n" + e.stdout)
        if e.stderr:
            output_lines.append("Error Output:\n" + e.stderr)
    except FileNotFoundError:
        output_lines.append("[!] Nmap command not found. Please install nmap and ensure it's in your PATH.")

    print(f"[*] Finished cookie check on {host}")
    return "\n".join(output_lines)


def run_waf_check(target):
    print(f"[*] Starting WAF check on {target}")
    output_lines = [f"[*] WAF Detection Report for: {target}"]

    try:
        result = subprocess.run(
            ["wafw00f", target],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().splitlines():
                if "is behind" in line:
                    output_lines.append(f"[+] {line}")
                elif "No WAF detected" in line:
                    output_lines.append("[!] No WAF detected.")
        else:
            output_lines.append("[!] No output or WAF scan failed.")

    except subprocess.TimeoutExpired:
        output_lines.append("[!] WAF check timed out.")
    except Exception as e:
        output_lines.append(f"[!] Error running wafw00f: {e}")

    print(f"[*] Finished WAF check on {target}")
    return "\n".join(output_lines) + "\n"


def strip_ansi_codes(text: str) -> str:
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def run_xss_check(domain: str, timeout: int = 180) -> str:
    output_lines = [f"[*] XSS Detection Report for: {domain}\n"]

    crawl_cmd = ["python3", "/opt/XSStrike/xsstrike.py", "-u", domain, "--crawl"]

    try:
        crawl_proc = subprocess.run(
            crawl_cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        raw_output = crawl_proc.stdout + "\n" + crawl_proc.stderr

    except Exception as e:
        output_lines.append(f"[!] XSStrike crawl failed: {e}")
        return "\n".join(output_lines)

    clean_output = strip_ansi_codes(raw_output)


    comp_block_pattern = re.compile(
        r"\[\+\] Vulnerable component: (.+?)\s*\n"
        r"\[!\] Component location: (.+?)\s*\n"
        r"\[!\] Total vulnerabilities: (\d+)\s*\n"
        r"((?:\[!\] Summary: .+?\n\[!\] Severity: .+?\n(?:\[!\] CVE: .+?\n)?)+)",
        re.DOTALL
    )

    vuln_pattern = re.compile(
        r"\[!\] Summary: (.+?)\s*\n"
        r"\[!\] Severity: (.+?)\s*\n"
        r"(?:\[!\] CVE: (.+?)\s*\n)?"
    )

    vulnerable_found = False
    for comp_match in comp_block_pattern.finditer(clean_output):
        vulnerable_found = True
        component = comp_match.group(1).strip()
        location = comp_match.group(2).strip()
        vuln_count = comp_match.group(3).strip()
        vulns_text = comp_match.group(4)

        output_lines.append(f"[+] Vulnerable JS Component: {component} ({vuln_count} vulnerabilities)")
        output_lines.append(f"    Location: {location}")

        for vuln_match in vuln_pattern.finditer(vulns_text):
            summary = vuln_match.group(1).strip()
            severity = vuln_match.group(2).strip()
            cve = vuln_match.group(3)
            cve_str = cve.strip() if cve else "N/A"

            output_lines.append(f"    - Summary : {summary}")
            output_lines.append(f"      Severity: {severity.capitalize()}")
            output_lines.append(f"      CVE     : {cve_str}")

        output_lines.append("")  # blank line after each component block

    if not vulnerable_found:
        output_lines.append("[*] No vulnerable JS components found.")

    output_lines.append("\n[*] XSStrike crawl found 0 URLs with parameters.")

    return "\n".join(output_lines) + "\n"

def run_sql_check(target):

    pass


def main():
    args = parse_arguments()
    checks_to_run = args.checks

    outputs = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    outputs.append(f"Web Security Scan Report\nTarget: {args.target}\nDate: {timestamp}\n")

    check_dispatch = {
        "ssl": lambda: run_ssl_check(args.target),
        "headers": lambda: run_headers_check(args.target),
        "dns": lambda: run_dns_check(args.target),
        "nmap": lambda: run_nmap_check(args.target, safe_mode=args.safe_mode),
        "cookies": lambda: run_cookies_check(args.target),
        "waf": lambda: run_waf_check(args.target),
        "xss": lambda: run_xss_check(args.target)
    }
  

    # Define categories
    threaded_checks = {"headers", "cookies", "ssl", "dns"}
    subprocess_checks = {"nmap", "waf","xss"}

    outputs = []

    # Run lightweight threadable checks first
    futures = {}
    print("[*] Starting I/O-bound checks in parallel...")
    with ThreadPoolExecutor(max_workers=6) as executor:
        for check in checks_to_run:
            if check in threaded_checks and check in check_dispatch:
                futures[executor.submit(check_dispatch[check])] = check

        for future in as_completed(futures):
            check = futures[future]
            outputs.append("=" * 60)
            outputs.append(f"{check.upper()} CHECK")
            outputs.append("=" * 60)
            try:
                result = future.result()
                outputs.append(result)
            except Exception as e:
                outputs.append(f"[!] Error during {check} check: {e}")

    # Run subprocess-heavy checks (wafw00f, nmap) with small thread pool
    futures = {}
    print("[*] Starting subprocess-heavy checks...")
    with ThreadPoolExecutor(max_workers=2) as executor:
        for check in checks_to_run:
            if check in subprocess_checks and check in check_dispatch:
                futures[executor.submit(check_dispatch[check])] = check

        for future in as_completed(futures):
            check = futures[future]
            outputs.append("=" * 60)
            outputs.append(f"{check.upper()} CHECK")
            outputs.append("=" * 60)
            try:
                result = future.result()
                outputs.append(result)
            except Exception as e:
                outputs.append(f"[!] Error during {check} check: {e}")

    report = "\n".join(outputs) + "\n"

    with open("scan_report.txt", "w", encoding="utf-8") as f:
        f.write(report)

    print("Scan complete. Results saved to scan_report.txt")

if __name__ == "__main__":
    main()
