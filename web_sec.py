import argparse
import sys
import subprocess
import socket
import ssl
import json
import re
import idna
import requests
from datetime import datetime, timezone
from time import sleep
from urllib.request import urlopen
from urllib.parse import urljoin, urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import SSL

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from concurrent.futures import ThreadPoolExecutor, as_completed


ALLOWED_CHECKS = {"ssl", "headers", "dns", "nmap", "cookies"}

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
    print(f"[*] Starting SSL check on {target}")
    report_lines = [f"[*] SSL Certificate Report for: {target}"]

    try:
        # Clean input
        host = target.replace('http://', '').replace('https://', '').split('/')[0]
        port = 443

        # IDNA support
        server_hostname = idna.encode(host).decode()

        # Set up socket and SSL context
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            ip = sock.getpeername()[0]
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())

        # Certificate parsing
        subject = cert.subject
        issuer = cert.issuer
        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        days_left = (valid_to - now).days
        expired = now > valid_to

        # Subject and issuer details
        subject_cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        subject_o = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value \
            if cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME) else ''
        issuer_cn = issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        issuer_o = issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value \
            if issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME) else ''

        # SANs
        try:
            san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_list = san_extension.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san_list = []

        # Report certificate info
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

        # SSL Labs Analysis
        report_lines.append("\n[+] Running SSL Labs Analysis...")
        api_url = 'https://api.ssllabs.com/api/v3/'

        while True:
            main_request = json.loads(urlopen(f"{api_url}analyze?host={host}&all=done").read().decode())
            if main_request['status'] in ('DNS', 'IN_PROGRESS'):
                sleep(5)
                continue
            elif main_request['status'] == 'READY':
                break

        endpoint = main_request['endpoints'][0]['ipAddress']
        endpoint_data = json.loads(urlopen(f"{api_url}getEndpointData?host={host}&s={endpoint}&all=done").read().decode())
        details = endpoint_data['details']

        # Vulnerabilities
        report_lines.append(f"Grade             : {main_request['endpoints'][0].get('grade')}")
        report_lines.append(f"Poodle            : {details.get('poodle')}")
        report_lines.append(f"Heartbleed        : {details.get('heartbleed')}")
        report_lines.append(f"Heartbeat         : {details.get('heartbeat')}")
        report_lines.append(f"FREAK             : {details.get('freak')}")
        report_lines.append(f"LOGJAM            : {details.get('logjam')}")
        report_lines.append(f"DROWN             : {details.get('drownVulnerable')}")

        # Supported Protocols
        protocols = details.get('protocols', [])
        protocol_versions = { 'TLS 1.0': False, 'TLS 1.1': False, 'TLS 1.2': False, 'TLS 1.3': False }
        for proto in protocols:
            version = proto.get('version')
            key = f"TLS {version}"
            if key in protocol_versions:
                protocol_versions[key] = True

        report_lines.append("\nSupported Protocols:")
        for proto, enabled in protocol_versions.items():
            status = "Enabled" if enabled else "Disabled"
            report_lines.append(f"  - {proto}: {status}")

        # Cipher Suites grouped by protocol version
        cipher_suites = details.get('suites', {}).get('list', [])

        # Group ciphers by protocol version for output
        ciphers_by_protocol = {
            'TLS 1.3': [],
            'TLS 1.2': [],
            'TLS 1.1': [],
            'TLS 1.0': [],
        }

        # List of weak cipher indicators (can expand as needed)
        weak_indicators = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'WEAK', 'CBC']

        def is_weak_cipher(name):
            # Mark as weak if any weak indicator found in cipher name (case insensitive)
            return any(ind in name.upper() for ind in weak_indicators)

        for cipher in cipher_suites:
            name = cipher.get('name', '')
            protocol = cipher.get('protocol', '')
            strength = cipher.get('cipherStrength', 0)
            weak = is_weak_cipher(name)
            weak_tag = " WEAK" if weak else ""
            line = f"{name}{weak_tag} ({strength} bits)"
            if protocol in ciphers_by_protocol:
                ciphers_by_protocol[protocol].append(line)
            else:
                # If unknown protocol, put in TLS 1.2 by default
                ciphers_by_protocol['TLS 1.2'].append(line)

        report_lines.append("\nCipher Suites")
        for proto in ['TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0']:
            ciphers = ciphers_by_protocol.get(proto, [])
            if ciphers:
                report_lines.append(f"# {proto} (server-preferred order)")
                for cipher in ciphers:
                    report_lines.append(f"  {cipher}")

    except Exception as e:
        return f"[!] SSL check failed for {target}: {e}\n"

    report_lines.append(f"\n[*] Finished SSL check on {target}")
    return "\n".join(report_lines) + "\n"


def run_ssl_check(target):
    print(f"[*] Starting SSL check on {target}")
    report_lines = [f"[*] SSL Certificate Report for: {target}"]

    try:
        host = target.replace('http://', '').replace('https://', '').split('/')[0]
        port = 443

        server_hostname = idna.encode(host).decode()

        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            ip = sock.getpeername()[0]
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())

        subject = cert.subject
        issuer = cert.issuer
        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        days_left = (valid_to - now).days
        expired = now > valid_to

        subject_cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        subject_o = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value \
            if cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME) else ''
        issuer_cn = issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        issuer_o = issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value \
            if issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME) else ''

        try:
            san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_list = san_extension.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san_list = []

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

        report_lines.append("\n[+] Running SSL Labs Analysis...")
        api_url = 'https://api.ssllabs.com/api/v3/'

        while True:
            main_request = json.loads(urlopen(f"{api_url}analyze?host={host}&all=done").read().decode())
            status = main_request['status']
            if status in ('DNS', 'IN_PROGRESS'):
                sleep(5)
                continue
            elif status == 'READY':
                break
            else:
                raise Exception(f"Unexpected SSL Labs status: {status}")

        endpoint = main_request['endpoints'][0]['ipAddress']
        endpoint_data = json.loads(urlopen(f"{api_url}getEndpointData?host={host}&s={endpoint}&all=done").read().decode())
        details = endpoint_data['details']

        report_lines.append(f"Grade             : {main_request['endpoints'][0].get('grade')}")
        report_lines.append(f"Poodle            : {details.get('poodle')}")
        report_lines.append(f"Heartbleed        : {details.get('heartbleed')}")
        report_lines.append(f"Heartbeat         : {details.get('heartbeat')}")
        report_lines.append(f"FREAK             : {details.get('freak')}")
        report_lines.append(f"LOGJAM            : {details.get('logjam')}")
        report_lines.append(f"DROWN             : {details.get('drownVulnerable')}")

        protocols_list = details.get('protocols', [])
        protocol_supported = {'TLS 1.0': False, 'TLS 1.1': False, 'TLS 1.2': False, 'TLS 1.3': False}
        for p in protocols_list:
            name = p.get('name', '').upper()
            if 'TLS 1.0' in name:
                protocol_supported['TLS 1.0'] = True
            elif 'TLS 1.1' in name:
                protocol_supported['TLS 1.1'] = True
            elif 'TLS 1.2' in name:
                protocol_supported['TLS 1.2'] = True
            elif 'TLS 1.3' in name:
                protocol_supported['TLS 1.3'] = True

        report_lines.append("\nSupported Protocols:")
        for proto, supported in protocol_supported.items():
            report_lines.append(f"  - {proto}: {'Enabled' if supported else 'Disabled'}")

        cipher_suites = details.get('suites', [])

        ciphers_by_protocol = {
            'TLS 1.3': [],
            'TLS 1.2': [],
            'TLS 1.1': [],
            'TLS 1.0': [],
        }

        weak_indicators = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'WEAK', 'CBC']

        def is_weak_cipher(name):
            return any(ind in name.upper() for ind in weak_indicators)

        for cipher in cipher_suites:
            name = cipher.get('name', '')
            protocol = cipher.get('protocol', '')
            strength = cipher.get('cipherStrength', 0)
            weak = is_weak_cipher(name)
            weak_tag = " WEAK" if weak else ""
            line = f"{name}{weak_tag} ({strength} bits)"
            if protocol in ciphers_by_protocol:
                ciphers_by_protocol[protocol].append(line)
            else:
                ciphers_by_protocol['TLS 1.2'].append(line)

        report_lines.append("\nCipher Suites:")
        for proto in ['TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0']:
            report_lines.append(f"# {proto} (server preference order)")
            if ciphers_by_protocol[proto]:
                for c in ciphers_by_protocol[proto]:
                    report_lines.append(f"  {c}")
            else:
                report_lines.append("  (None)")

        weak_ciphers = []
        for proto, ciphers in ciphers_by_protocol.items():
            for cipher_str in ciphers:
                if "WEAK" in cipher_str:
                    weak_ciphers.append(f"{proto}: {cipher_str}")

        if weak_ciphers:
            report_lines.append("\nWeak Ciphers:")
            for w in weak_ciphers:
                report_lines.append(f"  - {w}")
        else:
            report_lines.append("\nWeak Ciphers: None found")

    except Exception as e:
        return f"[!] SSL check failed for {target}: {e}\n"

    report_lines.append(f"\n[*] Finished SSL check on {target}")
    return "\n".join(report_lines) + "\n"


def run_dns_check(target):
    print(f"[*] Running DNS check on {target}")

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
        args = ['nmap',host]
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
    }

    threaded_checks = {"headers", "nmap", "cookies"}
    futures = {}

    with ThreadPoolExecutor(max_workers=3) as executor:
        for check in checks_to_run:
            if check in threaded_checks:
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

    # Run non-threaded checks serially
    for check in checks_to_run:
        if check not in threaded_checks and check in check_dispatch:
            outputs.append("=" * 60)
            outputs.append(f"{check.upper()} CHECK")
            outputs.append("=" * 60)
            result = check_dispatch[check]()
            outputs.append(result)

    report = "\n".join(outputs) + "\n"

    with open("scan_report.txt", "w", encoding="utf-8") as f:
        f.write(report)

    print("Scan complete. Results saved to scan_report.txt")


if __name__ == "__main__":
    main()
