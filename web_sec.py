import argparse
import sys
import subprocess
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.common.exceptions import WebDriverException
from urllib.parse import urljoin, urlparse, urlunparse
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException
from colorama import Fore, init
import requests

ALLOWED_CHECKS = {"ssl", "headers", "dns", "nmap", "cookies"}
init(autoreset=True)


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

    output_lines.append("\n==================== Cookie Summary ====================")
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
    return "\n".join(output_lines)


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
    print(f"[*] Running SSL check on {target}")

def run_headers_check(target):
    print(f"[*] Running headers check on {target}")
    output_lines = [f"[*] HTTP Security Headers Report for: {target}"]

    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    http_to_https = False

    try:
        parsed = urlparse(target)
        scheme = parsed.scheme if parsed.scheme else "http"
        base_url = f"{scheme}://{parsed.netloc or parsed.path}"

        response = requests.get(base_url, allow_redirects=True, timeout=10)
        final_url = response.url

        if base_url.startswith("http://") and final_url.startswith("https://"):
            http_to_https = True
            output_lines.append(Fore.YELLOW + f"[!] Detected HTTP → HTTPS redirect: {base_url} → {final_url}")

        headers = response.headers

        output_lines.append("\n=== Security Headers ===")
        for header in SECURITY_HEADERS:
            if header in headers:
                output_lines.append(Fore.GREEN + f"[+] {header}: {headers[header]}")
            else:
                output_lines.append(Fore.RED + f"[!] Missing header: {header}")

        output_lines.append("\n=== Full Response Headers ===")
        for k, v in headers.items():
            output_lines.append(f"{k}: {v}")

        output_lines.append("\n===       EXTRA INFO      ===")
        if http_to_https:
            output_lines.append(Fore.GREEN + "[+] HTTP redirects to HTTPS — good security practice.")
        else:
            output_lines.append(Fore.RED + "[!] HTTP does NOT redirect to HTTPS — consider enforcing HTTPS.")

    except requests.exceptions.RequestException as e:
        output_lines.append(Fore.RED + f"[!] Error fetching headers: {e}")

    return "\n".join(output_lines)

def run_dns_check(target):
    print(f"[*] Running DNS check on {target}")


def run_nmap_check(target, safe_mode=False):
    parsed = urlparse(target)
    host = parsed.netloc if parsed.netloc else parsed.path
    output_lines = []

    print(f"[*] Running Nmap check on {host}")

    # Nmap command arguments
    if safe_mode:
        args = ['nmap', '-sS', '-p-', '-Pn', host]
    else:
        args = ['nmap', '-sC', '-sV', host]

    output_lines.append("---------------------------------------------")
    output_lines.append("|                     NMAP                  |")
    output_lines.append("---------------------------------------------")

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

        # Parse ports and script output
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

    print("\n".join(output_lines))
    print(f"[*] Finished Nmap check on {host}")
    output_lines.append("---------------------------------------------")
    return "\n".join(output_lines)


def main():
    args = parse_arguments()
    checks_to_run = args.checks

    outputs = []
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    outputs.append(f"Web Security Scan Report\nTarget: {args.target}\nDate: {timestamp}\n")

    check_dispatch = {
        "ssl": lambda: run_ssl_check(args.target),
        "headers": lambda: run_headers_check(args.target),
        "dns": lambda: run_dns_check(args.target),
        "nmap": lambda: run_nmap_check(args.target, safe_mode=args.safe_mode),
        "cookies": lambda: run_cookies_check(args.target),
    }

    for check in checks_to_run:
        outputs.append("="*60)
        outputs.append(f"{check.upper()} CHECK")
        outputs.append("="*60)
        if check in check_dispatch:
            result = check_dispatch[check]()
            outputs.append(result)
        else:
            outputs.append(f"Unknown check: {check}")

    report = "\n".join(outputs)

    with open("scan_report.txt", "w", encoding="utf-8") as f:
        f.write(report)

    print("Scan complete. Results saved to scan_report.txt")

if __name__ == "__main__":
    main()
