# 🛡️ WebSec Auditor: Consolidated Web Security Scanner

WebSec Auditor is an all-in-one Python-based tool that automates **web security testing** and consolidates key findings in one place. It performs SSL analysis, HTTP header inspection, DNS lookups, cookie checks, and more. It also integrates with tools like **Nmap**, **ZAP**, and optionally routes traffic through **Tor**.

---

## 🚀 Features

### ✅ SSL & TLS Checker
- Parses and displays certificate subject, issuer, expiration, and SANs
- Uses [SSL Labs API](https://www.ssllabs.com/) to:
  - Identify supported protocols (TLS 1.0–1.3)
  - Flag vulnerable configurations (Heartbleed, FREAK, DROWN, etc.)
  - List weak cipher suites

### ✅ HTTP Security Headers
- Detects missing or insecure headers:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
  - `Access-Control-Allow-Origin`
- Detects HTTP to HTTPS redirection
- Analyzes CSP for risky directives like `'unsafe-inline'`, `*`, etc.

### 🍪 Cookie Scanner 
- Checks for:
  - Missing `HttpOnly`, `Secure`, and `SameSite` flags
  - Potential cross-domain access vulnerabilities

### 🌐 DNS Recon

This module performs DNS reconnaissance for a target domain.

#### ✅ Features:
- **Resolves common DNS records**:
- **Zone Transfer Testing**:
- **DMARC, SPF and DKIM info**;

### 📡 Nmap Integration 
- Performs port scanning and service detection
- Identifies open ports, vulnerable services, and version info

### 🧅 Tor Support 
- Routes traffic through the Tor network for anonymity
- Detects censorship or geo-blocking


### 🔌 ZAP Integration *(planned)*
- Automates OWASP ZAP scans via API
- Consolidates findings into main report

---

## 📦 Installation
before cloning make sure you have google-chrome or firefox installed due to cookie web crawling 
```bash
git clone https://github.com/yourname/websec-auditor.git
cd websec-auditor
pip install -r requirements.txt
