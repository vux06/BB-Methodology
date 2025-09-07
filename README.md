# 🕵️ Bug Bounty Mega Checklist  

A comprehensive bug bounty hunting checklist from **low-severity findings to critical vulnerabilities**.  
Use this as a reference when approaching new targets.  

---

## 🌐 Recon & Information Disclosure
- SPF / DKIM / DMARC misconfig (email spoofing)  
- Zone transfers (AXFR)  
- Subdomain takeover (dangling CNAME, SaaS services, S3, GitHub Pages, Azure, etc.)  
- Publicly exposed repos/files (`.git`, `.svn`, `.DS_Store`, `.bak`, `.zip`, `.old`)  
- Hardcoded secrets in JS / mobile apps (AWS keys, API tokens, passwords)  
- Open directories / exposed backups  
- Verbose error messages / debug endpoints / stack traces  
- `robots.txt` / `sitemap.xml` exposing sensitive paths  
- WHOIS / email leaks / employee OSINT  
- Information disclosure via headers (server version, `X-Powered-By`, etc.)  
- API docs exposed (Swagger, GraphQL introspection, Postman collections)  

---

## 🔐 Authentication & Session
- Missing / weak MFA enforcement  
- OTP bypass (reuse, predictable, resend flood, email vs SMS desync)  
- Bruteforce / rate limiting missing  
- Password reset flaws (predictable tokens, leakage via referer, reuse, no expiry, not invalidated)  
- Session fixation (reusing same token across login)  
- Session not invalidated on logout / password change  
- Weak cookie handling (Secure, HttpOnly, SameSite missing)  
- **JWT vulnerabilities**:  
  - `alg=none`  
  - Weak HMAC secret  
  - `kid` injection  
  - `jku` / `x5u` trust abuse  
- OAuth / SSO misconfigs (redirect_uri manipulation, implicit flow abuse, token leakage via referer)  
- Magic-link / email-link login abuse  

---

## 📊 Authorization & Access Control
- IDOR (horizontal privilege escalation)  
- Vertical privilege escalation (user → admin)  
- Force browsing hidden/admin endpoints  
- Role confusion (customer → staff → admin, parameter switching)  
- Business logic bypass (skipping critical steps in workflow)  
- Object-level authorization flaws (OWASP API #1)  
- Replacing account IDs in mobile/web requests  

---

## 💉 Input Injection
- SQL Injection (classic, union, blind, time-based, error-based)  
- Command Injection (`;`, `|`, `&&`, `$()`, PowerShell abuse)  
- NoSQL Injection (Mongo, Couch, etc.)  
- LDAP Injection  
- GraphQL Injection (deep queries, batching, DoS)  
- Template Injection (SSTI – Jinja2, Twig, Handlebars, etc.)  
- XML External Entity (XXE)  
- Deserialization vulnerabilities (Java, PHP, Python Pickle, Node.js)  
- CRLF Injection (HTTP response splitting, log injection)  

---

## 🖼 Client-Side
- Reflected XSS  
- Stored XSS  
- DOM-based XSS  
- CSP bypass → XSS (JSONP, Angular/React gadgets, etc.)  
- Clickjacking (sensitive actions without `X-Frame-Options`)  
- Open redirect (phishing/session theft)  
- Mixed content (HTTPS site loading insecure HTTP resources)  
- CORS misconfig (wildcard + credentials, `null` origin, overly trusted subdomain)  
- PostMessage abuse (`window.opener`, `targetOrigin='*'`)  
- Service worker abuse (cache poisoning, offline injection)  
- DOM clobbering  
- Prototype pollution (client-side → XSS, gadget chains)  

---

## 📂 File Handling
- Path traversal (`../etc/passwd`)  
- File upload bypass (polyglots, double extensions, MIME tricks)  
- Remote File Inclusion (RFI)  
- Local File Inclusion (LFI → log poisoning, wrappers → RCE)  
- Unrestricted file downloads (arbitrary file read)  
- Exposed file systems (NFS, SMB)  
- Exposed DB/config backups  

---

## 🌍 Server-Side
- SSRF (internal pivoting, cloud metadata theft)  
- Host header injection (cache poisoning, password reset poisoning)  
- Cache poisoning / cache deception  
- WebSocket hijacking / WS CSRF  
- Misconfigured reverse proxies / load balancers (IP bypass)  
- Prototype pollution (server-side, Node.js → RCE)  
- Server-side template injection (SSTI)  
- CRLF injection → HTTP response splitting  
- HTTP Request Smuggling (CL/TE desync, cache poisoning)  
- gRPC misconfig / injection  
- Race conditions in APIs (double purchase, bypass rate limits)  

---

## 🏗 Infrastructure & Cloud
- S3 bucket exposure (read/write/list)  
- GCP buckets / Firebase DB exposure  
- Publicly exposed admin dashboards (Kibana, Grafana, Jenkins, etc.)  
- Docker / Kubernetes API exposed  
- Redis / MongoDB / ElasticSearch open to internet  
- IAM role misconfig (assume-role escalation, overly permissive roles)  
- Exposed CI/CD pipelines (GitLab, GitHub Actions secrets)  
- SSRF → cloud credential theft (AWS/GCP/Azure metadata → creds → infra takeover)  
- Server misconfig (default creds, outdated versions, CVE exploitation)  

---

## 💸 Business Logic & Application Abuse
- Price manipulation (changing product value in requests)  
- Negative balance / refund abuse  
- Unlimited coupon / voucher use  
- Race conditions (bypass quantity limits, duplicate actions)  
- Inventory lock abuse (reserving items without payment)  
- Account takeover via workflow abuse (flawed email/phone change)  
- Payment gateway tampering (skipping payment verification step)  
- Referral/reward program abuse  
- Abuse of email/SMS features for spam/DoS  
- Abuse of password reset to lock out victims  

---

## 🚨 Critical / Chainable
- Remote Code Execution (RCE via injection, deserialization, LFI+upload, SSTI chain)  
- Database takeover (SQLi → dump, OS command exec)  
- Full account takeover (session hijack, reset abuse, auth bypass)  
- Critical SSRF → infra takeover (AWS/GCP/Azure creds)  
- Cloud misconfigs (IAM privilege escalation → root)  
- Supply chain attacks (dependency confusion, malicious npm/pypi packages)  
- Sandbox / container escape (Docker/K8s breakout)  
- Payment fraud → actual money loss  
- Zero-days in web components / CMS  

---

## ⚡ Extra Rare but Report-Worthy
- Web cache deception (auth pages cached as public)  
- HTTP Request Smuggling (advanced cache poisoning/desync)  
- Subprotocol attacks on WebSockets (`gopher://`, `file://`, etc.)  
- OAuth token leakage in `Referer` headers  
- SAML misconfigs (signature wrapping, XML injection)  
- Race conditions in MFA enrollment (attacker registers factor first)  

---

🔥 **Pro Tip:** Use this as a **mind-map** when hunting — don’t just stick to “one bug type.” Always test broad and deep.  
