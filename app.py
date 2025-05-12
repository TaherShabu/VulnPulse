import sqlite3
import csv
import io
from urllib.parse import urlencode
from flask import Flask, render_template_string, request, send_file, jsonify, url_for

app = Flask(__name__)

VULN_META = {
    "SQL Injection (SQLi)": {
        "about": "SQL Injection occurs when user input is directly included in SQL queries, allowing attackers to manipulate the database.",
        "prevent": "Always use parameterized queries or prepared statements. Never concatenate user input into SQL strings. Use ORM frameworks where possible, and validate all user input."
    },
    "Cross-Site Scripting (XSS)": {
        "about": "XSS allows attackers to inject malicious scripts into web pages viewed by other users.",
        "prevent": "Escape all user output, use frameworks that auto-escape by default, set Content Security Policy headers, and validate input where possible."
    },
    "Broken Authentication": {
        "about": "Broken Authentication vulnerabilities allow attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users’ identities.",
        "prevent": "Implement multi-factor authentication, use secure password storage (bcrypt, Argon2), invalidate sessions on logout, and avoid exposing session IDs in URLs."
    },
    "Sensitive Data Exposure": {
        "about": "Sensitive Data Exposure occurs when applications do not adequately protect sensitive information such as financial, healthcare, or PII.",
        "prevent": "Encrypt sensitive data in transit (TLS) and at rest, avoid logging secrets, use secure protocols, and never expose sensitive data in URLs or error messages."
    },
    "Command Injection": {
        "about": "Command Injection allows attackers to execute arbitrary commands on the host operating system via a vulnerable application.",
        "prevent": "Avoid passing user input directly to system commands. Use safe APIs that separate commands and data. Validate and sanitize all inputs."
    },
    "HTML Injection": {
        "about": "HTML Injection occurs when untrusted data is included in HTML content, allowing attackers to inject malicious HTML.",
        "prevent": "Escape HTML special characters in user input before rendering. Validate and sanitize user inputs."
    },
    "XML Injection": {
        "about": "XML Injection involves injecting malicious XML content or entities, including XML External Entity (XXE) attacks, to exploit XML parsers.",
        "prevent": "Disable external entity processing, validate and sanitize XML inputs, and use secure XML parsers."
    },
    "XPath Injection": {
        "about": "XPath Injection allows attackers to manipulate XPath queries used to access XML data.",
        "prevent": "Use parameterized XPath queries, validate and sanitize user inputs."
    },
    "LDAP Injection": {
        "about": "LDAP Injection occurs when untrusted input is used to construct LDAP queries, allowing attackers to manipulate directory queries.",
        "prevent": "Use parameterized LDAP queries, validate and sanitize inputs."
    },
    "CRLF Injection": {
        "about": "CRLF Injection allows attackers to inject carriage return and line feed characters, potentially enabling HTTP response splitting or log injection.",
        "prevent": "Validate and sanitize inputs, especially those used in HTTP headers."
    },
    "Expression Language Injection (EL Injection)": {
        "about": "EL Injection occurs when user input is injected into expression languages, leading to code execution or data leakage.",
        "prevent": "Avoid evaluating user input in expressions, validate and sanitize inputs."
    },
    "Server-Side Request Forgery (SSRF)": {
        "about": "SSRF allows attackers to make server-side requests to unintended locations, potentially accessing internal systems.",
        "prevent": "Validate and restrict URLs, use allowlists, and avoid fetching resources based on user input."
    },
    "Server-Side Template Injection (SSTI)": {
        "about": "SSTI occurs when user input is injected into server-side templates, allowing code execution.",
        "prevent": "Avoid rendering user input in templates without proper escaping. Use safe templating engines."
    },
    "Cross-Site Request Forgery (CSRF)": {
        "about": "CSRF tricks authenticated users into submitting unwanted requests to a web application.",
        "prevent": "Use anti-CSRF tokens, check Referer headers, and require user interaction for sensitive actions."
    },
    "Clickjacking": {
        "about": "Clickjacking tricks users into clicking hidden or disguised UI elements.",
        "prevent": "Use X-Frame-Options or Content Security Policy frame-ancestors headers to prevent framing."
    },
    "Open Redirect": {
        "about": "Open Redirect vulnerabilities allow attackers to redirect users to malicious sites.",
        "prevent": "Validate and restrict redirect URLs to trusted domains."
    },
    "Insecure Direct Object Reference (IDOR)": {
        "about": "IDOR allows attackers to access unauthorized objects by manipulating references.",
        "prevent": "Implement proper authorization checks on object access."
    },
    "Broken Access Control": {
        "about": "Broken Access Control allows unauthorized actions due to improper enforcement of access policies.",
        "prevent": "Enforce access controls consistently server-side."
    },
    "Privilege Escalation": {
        "about": "Privilege Escalation occurs when attackers gain higher privileges than intended.",
        "prevent": "Implement strict privilege separation and validation."
    },
    "Forced Browsing": {
        "about": "Forced Browsing involves accessing hidden resources by guessing URLs.",
        "prevent": "Use authentication and authorization on all resources."
    },
    "CORS Misconfiguration": {
        "about": "CORS Misconfiguration allows unauthorized cross-origin requests.",
        "prevent": "Configure CORS policies to allow only trusted origins."
    },
    "Insecure Cookie Attributes": {
        "about": "Insecure cookie attributes can expose cookies to theft or misuse.",
        "prevent": "Set Secure, HttpOnly, and SameSite attributes on cookies."
    },
    "Insecure Session Management": {
        "about": "Insecure session management leads to session fixation or hijacking.",
        "prevent": "Regenerate session IDs on login, use secure cookies, and invalidate sessions on logout."
    },
    "Open Admin Interfaces": {
        "about": "Open Admin Interfaces expose administrative functions to unauthorized users.",
        "prevent": "Restrict access to admin interfaces by IP and authentication."
    },
    "Subdomain Takeover": {
        "about": "Subdomain Takeover occurs when attackers claim unused subdomains.",
        "prevent": "Remove DNS entries for unused subdomains and monitor DNS configurations."
    },
    "DNS Takeover": {
        "about": "DNS Takeover allows attackers to control DNS records.",
        "prevent": "Secure DNS management with strong authentication and monitoring."
    },
    "CNAME Misconfiguration": {
        "about": "CNAME Misconfiguration can lead to subdomain takeover or traffic interception.",
        "prevent": "Properly configure CNAME records and monitor DNS."
    },
    "Open S3 Bucket": {
        "about": "Open S3 Buckets expose data publicly due to misconfigured permissions.",
        "prevent": "Set strict bucket policies and restrict public access."
    },
    "Open GCP/Azure Storage": {
        "about": "Open cloud storage exposes sensitive data publicly.",
        "prevent": "Configure storage permissions to restrict public access."
    },
    "Exposed Git Repository": {
        "about": "Exposed Git repositories leak source code and secrets.",
        "prevent": "Restrict access and avoid storing sensitive data in repos."
    },
    "Exposed .env File": {
        "about": "Exposed .env files leak environment variables and secrets.",
        "prevent": "Prevent public access to .env files via server configuration."
    },
    "Exposed Backup Files": {
        "about": "Exposed backup files can leak sensitive data.",
        "prevent": "Secure backup files with access controls."
    },
    "Directory Traversal": {
        "about": "Directory Traversal allows attackers to access files outside intended directories.",
        "prevent": "Validate and sanitize file path inputs."
    },
    "File Upload Vulnerabilities": {
        "about": "File Upload Vulnerabilities allow uploading malicious files.",
        "prevent": "Validate file types, use safe storage locations, and scan uploads."
    },
    "MIME Sniffing": {
        "about": "MIME Sniffing can cause browsers to interpret files incorrectly.",
        "prevent": "Set proper Content-Type headers and use X-Content-Type-Options: nosniff."
    },
    "HTTP Request Smuggling": {
        "about": "HTTP Request Smuggling exploits inconsistencies in HTTP parsing.",
        "prevent": "Use updated servers and proxies that handle requests correctly."
    },
    "HTTP Response Splitting": {
        "about": "HTTP Response Splitting allows injection of headers and content.",
        "prevent": "Validate and sanitize header inputs, avoid CRLF injection."
    },
    "Host Header Injection": {
        "about": "Host Header Injection manipulates the Host header to bypass security.",
        "prevent": "Validate Host headers and use fixed values where possible."
    },
    "Insecure Deserialization": {
        "about": "Insecure Deserialization allows attackers to execute arbitrary code via crafted objects.",
        "prevent": "Avoid deserializing untrusted data or use safe deserialization libraries."
    },
    "Prototype Pollution": {
        "about": "Prototype Pollution manipulates object prototypes to alter application behavior.",
        "prevent": "Validate and sanitize inputs that modify object properties."
    },
    "DOM Clobbering": {
        "about": "DOM Clobbering allows attackers to override DOM elements and scripts.",
        "prevent": "Avoid using unsafe DOM methods and validate inputs."
    },
    "Insecure JavaScript Dependencies": {
        "about": "Insecure dependencies introduce vulnerabilities via third-party code.",
        "prevent": "Regularly update dependencies and audit for vulnerabilities."
    },
    "Bypassing WAF/Rate Limits": {
        "about": "Attackers bypass Web Application Firewalls or rate limits to perform attacks.",
        "prevent": "Use advanced WAFs, anomaly detection, and strict rate limiting."
    },
    "Insecure Caching": {
        "about": "Insecure caching exposes sensitive data to unauthorized users.",
        "prevent": "Configure cache controls to prevent sensitive data caching."
    },
    "No Rate Limiting": {
        "about": "Lack of rate limiting enables brute force and denial of service attacks.",
        "prevent": "Implement rate limiting on critical endpoints."
    },
    "Cache Poisoning": {
        "about": "Cache Poisoning injects malicious content into caches.",
        "prevent": "Validate cache keys and control cache behavior."
    },
    "Logic Flaws": {
        "about": "Logic Flaws are errors in business logic that attackers exploit.",
        "prevent": "Thoroughly test and validate business processes."
    },
    "Email Spoofing": {
        "about": "Email Spoofing forges sender addresses to deceive recipients.",
        "prevent": "Use SPF, DKIM, and DMARC email authentication."
    },
    "Insecure Email Verification": {
        "about": "Weak email verification allows account takeover or fraud.",
        "prevent": "Use secure verification tokens and expiration."
    },
    "SMS/OTP Bypass": {
        "about": "SMS or OTP bypass allows attackers to circumvent two-factor authentication.",
        "prevent": "Use robust multi-factor authentication methods."
    },
    "Misconfigured Cloud Permissions (IAM)": {
        "about": "Misconfigured IAM permissions expose cloud resources.",
        "prevent": "Apply least privilege and regularly audit permissions."
    },
    "Open Docker APIs": {
        "about": "Open Docker APIs allow unauthorized container control.",
        "prevent": "Secure Docker APIs with authentication and firewalls."
    },
    "Kubernetes Dashboard Exposure": {
        "about": "Exposed Kubernetes dashboards allow cluster control.",
        "prevent": "Restrict dashboard access and use authentication."
    },
    "Insecure Mobile Storage": {
        "about": "Insecure mobile storage leaks sensitive data on devices.",
        "prevent": "Encrypt sensitive data and use secure storage APIs."
    },
    "Insecure Android Intents": {
        "about": "Insecure Intents allow data leakage or privilege escalation.",
        "prevent": "Use explicit intents and validate intent data."
    },
    "Android WebView Exploits": {
        "about": "WebView exploits allow code injection in mobile apps.",
        "prevent": "Disable JavaScript where not needed and validate URLs."
    },
    "iOS URL Scheme Hijack": {
        "about": "URL Scheme Hijacking allows malicious apps to intercept data.",
        "prevent": "Use secure URL schemes and validate inputs."
    },
    "API Rate Limit Bypass": {
        "about": "Attackers bypass API rate limits to perform abuse.",
        "prevent": "Implement robust rate limiting and authentication."
    },
    "GraphQL Introspection Enabled": {
        "about": "Enabled introspection exposes GraphQL schema to attackers.",
        "prevent": "Disable introspection in production or restrict access."
    },
    "GraphQL Injection": {
        "about": "GraphQL Injection manipulates queries to access unauthorized data.",
        "prevent": "Validate and sanitize GraphQL inputs."
    },
    "Broken Object Level Authorization (BOLA)": {
        "about": "BOLA allows unauthorized access to objects by bypassing authorization.",
        "prevent": "Enforce strict object-level authorization checks."
    },
    "Broken Function Level Authorization (BFLA)": {
        "about": "BFLA allows unauthorized function or API access.",
        "prevent": "Implement role-based access control on functions."
    },
    "Mass Assignment": {
        "about": "Mass Assignment allows attackers to modify object properties via bulk updates.",
        "prevent": "Whitelist allowed fields and validate inputs."
    },
    "Unsafe Redirects in Mobile Apps": {
        "about": "Unsafe redirects lead users to malicious destinations.",
        "prevent": "Validate redirect URLs and use allowlists."
    },
    "Native App Debug Info Leak": {
        "about": "Debug info leaks sensitive data in native apps.",
        "prevent": "Disable debug info in production builds."
    },
    "WebSocket Hijacking": {
        "about": "WebSocket Hijacking allows attackers to intercept or manipulate WebSocket connections.",
        "prevent": "Use authentication, encryption, and origin checks."
    },
    "Insecure WebSocket Usage": {
        "about": "Insecure WebSocket usage exposes data or allows attacks.",
        "prevent": "Use secure WebSocket protocols (wss) and validate messages."
    },
    "TLS/SSL Misconfiguration": {
        "about": "TLS/SSL Misconfiguration weakens encrypted communication.",
        "prevent": "Use strong ciphers, disable deprecated protocols, and configure properly."
    },
    "Hardcoded Secrets / API Keys": {
        "about": "Hardcoded secrets expose credentials in code.",
        "prevent": "Use secure vaults and environment variables."
    },
    "Leaked Credentials in Repos": {
        "about": "Leaked credentials in source repositories allow unauthorized access.",
        "prevent": "Scan repos for secrets and rotate compromised credentials."
    },
    "Dependency Confusion": {
        "about": "Dependency Confusion tricks systems into installing malicious packages.",
        "prevent": "Use private package registries and verify dependencies."
    },
    "Package Typosquatting": {
        "about": "Typosquatting involves malicious packages with similar names.",
        "prevent": "Verify package sources and names carefully."
    },
    "DLL Hijacking (Windows)": {
        "about": "DLL Hijacking loads malicious DLLs due to search order issues.",
        "prevent": "Use fully qualified paths and secure DLL loading."
    },
    "Symlink Race Attacks": {
        "about": "Symlink race attacks exploit time-of-check to time-of-use vulnerabilities.",
        "prevent": "Use secure file handling and atomic operations."
    },
    "Insecure File Permissions": {
        "about": "Insecure file permissions expose sensitive files.",
        "prevent": "Set least privilege permissions on files."
    },
    "Zip Slip": {
        "about": "Zip Slip allows directory traversal via crafted archive extraction.",
        "prevent": "Validate and sanitize file paths during extraction."
    },
    "HTTP Method Override": {
        "about": "HTTP Method Override abuses headers to change request methods.",
        "prevent": "Validate and restrict allowed HTTP methods."
    },
    "Unrestricted File Download": {
        "about": "Allows downloading of arbitrary files.",
        "prevent": "Validate file paths and restrict access."
    },
    "Insecure Iframes": {
        "about": "Insecure iframes can be used for clickjacking or malicious content.",
        "prevent": "Use sandbox attributes and CSP to control iframes."
    },
    "Framing Attacks": {
        "about": "Framing attacks trick users via embedded frames.",
        "prevent": "Use X-Frame-Options or CSP frame-ancestors."
    },
    "Reflected File Download": {
        "about": "Reflected File Download tricks users into downloading malicious files.",
        "prevent": "Validate file names and content disposition headers."
    },
    "CDN Misconfiguration": {
        "about": "CDN Misconfiguration exposes sensitive data or allows cache poisoning.",
        "prevent": "Configure CDN caching and access controls properly."
    },
    "OAuth Misconfiguration": {
        "about": "OAuth Misconfiguration leads to token leakage or unauthorized access.",
        "prevent": "Follow OAuth best practices and validate redirect URIs."
    },
    "Open Firebase Database": {
        "about": "Open Firebase databases allow unauthorized data access.",
        "prevent": "Set Firebase security rules to restrict access."
    },
    "Insufficient Logging and Monitoring": {
        "about": "Lack of logging and monitoring delays attack detection.",
        "prevent": "Implement comprehensive logging and real-time monitoring."
    },
    "Tainted Third-party Scripts": {
        "about": "Third-party scripts can introduce vulnerabilities or malicious code.",
        "prevent": "Audit and restrict third-party scripts."
    },
    "Supply Chain Attack": {
        "about": "Supply chain attacks compromise software dependencies or build processes.",
        "prevent": "Secure build pipelines and verify dependencies."
    },
    "App Transport Security Bypass (iOS)": {
        "about": "Bypassing iOS App Transport Security allows insecure network communication.",
        "prevent": "Enforce ATS and avoid exceptions."
    },
    "Email Enumeration": {
        "about": "Email Enumeration leaks valid email addresses.",
        "prevent": "Use generic error messages and rate limiting."
    },
    "HTML5 Storage Misuse (localStorage/sessionStorage)": {
        "about": "Misuse of HTML5 storage exposes sensitive data to XSS attacks.",
        "prevent": "Avoid storing sensitive data in localStorage/sessionStorage."
    },
    "Unsafe Regular Expressions (ReDoS)": {
        "about": "Unsafe regex patterns cause denial of service via excessive backtracking.",
        "prevent": "Use safe regex patterns and limit input size."
    },
    "Heap Overflow": {
        "about": "Heap Overflow corrupts memory leading to code execution.",
        "prevent": "Use safe languages and memory management."
    },
    "Buffer Overflow": {
        "about": "Buffer Overflow overwrites memory causing crashes or code execution.",
        "prevent": "Use safe coding practices and bounds checking."
    },
    "Use After Free": {
        "about": "Use After Free accesses memory after it is freed.",
        "prevent": "Use safe memory management and avoid dangling pointers."
    },
    "Integer Overflow": {
        "about": "Integer Overflow causes unexpected behavior due to arithmetic overflow.",
        "prevent": "Validate inputs and use safe arithmetic operations."
    },
    "Format String Vulnerabilities": {
        "about": "Format String vulnerabilities allow code execution via uncontrolled format strings.",
        "prevent": "Avoid user-controlled format strings."
    },
    "Race Conditions in File Access": {
        "about": "Race conditions lead to inconsistent or insecure file operations.",
        "prevent": "Use atomic operations and proper locking."
    },
    "Cross-Site Script Inclusion (XSSI)": {
        "about": "XSSI allows attackers to steal sensitive data via script inclusion.",
        "prevent": "Use anti-XSSI tokens and proper content-type headers."
    },
    "Font Injection": {
        "about": "Font Injection injects malicious fonts to exploit vulnerabilities.",
        "prevent": "Validate font sources and use CSP."
    },
    "Insecure QR Code Handling": {
        "about": "Insecure QR code handling can lead to phishing or malware.",
        "prevent": "Validate QR code content before processing."
    },
    "Bluetooth/WiFi-Based Attacks": {
        "about": "Attacks exploiting Bluetooth or WiFi vulnerabilities.",
        "prevent": "Use secure protocols and update firmware."
    },
    "RCE via misconfigured CI/CD": {
        "about": "Remote Code Execution via misconfigured Continuous Integration/Deployment pipelines.",
        "prevent": "Secure CI/CD pipelines and restrict access."
    }
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8" />
    <title>VulnPulse Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" />
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background: #171b22; color: #e0e0e0; font-family: 'Fira Mono', 'Consolas', monospace, Arial, sans-serif; }
        h1 {
  letter-spacing: 2px;
  font-weight: bold;
  color: #00ffae;
  text-shadow: 0 4px 6px rgba(0, 255, 174, 0.5); /* Improved shadow effect */
  margin-bottom: 0.7em;
  text-align: center; /* Centers the text */
  width: 100%; /* Ensure it spans the full width of the container */
  display: block; /* Ensure it's a block element */
  padding: 0 10px; /* Optional, adds padding around text */
}

        .section-title { color: #00ffae; font-size: 1.3em; margin-top: 1.5em; margin-bottom: 0.7em; font-weight: bold; letter-spacing: 1px; border-bottom: 2px solid #00ffae; padding-bottom: 0.3em; background: linear-gradient(90deg, #00ffae22 0%, #171b22 100%);}
.category-badge {
  display: inline-block;
  width: 100px;                /* fixed width */
  height: 100px;               /* fixed height */
  background-color: #2c2c2c;
  color: white;
  padding: 10px;
  overflow: hidden;
  text-align: center;
  vertical-align: top;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.3);
  position: relative;
}

.category-badge * {
  font-size: clamp(10px, 1.2vw, 14px);  /* shrink font to fit */
  word-wrap: break-word;
  max-width: 100%;
}
        .details-box { display: none; margin-top: 6px; background: #22272e; border: 1px solid #00ffae44; padding: 10px 14px; font-size: 0.95em; border-radius: 5px; box-shadow: 0 2px 10px #00ffae22; color: #e0e0e0;}
        .title-cell { cursor: pointer; position: relative; max-width: 450px; word-break: break-word;}
        .bookmark-btn { cursor: pointer;}
        .bookmarked { color: #ffe066;}
        .top10-unique { background: linear-gradient(90deg, #00ffae44 0%, #232c36 100%); border: 2.5px solid #00ffae; border-radius: 14px; box-shadow: 0 4px 32px #00ffae33; padding: 18px 18px 10px 18px; margin-bottom: 20px;}
        .top10-unique h5 { color: #171b22; background: #00ffae; display: inline-block; padding: 6px 22px; border-radius: 18px 18px 0 0; font-weight: bold; font-size: 1.2em; letter-spacing: 2px; margin-bottom: 18px; margin-top: 0; box-shadow: 0 2px 12px #00ffae33;}
        .top10-list { list-style: none; padding-left: 0; margin-bottom: 1.5rem;}
        .top10-list li { background: #232c36; color: #00ffae; border-radius: 8px; padding: 8px 18px; margin-bottom: 8px; font-size: 1.05em; display: flex; align-items: center; justify-content: space-between; font-family: 'Fira Mono', monospace; font-weight: bold; letter-spacing: 1px; border-left: 6px solid #00ffae; transition: background 0.2s, color 0.2s;}
        .top10-list li.selected, .top10-list li:hover { background: #00ffae; color: #171b22; cursor: pointer;}
        .top10-list .cat-count { font-size: 0.95em; color: #aaa; margin-left: 10px; font-weight: normal;}
        .sidebar { background: #1a1e25; border-radius: 14px; padding: 18px 18px 10px 18px; box-shadow: 0 2px 16px #00ffae11; margin-bottom: 20px;}
        .sidebar h5 { color: #00ffae; font-size: 1.1em; margin-top: 1.5em; margin-bottom: 0.7em; font-weight: bold; letter-spacing: 1px;}
        .form-select, .form-control { background: #232c36; color: #00ffae; border: 1.5px solid #00ffae55;}
        .form-select:focus, .form-control:focus { background: #232c36; color: #00ffae; border: 1.5px solid #00ffae; box-shadow: 0 0 0 0.2rem #00ffae33;}
        .btn-primary, .btn-outline-success, .btn-outline-secondary { background: #00ffae; color: #171b22; border: none; font-weight: bold; box-shadow: 0 2px 10px #00ffae22;}
        .btn-primary:hover, .btn-outline-success:hover, .btn-outline-secondary:hover { background: #0077ff; color: #fff;}
        .table { color: #e0e0e0; background: #1a1e25; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 16px #00ffae11;}
        .table th, .table td { border-color: #232c36;}
        .table thead th { background: #00ffae; color: #171b22; font-size: 1.07em; letter-spacing: 1px; border-bottom: 3px solid #00ffae;}
        .table-hover tbody tr:hover { background-color: #232c36;}
        .pagination .page-link { background: #232c36; color: #00ffae; border: 1.5px solid #00ffae44;}
        .pagination .page-item.active .page-link { background: #00ffae; color: #171b22; border: 1.5px solid #00ffae;}
        .fw-semibold { font-weight: 600; color: #fff; text-shadow: 0 0 5px #00ffae22;}
        .btn-link { color: #00ffae;}
        .btn-link:hover { color: #0077ff;}
        ::selection { background: #00ffae; color: #171b22;}
        @media (max-width: 991px) { .sidebar, .top10-unique { margin-bottom: 30px; } }
        @media (max-width: 600px) { .table-responsive { font-size: 13px; } .sidebar, .top10-unique { margin-bottom: 20px; } }
    </style>
</head>
<body>
<div class="container my-4">
    <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap">
        <h1>VulnPulse Dashboard</h1>
    </div>
    <div class="row">
        <div class="container-fluid mt-4">
  <div class="row">
  
  <!-- Top 10 List (Right Side) -->
    <div class="col-lg-3 mb-4">
      <div class="top10-unique">
        <h5>TOP 10 VULNERABILITIES</h5>
        <ul class="top10-list">
          <li class="{% if not selected_category %}selected{% endif %}" onclick="filterByCategory('')">All</li>
          {% for cat in top10 %}
            <li class="{% if selected_category == cat.category %}selected{% endif %}" onclick="filterByCategory('{{ cat.category }}')">
              <span>{{ cat.category }}</span>
              <span class="cat-count">{{ cat.count }}</span>
            </li>
          {% endfor %}
          {% if new %}
            <li style="background:#232c36;cursor:default;"><em>New Categories</em></li>
            {% for cat in new %}
              <li class="{% if selected_category == cat.category %}selected{% endif %}" onclick="filterByCategory('{{ cat.category }}')">
                <span>{{ cat.category }}</span>
                <span class="cat-count">{{ cat.count }}</span>
              </li>
            {% endfor %}
          {% endif %}
          {% if unknown %}
            <li style="background:#232c36;cursor:default;"><em>Unknown Category</em></li>
            {% for cat in unknown %}
              <li class="{% if selected_category == cat.category %}selected{% endif %}" onclick="filterByCategory('{{ cat.category }}')">
                <span>{{ cat.category }}</span>
                <span class="cat-count">{{ cat.count }}</span>
              </li>
            {% endfor %}
          {% endif %}
        </ul>
      </div>
    </div>
    
    <!-- Main Content: Filters & Reports (Center) -->
    <div class="col-lg-6 mb-4">
      <div class="section-title">Filter Reports</div>
      <form class="row g-2 mb-4" id="filterForm" method="get">
        <div class="col-md-9">
          <input type="text" class="form-control" name="q" placeholder="Search title, keyword, or URL" value="{{ q }}" />
        </div>
        <input type="hidden" name="category" id="categoryField" value="{{ selected_category }}">
        <div class="col-md-3 d-grid">
          <button class="btn btn-primary" type="submit">Filter</button>
        </div>
        <div class="col-12 mt-2">
          <label>Categories:</label>
          <select name="category" class="form-select" style="height: 80px;" onchange="filterByCategory(this.value)">
  <option value="" {% if not selected_category %}selected{% endif %}>All</option>
  {% for c in all_categories %}
    <option value="{{ c }}" {% if c == selected_category %}selected{% endif %}>{{ c }}</option>
  {% endfor %}
</select>

        </div>
      </form>

      <div class="mb-3">
        <button class="btn btn-outline-success btn-sm" onclick="exportCSV()">Export CSV</button>
        <button class="btn btn-outline-secondary btn-sm" onclick="window.print()">Print</button>
      </div>

      <div class="section-title">Vulnerability Reports</div>
      <div class="table-responsive">
        <table class="table table-hover align-middle" id="reportsTable">
          <thead>
            <tr>
              <th>Title</th>
              <th>Category</th>
              <th>Date</th>
              <th>Bookmark</th>
            </tr>
          </thead>
          <tbody>
            {% for r in reports %}
            <tr>
              <td class="title-cell" style="position: relative;">
                <a href="{{ r.url }}" target="_blank" class="fw-semibold" style="color:#00ffae;">{{ r.title }}</a>
              </td>
              <td>
  <span class="category-badge">
    {{ r.category }}
  </span>
</td>


              <td>
                {% if r.day and r.month and r.year %}
                  {{ "%02d"|format(r.day) }}/{{ "%02d"|format(r.month) }}/{{ r.year }}
                {% else %}
                  {{ r.disclosed_at }}
                {% endif %}
              </td>
              <td>
                <button class="btn btn-link bookmark-btn" data-id="{{ r.id }}">
                  <span id="bm-{{ r.id }}" class="bi bi-star"></span>
                </button>
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

      <!-- Pagination -->
      <div class="d-flex justify-content-between align-items-center mt-3">
        <div>
          <span style="color:#00ffae; font-weight:bold;">Page:</span>
          <form method="get" id="pageSelectForm" class="d-inline">
            <select id="pageSelect" name="page" class="form-select d-inline" style="width: auto; display: inline-block; background:#232c36; color:#00ffae; border:1.5px solid #00ffae55; font-size:0.95em; margin-left:6px;" onchange="this.form.submit()">
              {% for p in range(1, total_pages+1) %}
                <option value="{{ p }}" {% if page == p %}selected{% endif %}>{{ p }}</option>
              {% endfor %}
            </select>
            <input type="hidden" name="q" value="{{ q }}">
            <input type="hidden" name="category" value="{{ selected_category }}">
          </form>
          <span style="color:#aaa; font-size:0.95em; margin-left:12px;">of {{ total_pages }}</span>
        </div>
        <nav>
          <ul class="pagination mb-0">
            {% for item in pagination_links %}
              <li class="page-item {% if item.page == page %}active{% endif %}">
                <a class="page-link" href="{{ item.url }}">{{ item.page }}</a>
              </li>
            {% endfor %}
          </ul>
        </nav>
      </div>
    </div>
    <!-- Graphs Section (Left Side) -->
   <div class="col-lg-3 mb-4">
  <div class="sidebar">
    <h5>Category Distribution</h5>
    <canvas id="pieChart" height="180"></canvas>
    <h5 class="mt-4">Top 10 Bar</h5>
    <canvas id="barChart" height="400" style="margin-top: 20px; margin-left: 10px;"></canvas>

    <p style="font-size: 0.85em; color: #666; margin-top: 20px;">
      <em>Disclaimer:</em> The data presented here is sourced from publicly disclosed reports on HackerOne and is intended for educational and research purposes only. While we strive for accuracy, the insights may not fully represent real-time trends or the complete security landscape.For suggestions, feedback, or to report any issues, please contact us at --<a href="mailto:shabutaher0@gmail.com">shabutaher0@gmail.com</a>.<br>
      Curated and developed by Taher Shabu, with contributions from Vamshi Reddy.
    </p>
  </div>
</div>
  </div>
</div>


<script>
   function filterByCategory(cat) {
    var field = document.getElementById('categoryField');
    var form = document.getElementById('filterForm');
    if (field && form) {
        field.value = cat;
        form.submit();
    }
}

    document.querySelectorAll('.details-toggle').forEach(btn => {
        btn.addEventListener('click', e => {
            e.stopPropagation();
            const id = btn.getAttribute('data-id');
            const box = document.getElementById('details-' + id);
            const isVisible = box.style.display === 'block';
            document.querySelectorAll('.details-box').forEach(el => el.style.display = 'none');
            box.style.display = isVisible ? 'none' : 'block';
        });
    });
    document.addEventListener('click', () => {
        document.querySelectorAll('.details-box').forEach(el => el.style.display = 'none');
    });
    document.querySelectorAll('.bookmark-btn').forEach(btn => {
        const id = btn.getAttribute('data-id');
        const star = document.getElementById('bm-' + id);
        if (localStorage.getItem('bm-' + id)) {
            star.classList.add('bookmarked', 'bi-star-fill');
            star.classList.remove('bi-star');
        }
        btn.addEventListener('click', e => {
            e.stopPropagation();
            if (localStorage.getItem('bm-' + id)) {
                localStorage.removeItem('bm-' + id);
                star.classList.remove('bookmarked', 'bi-star-fill');
                star.classList.add('bi-star');
            } else {
                localStorage.setItem('bm-' + id, '1');
                star.classList.add('bookmarked', 'bi-star-fill');
                star.classList.remove('bi-star');
            }
        });
    });
    function exportCSV() {
        const params = new URLSearchParams(new FormData(document.getElementById('filterForm')));
        window.location = '/exportcsv?' + params.toString();
    }
    fetch('/chartdata?' + new URLSearchParams(window.location.search).toString())
        .then(res => res.json())
        .then(data => {
   new Chart(document.getElementById('barChart'), {
    type: 'bar',
    data: {
        labels: data.bar.labels,
        datasets: [{
            label: 'Top 10 Categories',
            data: data.bar.data,
            backgroundColor: '#00ffae'
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: true,
        layout: {
            padding: {
                left: 0, // ✅ Shift chart fully to the left
                right: 0,
                top: 0,
                bottom: 0
            }
        },
        plugins: {
            legend: { display: false },
            tooltip: {
                callbacks: {
                    title: function(tooltipItems) {
                        // ✅ Show full label on hover only
                        return data.bar.labels[tooltipItems[0].dataIndex];
                    }
                }
            }
        },
        scales: {
            x: {
                ticks: {
                    display: false // ✅ Hide x-axis labels completely
                },
                grid: { color: '#333' }
            },
            y: {
                ticks: {
                    color: '#00ffae'
                },
                grid: { color: '#333' }
            }
        }
    }
});


            new Chart(document.getElementById('pieChart'), {
                type: 'pie',
                data: {
                    labels: data.pie.labels,
                    datasets: [{ label: 'Top 1', data: data.pie.data, backgroundColor: [
                        '#00ffae', '#0077ff', '#ff00ae', '#aeff00', '#ffaa00', '#00aaff', '#ffae00', '#ae00ff', '#ff0077', '#00ffaa', '#22272e', '#444', '#888'
                    ] }]
                },
                options: {
                    plugins: { legend: { labels: { color: '#00ffae' } } }
                }
            });
        });
</script>
</body>
</html>
"""


def get_db_connection():
    conn = sqlite3.connect('hackerone_reports.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_all_categories():
    conn = get_db_connection()
    rows = conn.execute('SELECT DISTINCT category FROM reports').fetchall()
    conn.close()
    return sorted([r['category'] for r in rows])

def get_years():
    conn = get_db_connection()
    rows = conn.execute('SELECT DISTINCT year FROM reports WHERE year IS NOT NULL').fetchall()
    conn.close()
    return sorted([r['year'] for r in rows if r['year']])

def get_category_counts():
    conn = get_db_connection()
    rows = conn.execute('SELECT category, COUNT(*) as count FROM reports GROUP BY category').fetchall()
    conn.close()
    known = []
    other = []
    for r in rows:
        cat = r['category']
        if cat in VULN_META:
            known.append({"category": cat, "count": r['count']})
        else:
            other.append({"category": "Other", "count": r['count']})
    known = sorted(known, key=lambda x: x['count'], reverse=True)
    other_combined = {"category": "Other", "count": sum(x['count'] for x in other)}
    return known, [other_combined] if other_combined['count'] > 0 else []

def filter_reports(args, per_page=20):  # Changed: per_page as parameter with default
    q = args.get('q', '').strip()
    year = args.get('year')
    month = args.get('month')
    where = []
    params = []
    page = int(args.get('page', 1))
    sort = args.get('sort', 'date_desc')
    selected_category = args.get('category', '')
    categories = []

    if selected_category == "Other":
        conn = get_db_connection()
        unknown_cats = [
            r['category']
            for r in conn.execute('SELECT DISTINCT category FROM reports').fetchall()
            if r['category'] not in VULN_META
        ]
        conn.close()

        if unknown_cats:
            placeholders = ",".join(["?"] * len(unknown_cats))
            where.append(f"category IN ({placeholders})")
            params += unknown_cats
        else:
            where.append("0")  # Forces empty result set

    elif selected_category:
        categories = [selected_category]
        placeholders = ",".join(["?"] * len(categories))
        where.append(f"category IN ({placeholders})")
        params += categories

    if q:
        where.append("(title LIKE ? OR url LIKE ? OR category LIKE ?)")
        params += [f"%{q}%"] * 3

    if year:
        where.append("year = ?")
        params.append(year)

    if month:
        where.append("month = ?")
        params.append(month)

    sql = "SELECT * FROM reports"
    if where:
        sql += " WHERE " + " AND ".join(where)
        
    # Fixed: Added ID to ORDER BY for consistent pagination
    if sort == 'date_desc':
        sql += " ORDER BY year DESC, month DESC, day DESC, id DESC"
    else:
        sql += " ORDER BY year ASC, month ASC, day ASC, id ASC"
        
    sql += " LIMIT ? OFFSET ?"
    params += [per_page, per_page * (page - 1)]

    conn = get_db_connection()
    rows = conn.execute(sql, params).fetchall()
    count_sql = "SELECT COUNT(*) FROM reports"
    if where:
        count_sql += " WHERE " + " AND ".join(where)
    total_count = conn.execute(count_sql, params[:-2]).fetchone()[0]
    conn.close()
    return [dict(r) for r in rows], total_count

@app.route("/")
def index():
    args = request.args
    per_page = 5  # Centralized page size definition
    reports, total_count = filter_reports(args, per_page=per_page)  # Pass per_page
    page = int(args.get('page', 1))
    total_pages = (total_count + per_page - 1) // per_page
    all_categories = get_all_categories()
    years = get_years()
    known, other = get_category_counts()
    selected_category = args.get('category', '')
    dark = True
    top10 = known[:10]

    args_dict = request.args.to_dict(flat=False)
    pagination_links = []
    start_page = max(1, page - 5)
    end_page = min(total_pages, page + 5)

    for p in range(start_page, end_page + 1):
        args_dict['page'] = [str(p)]
        link = url_for('index') + '?' + urlencode(args_dict, doseq=True)
        pagination_links.append({'page': p, 'url': link})

    return render_template_string(
        HTML_TEMPLATE,
        reports=reports,
        total_pages=total_pages,
        page=page,
        per_page=per_page,
        q=args.get('q', ''),
        year=int(args.get('year')) if args.get('year', '').isdigit() else '',
        month=int(args.get('month')) if args.get('month', '').isdigit() else '',
        sort=args.get('sort', 'date_desc'),
        all_categories=all_categories,
        selected_categories=[selected_category] if selected_category else [],
        years=years,
        meta=VULN_META,
        dark=dark,
        top10=top10,
        new=[],
        unknown=other,
        selected_category=selected_category,
        pagination_links=pagination_links
    )

# Rest of the code remains identical (chartdata, exportcsv, etc.)


@app.route("/chartdata")
def chartdata():
    conn = get_db_connection()
    rows = conn.execute("SELECT category, COUNT(*) as cnt FROM reports GROUP BY category").fetchall()
    conn.close()

    known = []
    other = []
    for r in rows:
        cat = r['category']
        if cat in VULN_META:
            known.append({"category": cat, "count": r['cnt']})
        else:
            other.append({"category": "Other", "count": r['cnt']})

    known = sorted(known, key=lambda x: x['count'], reverse=True)
    other_combined = {"category": "Other", "count": sum(x['count'] for x in other)}

    top10 = known[:10]
    pie_labels = [c['category'] for c in top10]
    pie_data = [c['count'] for c in top10]
    bar_labels = [c['category'] for c in top10]
    bar_data = [c['count'] for c in top10]

    return jsonify({
        'bar': {'labels': bar_labels, 'data': bar_data},
        'pie': {'labels': pie_labels, 'data': pie_data}
    })

@app.route("/exportcsv")
def exportcsv():
    reports, _ = filter_reports(request.args)
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Title', 'Category', 'Year', 'Month', 'Day', 'URL', 'Disclosed At'])
    for r in reports:
        cw.writerow([r['id'], r['title'], r['category'], r['year'], r['month'], r['day'], r['url'], r['disclosed_at']])
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='vulnpulse_reports.csv')

if __name__ == "__main__":
    app.run(debug=True)