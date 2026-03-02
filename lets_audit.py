"""
Lets Audit — Windows Security Audit Tool
Checks: Open Ports, Weak/Default Passwords, Outdated Software
Outputs: Polished HTML Report
"""

import subprocess
import socket
import json
import os
import sys
import datetime
import platform
import winreg
import ctypes
import re
from pathlib import Path


# ─────────────────────────────────────────────
#  HELPER
# ─────────────────────────────────────────────

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=15)
        return result.stdout.strip()
    except Exception:
        return ""


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


# ─────────────────────────────────────────────
#  1. OPEN PORTS SCAN
# ─────────────────────────────────────────────

COMMON_RISKY_PORTS = {
    21:   ("FTP",        "Transmits data in plaintext — highly insecure."),
    22:   ("SSH",        "Exposed SSH can be brute-forced if misconfigured."),
    23:   ("Telnet",     "Unencrypted remote access — should never be open."),
    25:   ("SMTP",       "Open SMTP can be abused for spam relay."),
    80:   ("HTTP",       "Unencrypted web traffic — consider HTTPS instead."),
    110:  ("POP3",       "Unencrypted email retrieval."),
    135:  ("RPC",        "Windows RPC — frequent attack target."),
    137:  ("NetBIOS",    "Legacy Windows networking — disable if unused."),
    139:  ("NetBIOS",    "Legacy Windows file sharing — disable if unused."),
    143:  ("IMAP",       "Unencrypted email — prefer IMAPS (993)."),
    443:  ("HTTPS",      "Standard secure web traffic — usually OK."),
    445:  ("SMB",        "File sharing — targeted by ransomware (e.g., WannaCry)."),
    1433: ("MSSQL",      "SQL Server — should never be publicly exposed."),
    3306: ("MySQL",      "Database port — should be firewalled from internet."),
    3389: ("RDP",        "Remote Desktop — major brute-force target if exposed."),
    5900: ("VNC",        "Remote control — often has weak authentication."),
    8080: ("HTTP-Alt",   "Alternate HTTP — often used by dev servers accidentally left open."),
}

def scan_open_ports():
    findings = []
    netstat = run_cmd("netstat -ano")
    listening_ports = set()

    for line in netstat.splitlines():
        if "LISTENING" in line or "ESTABLISHED" in line:
            parts = line.split()
            if len(parts) >= 2:
                addr = parts[1]
                try:
                    port = int(addr.rsplit(":", 1)[-1])
                    listening_ports.add(port)
                except ValueError:
                    pass

    for port in sorted(listening_ports):
        if port in COMMON_RISKY_PORTS:
            name, note = COMMON_RISKY_PORTS[port]
            severity = "HIGH" if port in [23, 21, 445, 3389, 5900, 135, 137, 139] else "MEDIUM"
            findings.append({
                "port": port,
                "service": name,
                "note": note,
                "severity": severity,
            })
        else:
            findings.append({
                "port": port,
                "service": "Unknown",
                "note": "Non-standard port in use — verify what process is using it.",
                "severity": "LOW",
            })

    return findings


# ─────────────────────────────────────────────
#  2. WEAK / DEFAULT PASSWORDS
# ─────────────────────────────────────────────

WEAK_PASSWORDS = [
    "password", "123456", "password1", "admin", "letmein",
    "qwerty", "111111", "abc123", "welcome", "monkey",
    "1234567890", "dragon", "master", "pass", "test",
    "guest", "root", "toor", "administrator", "changeme",
]

def check_password_policy():
    findings = []
    policy_raw = run_cmd("net accounts")

    def extract(label, text):
        for line in text.splitlines():
            if label.lower() in line.lower():
                parts = line.split(":")
                if len(parts) > 1:
                    return parts[-1].strip()
        return None

    min_length = extract("Minimum password length", policy_raw)
    max_age    = extract("Maximum password age", policy_raw)
    lockout    = extract("Lockout threshold", policy_raw)
    complexity = run_cmd('powershell -Command "(Get-LocalUser | Select-Object -First 1).PasswordRequired"')

    # Min length
    try:
        ml = int(min_length) if min_length else 0
        if ml < 8:
            findings.append({
                "check": "Minimum Password Length",
                "value": str(ml) if min_length else "Not set",
                "note": "Passwords shorter than 8 characters are trivially brute-forced. Recommended: 12+.",
                "severity": "HIGH",
            })
        else:
            findings.append({
                "check": "Minimum Password Length",
                "value": str(ml),
                "note": "Meets basic standards.",
                "severity": "OK",
            })
    except Exception:
        pass

    # Max age
    try:
        ma = max_age if max_age else "Never"
        if "never" in ma.lower() or ma == "Unlimited":
            findings.append({
                "check": "Password Expiry",
                "value": "Never expires",
                "note": "Passwords that never expire increase long-term compromise risk.",
                "severity": "MEDIUM",
            })
        else:
            findings.append({
                "check": "Password Expiry",
                "value": f"Every {ma} days",
                "note": "Password rotation policy is active.",
                "severity": "OK",
            })
    except Exception:
        pass

    # Lockout
    try:
        lo = int(lockout) if lockout and lockout.isdigit() else 0
        if lo == 0:
            findings.append({
                "check": "Account Lockout Threshold",
                "value": "No lockout",
                "note": "Without account lockout, brute-force attacks can run indefinitely.",
                "severity": "HIGH",
            })
        else:
            findings.append({
                "check": "Account Lockout Threshold",
                "value": f"Locks after {lo} failed attempts",
                "note": "Account lockout is configured.",
                "severity": "OK",
            })
    except Exception:
        pass

    # Guest account
    guest = run_cmd('net user guest | findstr "Account active"')
    if "Yes" in guest:
        findings.append({
            "check": "Guest Account",
            "value": "Enabled",
            "note": "The Guest account is active — it should be disabled.",
            "severity": "HIGH",
        })
    else:
        findings.append({
            "check": "Guest Account",
            "value": "Disabled",
            "note": "Guest account is disabled — good.",
            "severity": "OK",
        })

    # Check for users with empty passwords
    empty_pw = run_cmd('powershell -Command "Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false } | Select-Object -ExpandProperty Name"')
    if empty_pw:
        findings.append({
            "check": "Users Without Required Password",
            "value": empty_pw.replace("\n", ", "),
            "note": "These accounts don't require a password — a serious security risk.",
            "severity": "HIGH",
        })

    return findings


# ─────────────────────────────────────────────
#  3. OUTDATED SOFTWARE
# ─────────────────────────────────────────────

def check_outdated_software():
    findings = []

    # Windows Update status
    wu_status = run_cmd(
        'powershell -Command "(New-Object -ComObject Microsoft.Update.AutoUpdate).Results | Select-Object -ExpandProperty LastInstallationSuccessDate"'
    )
    if wu_status:
        try:
            last_update = datetime.datetime.strptime(wu_status[:10], "%Y-%m-%d")
            days_ago = (datetime.datetime.now() - last_update).days
            severity = "HIGH" if days_ago > 90 else ("MEDIUM" if days_ago > 30 else "OK")
            findings.append({
                "software": "Windows Updates",
                "version": wu_status[:10],
                "note": f"Last successful update was {days_ago} days ago.",
                "severity": severity,
            })
        except Exception:
            findings.append({
                "software": "Windows Updates",
                "version": "Unknown",
                "note": "Could not determine last update date.",
                "severity": "MEDIUM",
            })
    else:
        findings.append({
            "software": "Windows Updates",
            "version": "Unknown",
            "note": "Could not determine Windows Update status. Check manually.",
            "severity": "MEDIUM",
        })

    # Windows Defender
    defender = run_cmd(
        'powershell -Command "Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureAge"'
    )
    try:
        age = int(defender.strip())
        severity = "HIGH" if age > 7 else ("MEDIUM" if age > 3 else "OK")
        findings.append({
            "software": "Windows Defender Signatures",
            "version": f"{age} days old",
            "note": f"Antivirus definitions are {age} days old." + (" Update immediately!" if age > 7 else ""),
            "severity": severity,
        })
    except Exception:
        findings.append({
            "software": "Windows Defender",
            "version": "Unknown",
            "note": "Could not determine Defender signature age.",
            "severity": "MEDIUM",
        })

    # Firewall status
    fw = run_cmd('netsh advfirewall show allprofiles state')
    if "OFF" in fw.upper():
        findings.append({
            "software": "Windows Firewall",
            "version": "OFF",
            "note": "One or more firewall profiles are DISABLED — enable immediately.",
            "severity": "HIGH",
        })
    else:
        findings.append({
            "software": "Windows Firewall",
            "version": "ON",
            "note": "Windows Firewall is active on all profiles.",
            "severity": "OK",
        })

    # Installed software from registry
    outdated_flags = []
    reg_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    risky_old = ["Adobe Flash", "Java 6", "Java 7", "Java 8", "Silverlight",
                 "QuickTime", "WinRAR 4", "VLC 2.", "Internet Explorer"]

    for reg_path in reg_paths:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    sub_name = winreg.EnumKey(key, i)
                    sub_key = winreg.OpenKey(key, sub_name)
                    try:
                        name, _ = winreg.QueryValueEx(sub_key, "DisplayName")
                        version = ""
                        try:
                            version, _ = winreg.QueryValueEx(sub_key, "DisplayVersion")
                        except Exception:
                            pass
                        for risk in risky_old:
                            if risk.lower() in name.lower():
                                outdated_flags.append(f"{name} {version}".strip())
                    except Exception:
                        pass
                except Exception:
                    pass
        except Exception:
            pass

    if outdated_flags:
        for sw in list(set(outdated_flags)):
            findings.append({
                "software": sw,
                "version": "Installed",
                "note": "This software is known to be outdated, unsupported, or a security risk. Uninstall or update.",
                "severity": "HIGH",
            })
    else:
        findings.append({
            "software": "Known Risky Software Scan",
            "version": "—",
            "note": "No known high-risk legacy software detected.",
            "severity": "OK",
        })

    return findings


# ─────────────────────────────────────────────
#  BUILD HTML REPORT
# ─────────────────────────────────────────────

SEVERITY_COLOR = {
    "HIGH":   "#ff4d4d",
    "MEDIUM": "#ffaa00",
    "LOW":    "#4da6ff",
    "OK":     "#00cc88",
}

SEVERITY_BG = {
    "HIGH":   "rgba(255,77,77,0.10)",
    "MEDIUM": "rgba(255,170,0,0.10)",
    "LOW":    "rgba(77,166,255,0.10)",
    "OK":     "rgba(0,204,136,0.08)",
}

def severity_badge(s):
    c = SEVERITY_COLOR.get(s, "#888")
    icon = {"HIGH": "!", "MEDIUM": "-", "LOW": "~", "OK": "+"}.get(s, "?")
    return f'<span class="badge" style="background:{c}22;color:{c};border:1px solid {c}55">{icon} {s}</span>'


def score_from_findings(ports, passwords, software):
    total, issues = 0, 0
    for p in ports:
        total += 1
        if p["severity"] in ("HIGH", "MEDIUM"):
            issues += 1
    for p in passwords:
        total += 1
        if p["severity"] in ("HIGH", "MEDIUM"):
            issues += 1
    for s in software:
        total += 1
        if s["severity"] in ("HIGH", "MEDIUM"):
            issues += 1
    if total == 0:
        return 100
    score = int(((total - issues) / total) * 100)
    return score


def score_color(score):
    if score >= 80:
        return "#00cc88"
    elif score >= 50:
        return "#ffaa00"
    return "#ff4d4d"


def render_port_table(ports):
    if not ports:
        return "<p style='color:#888'>No listening ports detected.</p>"
    rows = ""
    for p in ports:
        c = SEVERITY_COLOR.get(p["severity"], "#888")
        bg = SEVERITY_BG.get(p["severity"], "transparent")
        rows += f"""
        <tr style="background:{bg}">
            <td><code>{p['port']}</code></td>
            <td>{p['service']}</td>
            <td style="color:#aaa;font-size:0.88em">{p['note']}</td>
            <td>{severity_badge(p['severity'])}</td>
        </tr>"""
    return f"<table><thead><tr><th>Port</th><th>Service</th><th>Notes</th><th>Severity</th></tr></thead><tbody>{rows}</tbody></table>"


def render_password_table(passwords):
    if not passwords:
        return "<p style='color:#888'>No password checks completed.</p>"
    rows = ""
    for p in passwords:
        bg = SEVERITY_BG.get(p["severity"], "transparent")
        rows += f"""
        <tr style="background:{bg}">
            <td>{p['check']}</td>
            <td><code>{p['value']}</code></td>
            <td style="color:#aaa;font-size:0.88em">{p['note']}</td>
            <td>{severity_badge(p['severity'])}</td>
        </tr>"""
    return f"<table><thead><tr><th>Check</th><th>Value</th><th>Notes</th><th>Severity</th></tr></thead><tbody>{rows}</tbody></table>"


def render_software_table(software):
    if not software:
        return "<p style='color:#888'>No software checks completed.</p>"
    rows = ""
    for s in software:
        bg = SEVERITY_BG.get(s["severity"], "transparent")
        rows += f"""
        <tr style="background:{bg}">
            <td>{s['software']}</td>
            <td><code>{s['version']}</code></td>
            <td style="color:#aaa;font-size:0.88em">{s['note']}</td>
            <td>{severity_badge(s['severity'])}</td>
        </tr>"""
    return f"<table><thead><tr><th>Software</th><th>Version/Status</th><th>Notes</th><th>Severity</th></tr></thead><tbody>{rows}</tbody></table>"


def count_issues(findings_list):
    return sum(1 for f in findings_list if f.get("severity") in ("HIGH", "MEDIUM"))


def generate_html(ports, passwords, software):
    now = datetime.datetime.now().strftime("%B %d, %Y — %H:%M")
    hostname = platform.node()
    os_info = platform.version()
    score = score_from_findings(ports, passwords, software)
    sc = score_color(score)

    port_issues     = count_issues(ports)
    password_issues = count_issues(passwords)
    software_issues = count_issues(software)
    total_issues    = port_issues + password_issues + software_issues

    grade = "A" if score >= 90 else ("B" if score >= 75 else ("C" if score >= 55 else ("D" if score >= 40 else "F")))

    port_table     = render_port_table(ports)
    password_table = render_password_table(passwords)
    software_table = render_software_table(software)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lets Audit — {hostname}</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #0c0e14;
    --surface: #13151e;
    --surface2: #1a1d28;
    --border: #252836;
    --text: #e8eaf0;
    --muted: #666c80;
    --accent: #7c6af7;
    --high: #ff4d4d;
    --medium: #ffaa00;
    --low: #4da6ff;
    --ok: #00cc88;
  }}

  * {{ margin:0; padding:0; box-sizing:border-box; }}

  body {{
    font-family: 'Syne', sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    line-height: 1.6;
  }}

  /* SCANLINE EFFECT */
  body::before {{
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,0,0,0.04) 2px,
      rgba(0,0,0,0.04) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }}

  .header {{
    background: linear-gradient(135deg, #0c0e14 0%, #13101f 100%);
    border-bottom: 1px solid var(--border);
    padding: 48px 60px 40px;
    position: relative;
    overflow: hidden;
  }}

  .header::after {{
    content: 'AUDIT';
    position: absolute;
    right: -20px;
    top: 50%;
    transform: translateY(-50%);
    font-size: 180px;
    font-weight: 800;
    color: rgba(124,106,247,0.04);
    pointer-events: none;
    user-select: none;
    letter-spacing: -10px;
  }}

  .header-top {{
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 24px;
    flex-wrap: wrap;
  }}

  .logo {{
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
  }}

  .logo-icon {{
    width: 38px; height: 38px;
    background: var(--accent);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 12px;
    font-family: 'Space Mono', monospace;
    font-weight: 700;
    color: #fff;
    letter-spacing: -0.5px;
  }}

  .logo-text {{
    font-size: 0.75em;
    font-family: 'Space Mono', monospace;
    color: var(--accent);
    letter-spacing: 3px;
    text-transform: uppercase;
  }}

  h1 {{
    font-size: 2.2em;
    font-weight: 800;
    letter-spacing: -1px;
    line-height: 1.1;
    margin-bottom: 8px;
  }}

  .meta {{
    font-family: 'Space Mono', monospace;
    font-size: 0.78em;
    color: var(--muted);
    margin-top: 8px;
  }}

  .score-block {{
    text-align: center;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 20px 36px;
    min-width: 160px;
  }}

  .score-label {{
    font-size: 0.72em;
    font-family: 'Space Mono', monospace;
    color: var(--muted);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 4px;
  }}

  .score-num {{
    font-size: 3.5em;
    font-weight: 800;
    color: {sc};
    line-height: 1;
    letter-spacing: -3px;
  }}

  .score-grade {{
    font-size: 0.9em;
    color: {sc};
    margin-top: 4px;
    font-family: 'Space Mono', monospace;
  }}

  /* SUMMARY CARDS */
  .summary {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    padding: 32px 60px;
    border-bottom: 1px solid var(--border);
  }}

  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
  }}

  .card-label {{
    font-size: 0.72em;
    font-family: 'Space Mono', monospace;
    color: var(--muted);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 8px;
  }}

  .card-value {{
    font-size: 2em;
    font-weight: 800;
    line-height: 1;
  }}

  .card-sub {{
    font-size: 0.8em;
    color: var(--muted);
    margin-top: 4px;
  }}

  /* SECTIONS */
  .sections {{ padding: 40px 60px; }}

  .section {{
    margin-bottom: 48px;
  }}

  .section-header {{
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 20px;
    padding-bottom: 14px;
    border-bottom: 1px solid var(--border);
  }}

  .section-icon {{
    width: 32px; height: 32px;
    border-radius: 8px;
    background: var(--surface2);
    display: flex; align-items: center; justify-content: center;
    font-size: 11px;
    font-family: 'Space Mono', monospace;
    font-weight: 700;
    color: var(--accent);
    border: 1px solid var(--border);
  }}

  .section-title {{
    font-size: 1.1em;
    font-weight: 600;
    letter-spacing: -0.3px;
  }}

  .issue-count {{
    margin-left: auto;
    font-family: 'Space Mono', monospace;
    font-size: 0.78em;
    color: var(--muted);
  }}

  .issue-count span {{
    color: #ff4d4d;
    font-weight: 700;
  }}

  /* TABLE */
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.88em;
  }}

  th {{
    text-align: left;
    font-family: 'Space Mono', monospace;
    font-size: 0.75em;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--muted);
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
  }}

  td {{
    padding: 12px 14px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}

  tr:last-child td {{ border-bottom: none; }}

  tr:hover td {{ background: rgba(255,255,255,0.02); }}

  code {{
    font-family: 'Space Mono', monospace;
    font-size: 0.9em;
    background: rgba(255,255,255,0.05);
    padding: 2px 6px;
    border-radius: 4px;
    color: #b4c2ff;
  }}

  .badge {{
    display: inline-block;
    font-family: 'Space Mono', monospace;
    font-size: 0.72em;
    letter-spacing: 0.5px;
    padding: 3px 8px;
    border-radius: 4px;
    white-space: nowrap;
    font-weight: 700;
  }}

  /* FOOTER */
  .footer {{
    text-align: center;
    padding: 32px;
    border-top: 1px solid var(--border);
    font-family: 'Space Mono', monospace;
    font-size: 0.72em;
    color: var(--muted);
  }}

  @media (max-width: 600px) {{
    .header, .summary, .sections {{ padding-left: 20px; padding-right: 20px; }}
    h1 {{ font-size: 1.6em; }}
    .header::after {{ display: none; }}
  }}
</style>
</head>
<body>

<header class="header">
  <div class="header-top">
    <div>
      <div class="logo">
        <div class="logo-icon">LA</div>
        <div class="logo-text">Lets Audit v1.0</div>
      </div>
      <h1>Security Audit<br>Report</h1>
      <div class="meta">
        {hostname} &nbsp;|&nbsp; Windows &nbsp;|&nbsp; {now}
      </div>
    </div>
    <div class="score-block">
      <div class="score-label">Security Score</div>
      <div class="score-num">{score}</div>
      <div class="score-grade">Grade {grade}</div>
    </div>
  </div>
</header>

<div class="summary">
  <div class="card">
    <div class="card-label">Total Issues</div>
    <div class="card-value" style="color:{'#ff4d4d' if total_issues > 0 else '#00cc88'}">{total_issues}</div>
    <div class="card-sub">HIGH + MEDIUM severity</div>
  </div>
  <div class="card">
    <div class="card-label">Open Port Issues</div>
    <div class="card-value" style="color:{'#ff4d4d' if port_issues > 0 else '#00cc88'}">{port_issues}</div>
    <div class="card-sub">{len(ports)} ports scanned</div>
  </div>
  <div class="card">
    <div class="card-label">Password Issues</div>
    <div class="card-value" style="color:{'#ff4d4d' if password_issues > 0 else '#00cc88'}">{password_issues}</div>
    <div class="card-sub">{len(passwords)} policies checked</div>
  </div>
  <div class="card">
    <div class="card-label">Software Issues</div>
    <div class="card-value" style="color:{'#ff4d4d' if software_issues > 0 else '#00cc88'}">{software_issues}</div>
    <div class="card-sub">{len(software)} items checked</div>
  </div>
</div>

<main class="sections">

  <div class="section">
    <div class="section-header">
      <div class="section-icon">01</div>
      <div class="section-title">Open Ports</div>
      <div class="issue-count">
        <span>{port_issues}</span> issue{'s' if port_issues != 1 else ''} found
      </div>
    </div>
    {port_table}
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">02</div>
      <div class="section-title">Password Policy</div>
      <div class="issue-count">
        <span>{password_issues}</span> issue{'s' if password_issues != 1 else ''} found
      </div>
    </div>
    {password_table}
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">03</div>
      <div class="section-title">Software & System Health</div>
      <div class="issue-count">
        <span>{software_issues}</span> issue{'s' if software_issues != 1 else ''} found
      </div>
    </div>
    {software_table}
  </div>

</main>

<footer class="footer">
  Generated by Lets Audit — for educational and personal use only.<br>
  Always consult a professional for production systems.
</footer>

</body>
</html>"""
    return html


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    print("\n  Lets Audit — Windows Security Audit Tool")
    print("=" * 40)

    if not is_admin():
        print("[!] Warning: Not running as Administrator. Some checks may be incomplete.")
        print("    Right-click the script and choose 'Run as Administrator' for full results.\n")

    print("[ 1/3 ] Scanning open ports...")
    ports = scan_open_ports()
    print(f"        → Found {len(ports)} listening ports")

    print("[ 2/3 ] Checking password policies...")
    passwords = check_password_policy()
    print(f"        → Completed {len(passwords)} checks")

    print("[ 3/3 ] Checking software & system health...")
    software = check_outdated_software()
    print(f"        → Completed {len(software)} checks")

    print("\n[ OK ] Generating HTML report...")
    html = generate_html(ports, passwords, software)

    output_path = Path(os.path.expanduser("~")) / "Desktop" / f"lets_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  Report saved to:\n    {output_path}")
    print("\n  Open the file in your browser to view the full report.\n")

    # Try to auto-open
    try:
        os.startfile(str(output_path))
    except Exception:
        pass


if __name__ == "__main__":
    main()
