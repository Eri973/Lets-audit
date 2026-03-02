# Lets Audit

A Windows security audit tool that scans your system for common vulnerabilities and generates a clean, detailed HTML report.

Built as a student cybersecurity project — open source, transparent, and educational.

---

## What It Checks

| Category | Details |
|---|---|
| **Open Ports** | Scans all listening ports and flags risky ones (RDP, Telnet, SMB, FTP, etc.) |
| **Password Policy** | Minimum length, expiry, lockout threshold, guest account, passwordless users |
| **Software & System Health** | Windows Update age, Defender signature age, Firewall status, legacy/risky software |

---

## Sample Report

The tool generates a dark-themed HTML report with:
- A security score (0–100) and letter grade
- Summary cards showing issue counts per category
- Color-coded severity badges: `HIGH` / `MEDIUM` / `LOW` / `OK`
- Detailed notes and remediation hints for every finding

---

## Requirements

- Windows 10 or 11
- Python 3.8+

No third-party packages needed — uses Python standard library only.

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/lets-audit.git
cd lets-audit
```

---

## Usage

**Standard run:**
```bash
python lets_audit.py
```

**For full results, run as Administrator:**
1. Open Command Prompt as Administrator
2. Navigate to the folder
3. Run `python lets_audit.py`

The HTML report is automatically saved to your Desktop and opens in your browser.

---

## Severity Levels

| Level | Meaning |
|---|---|
| `HIGH` | Serious risk — fix immediately |
| `MEDIUM` | Should be addressed soon |
| `LOW` | Worth reviewing |
| `OK` | No issues found |

---

## Disclaimer

This tool is intended for **educational and personal use only**. Only run it on systems you own or have explicit permission to audit. The author is not responsible for any misuse.

---

## Contributing

Pull requests are welcome. Ideas for future checks:
- [ ] Have I Been Pwned API integration for leaked passwords
- [ ] Scheduled weekly scans via Windows Task Scheduler
- [ ] Email delivery of reports
- [ ] Standalone `.exe` via PyInstaller
- [ ] macOS / Linux support

---

## License

MIT License — see [LICENSE](LICENSE) for details.
