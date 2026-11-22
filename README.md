[![Python CI](https://github.com/elliottkennedy52-ux/dvwa-auto-scanner/actions/workflows/python-ci.yml/badge.svg)](https://github.com/elliottkennedy52-ux/dvwa-auto-scanner/actions/workflows/python-ci.yml)

# DVWA Automated Lab Security Scanner

A Python CLI wrapper that orchestrates `nmap`, `nikto`, and `sqlmap` for authorized local security testing and remediation validation against Damn Vulnerable Web Application (DVWA) lab environments.

## Prerequisites
- Python 3.9+
- `nmap`
- `nikto` (or containerized Nikto)
- `sqlmap`

## Usage

### Basic Reconnaissance (Nmap + Nikto)
```bash
python3 scanner.py -t 127.0.0.1 -p 4280
```

### Authenticated Assessment (Including SQLMap)
```bash
python3 scanner.py -t 127.0.0.1 -p 4280 -c "PHPSESSID=your_session_id; security=low" --sqlmap-path ~/tools/sqlmap/sqlmap.py
```

## Legal & Authorization Notice
This tool is built strictly for authorized local lab environments and educational security testing. Never run automated scanners against systems without explicit written permission.
