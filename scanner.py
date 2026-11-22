#!/usr/bin/env python3
"""
Automated Local Lab Security Scanner
Wraps nmap, nikto, and sqlmap to perform reconnaissance and vulnerability checks
against authorized local targets (e.g., DVWA on localhost:4280).
"""

import argparse
import shutil
import subprocess
from datetime import datetime
from pathlib import Path


def check_tool(tool_name: str) -> bool:
    """Verify if a CLI security tool is installed and available in PATH."""
    return shutil.which(tool_name) is not None


def run_command(command: list[str], log_file: Path) -> None:
    """Execute a security tool via subprocess and stream output to a report file."""
    header = f"\n{'='*60}\nRUNNING: {' '.join(command)}\n{'='*60}\n"
    print(header.strip())

    with log_file.open("a", encoding="utf-8") as f:
        f.write(header)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            output = result.stdout or result.stderr or "[No output returned]"
            print(output[:600] + ("...\n[Truncated in console; full output saved]" if len(output) > 600 else ""))
            f.write(output + "\n")
        except subprocess.TimeoutExpired:
            msg = "[!] Command timed out after 300 seconds.\n"
            print(msg.strip())
            f.write(msg)
        except OSError as exc:
            msg = f"[!] Execution error: {exc}\n"
            print(msg.strip())
            f.write(msg)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automated Security Assessment Wrapper for Local Labs (DVWA)"
    )
    parser.add_argument(
        "-t", "--target", default="127.0.0.1", help="Target host/IP (default: 127.0.0.1)"
    )
    parser.add_argument(
        "-p", "--port", default="4280", help="Target web port (default: 4280)"
    )
    parser.add_argument(
        "-c", "--cookie", default="", help="Authenticated session cookie (e.g., 'PHPSESSID=xyz; security=low')"
    )
    parser.add_argument(
        "--sqlmap-path",
        default="sqlmap",
        help="Path to sqlmap executable or sqlmap.py script",
    )
    args = parser.parse_args()

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = reports_dir / f"scan_report_{timestamp}.txt"

    base_url = f"http://{args.target}:{args.port}"
    print(f"[*] Starting automated assessment against {base_url}")
    print(f"[*] Saving full report to: {report_file}")

    # 1. Port & Service Discovery (Nmap)
    if check_tool("nmap"):
        run_command(
            ["nmap", "-sV", "-p", args.port, args.target],
            report_file,
        )
    else:
        print("[-] Skipping nmap (not found in PATH).")

    # 2. Web Server Misconfiguration Scan (Nikto)
    if check_tool("nikto"):
        run_command(
            ["nikto", "-h", base_url, "-Tuning", "123b"],
            report_file,
        )
    else:
        print("[-] Skipping nikto (not found in PATH).")

    # 3. Authenticated SQL Injection Audit (SQLMap)
    if args.cookie:
        sqli_target = f"{base_url}/vulnerabilities/sqli/?id=1&Submit=Submit"
        if args.sqlmap_path.endswith(".py"):
            cmd = ["python3", args.sqlmap_path]
        elif check_tool(args.sqlmap_path):
            cmd = [args.sqlmap_path]
        else:
            cmd = []

        if cmd:
            cmd.extend([
                "-u", sqli_target,
                "--cookie", args.cookie,
                "--batch",
                "--dbs",
            ])
            run_command(cmd, report_file)
        else:
            print(f"[-] Skipping sqlmap ({args.sqlmap_path} not found).")
    else:
        print("[-] Skipping sqlmap (no --cookie provided).")

    print(f"\n[+] Scan complete. Full results saved to {report_file}")


if __name__ == "__main__":
    main()
