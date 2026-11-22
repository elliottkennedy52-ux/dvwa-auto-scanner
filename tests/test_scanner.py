from unittest.mock import patch

import scanner


def test_check_tool_found_and_missing():
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        assert scanner.check_tool("nmap") is True

    with patch("shutil.which", return_value=None):
        assert scanner.check_tool("nonexistent_tool") is False


def test_run_command_writes_report_file(tmp_path):
    log_file = tmp_path / "test_report.txt"
    scanner.run_command(["python3", "-c", "print('scan ok')"], log_file)

    content = log_file.read_text(encoding="utf-8")
    assert "RUNNING: python3 -c print('scan ok')" in content
    assert "scan ok" in content
