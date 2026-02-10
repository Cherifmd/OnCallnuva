#!/usr/bin/env python3
"""
============================================================
Security Scanner - No Third-Party Dependencies Required
============================================================
Scans the codebase for:
  1. Known vulnerable dependency versions
  2. SQL injection patterns
  3. Hardcoded secrets / credentials
  4. Insecure configuration patterns
  5. Path traversal vulnerabilities
  6. Command injection patterns

Usage:
    python security_scan.py [--path /path/to/project]

Returns exit code 0 if clean, 1 if vulnerabilities found.
============================================================
"""

import os
import re
import sys
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple
from dataclasses import dataclass, field
from datetime import datetime

# ======================== CONFIGURATION ========================

# Known vulnerable package versions (CVE database subset)
VULNERABLE_PACKAGES: Dict[str, List[Dict]] = {
    "fastapi": [
        {"below": "0.109.0", "cve": "CVE-2024-24762", "severity": "HIGH",
         "desc": "DoS via multipart form data"},
    ],
    "sqlalchemy": [
        {"below": "2.0.0", "cve": "CVE-2023-XXXXX", "severity": "MEDIUM",
         "desc": "Potential SQL injection in legacy query mode"},
    ],
    "grpcio": [
        {"below": "1.56.0", "cve": "CVE-2023-33953", "severity": "HIGH",
         "desc": "Denial of service via hpack table"},
    ],
    "uvicorn": [
        {"below": "0.25.0", "cve": "CVE-2023-XXXXX", "severity": "LOW",
         "desc": "HTTP request smuggling potential"},
    ],
    "redis": [
        {"below": "4.5.5", "cve": "CVE-2023-28858", "severity": "MEDIUM",
         "desc": "Async connection info leak"},
    ],
    "jinja2": [
        {"below": "3.1.3", "cve": "CVE-2024-22195", "severity": "MEDIUM",
         "desc": "XSS via xmlattr filter"},
    ],
    "aiohttp": [
        {"below": "3.9.2", "cve": "CVE-2024-23334", "severity": "HIGH",
         "desc": "Directory traversal vulnerability"},
    ],
}

# SQL Injection patterns to detect in Python code
SQL_INJECTION_PATTERNS = [
    # f-string SQL queries
    (r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE).*\{.*\}.*["\']',
     "F-string SQL query detected - use parameterized queries"),
    # String format SQL
    (r'(?:SELECT|INSERT|UPDATE|DELETE).*%s.*%\s*\(',
     "%-format SQL string detected - use parameterized queries"),
    # String concatenation SQL
    (r'(?:SELECT|INSERT|UPDATE|DELETE).*\+\s*(?:str\(|request\.|params\[)',
     "String concatenation in SQL - use parameterized queries"),
    # .format() SQL
    (r'(?:SELECT|INSERT|UPDATE|DELETE).*\.format\(',
     ".format() in SQL query detected - use parameterized queries"),
    # Raw SQL execution with user input
    (r'execute\(\s*f["\']',
     "Raw SQL execution with f-string - high risk SQL injection"),
    (r'text\(\s*f["\']',
     "SQLAlchemy text() with f-string - use bind parameters"),
]

# Secret/credential patterns
SECRET_PATTERNS = [
    (r'(?:password|passwd|pwd|secret|api_key|apikey|token|auth)\s*=\s*["\'][^"\']{8,}["\']',
     "Hardcoded credential/secret detected"),
    (r'(?:BEGIN\s+(?:RSA|DSA|EC)\s+PRIVATE\s+KEY)',
     "Private key found in source code"),
    (r'(?:AKIA|ASIA)[A-Z0-9]{16}',
     "Potential AWS access key detected"),
    (r'(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36,}',
     "GitHub token detected"),
]

# Insecure configuration patterns
INSECURE_PATTERNS = [
    (r'debug\s*=\s*True', "Debug mode enabled - disable in production"),
    (r'verify\s*=\s*False', "SSL verification disabled"),
    (r'insecure_channel\(', "gRPC insecure channel (expected for local dev)"),
    (r'allow_origins\s*=\s*\[?\s*["\']\*["\']', "CORS allows all origins"),
    (r'pickle\.loads?\(', "Pickle usage - potential code execution vulnerability"),
    (r'eval\s*\(', "eval() usage - potential code injection"),
    (r'exec\s*\(', "exec() usage - potential code injection"),
    (r'subprocess\.call\(.*shell\s*=\s*True', "Shell=True in subprocess - command injection risk"),
    (r'os\.system\s*\(', "os.system() usage - prefer subprocess with shell=False"),
]

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    (r'open\s*\(\s*(?:request\.|params\[|args\[)',
     "File open with user-controlled path - path traversal risk"),
    (r'os\.path\.join\s*\(.*(?:request\.|params\[)',
     "os.path.join with user input - validate path"),
    (r'\.\./|\.\.\\',
     "Relative path traversal pattern found"),
]


@dataclass
class Finding:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    file: str
    line: int
    message: str
    snippet: str = ""


@dataclass
class ScanReport:
    timestamp: str = ""
    project_path: str = ""
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity in ("LOW", "INFO"))


def parse_version(v: str) -> Tuple[int, ...]:
    """Parse a version string to a comparable tuple."""
    try:
        parts = re.findall(r'\d+', v)
        return tuple(int(p) for p in parts[:3])
    except (ValueError, IndexError):
        return (0, 0, 0)


def is_version_below(version: str, threshold: str) -> bool:
    """Check if version < threshold."""
    return parse_version(version) < parse_version(threshold)


def scan_requirements(project_path: str, report: ScanReport):
    """Scan requirements.txt files for vulnerable dependencies."""
    for req_file in Path(project_path).rglob("requirements.txt"):
        try:
            content = req_file.read_text(encoding="utf-8")
            for line_num, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Parse package==version or package>=version
                match = re.match(r'^([a-zA-Z0-9_-]+)(?:\[.*\])?\s*[=><~]+\s*([0-9.]+)', line)
                if match:
                    pkg_name = match.group(1).lower().replace("-", "").replace("_", "")
                    pkg_version = match.group(2)

                    # Check against known vulnerabilities
                    for vuln_key, vulns in VULNERABLE_PACKAGES.items():
                        if vuln_key.replace("-", "").replace("_", "") == pkg_name:
                            for vuln in vulns:
                                if is_version_below(pkg_version, vuln["below"]):
                                    report.findings.append(Finding(
                                        severity=vuln["severity"],
                                        category="VULNERABLE_DEPENDENCY",
                                        file=str(req_file.relative_to(project_path)),
                                        line=line_num,
                                        message=f"{vuln['cve']}: {vuln['desc']} "
                                                f"(package {match.group(1)}=={pkg_version}, "
                                                f"fix: upgrade to >={vuln['below']})",
                                        snippet=line,
                                    ))
        except Exception as e:
            print(f"  Warning: Could not scan {req_file}: {e}")


def scan_python_files(project_path: str, report: ScanReport):
    """Scan Python source files for security patterns."""
    for py_file in Path(project_path).rglob("*.py"):
        # Skip generated protobuf files and venvs
        rel = str(py_file.relative_to(project_path))
        if any(skip in rel for skip in ["generated/", "venv/", ".venv/", "__pycache__/", "security_scan.py"]):
            continue

        try:
            content = py_file.read_text(encoding="utf-8")
            lines = content.splitlines()
            report.files_scanned += 1

            for line_num, line in enumerate(lines, 1):
                # SQL Injection checks
                for pattern, msg in SQL_INJECTION_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        report.findings.append(Finding(
                            severity="HIGH",
                            category="SQL_INJECTION",
                            file=rel,
                            line=line_num,
                            message=msg,
                            snippet=line.strip()[:120],
                        ))

                # Secret/credential checks (skip .env files and config samples)
                if not rel.endswith((".env", ".env.example")):
                    for pattern, msg in SECRET_PATTERNS:
                        if re.search(pattern, line, re.IGNORECASE):
                            # Exclude obvious defaults and environment variable reads
                            if "os.getenv" not in line and "os.environ" not in line:
                                report.findings.append(Finding(
                                    severity="MEDIUM",
                                    category="HARDCODED_SECRET",
                                    file=rel,
                                    line=line_num,
                                    message=msg,
                                    snippet=line.strip()[:80] + "...[REDACTED]",
                                ))

                # Insecure configuration checks
                for pattern, msg in INSECURE_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        report.findings.append(Finding(
                            severity="LOW" if "expected" in msg.lower() else "MEDIUM",
                            category="INSECURE_CONFIG",
                            file=rel,
                            line=line_num,
                            message=msg,
                            snippet=line.strip()[:120],
                        ))

                # Path traversal checks
                for pattern, msg in PATH_TRAVERSAL_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        report.findings.append(Finding(
                            severity="HIGH",
                            category="PATH_TRAVERSAL",
                            file=rel,
                            line=line_num,
                            message=msg,
                            snippet=line.strip()[:120],
                        ))
        except Exception as e:
            print(f"  Warning: Could not scan {py_file}: {e}")


def scan_docker_files(project_path: str, report: ScanReport):
    """Scan Dockerfiles for security issues."""
    for df in Path(project_path).rglob("Dockerfile*"):
        try:
            content = df.read_text(encoding="utf-8")
            rel = str(df.relative_to(project_path))
            lines = content.splitlines()
            report.files_scanned += 1

            has_user = False
            for line_num, line in enumerate(lines, 1):
                # Check for USER directive
                if line.strip().startswith("USER"):
                    has_user = True

                # Running as root
                if re.search(r'USER\s+root', line):
                    report.findings.append(Finding(
                        severity="MEDIUM",
                        category="DOCKER_SECURITY",
                        file=rel,
                        line=line_num,
                        message="Container runs as root user",
                        snippet=line.strip(),
                    ))

                # Using latest tag
                if re.search(r'FROM\s+\S+:latest', line):
                    report.findings.append(Finding(
                        severity="LOW",
                        category="DOCKER_SECURITY",
                        file=rel,
                        line=line_num,
                        message="Using :latest tag - pin specific version for reproducibility",
                        snippet=line.strip(),
                    ))

            if not has_user:
                report.findings.append(Finding(
                    severity="MEDIUM",
                    category="DOCKER_SECURITY",
                    file=rel,
                    line=0,
                    message="No USER directive - container runs as root by default",
                ))
        except Exception as e:
            print(f"  Warning: Could not scan {df}: {e}")


def scan_yaml_files(project_path: str, report: ScanReport):
    """Scan YAML/compose files for exposed secrets."""
    for yml_file in Path(project_path).rglob("*.yml"):
        try:
            content = yml_file.read_text(encoding="utf-8")
            rel = str(yml_file.relative_to(project_path))
            lines = content.splitlines()
            report.files_scanned += 1

            for line_num, line in enumerate(lines, 1):
                # Check for hardcoded passwords in compose
                if re.search(r'(?:PASSWORD|SECRET|TOKEN)\s*[:=]\s*\S+', line, re.IGNORECASE):
                    if "${" not in line:  # Not using env vars
                        report.findings.append(Finding(
                            severity="MEDIUM",
                            category="HARDCODED_SECRET",
                            file=rel,
                            line=line_num,
                            message="Potential hardcoded secret in YAML config",
                            snippet=line.strip()[:60] + "...[REDACTED]",
                        ))
        except Exception as e:
            pass


def print_report(report: ScanReport):
    """Print a formatted security report."""
    print("\n" + "=" * 70)
    print("  SECURITY SCAN REPORT")
    print("=" * 70)
    print(f"  Timestamp : {report.timestamp}")
    print(f"  Project   : {report.project_path}")
    print(f"  Files     : {report.files_scanned} scanned")
    print(f"  Findings  : {len(report.findings)} total")
    print(f"    CRITICAL: {report.critical_count}")
    print(f"    HIGH    : {report.high_count}")
    print(f"    MEDIUM  : {report.medium_count}")
    print(f"    LOW/INFO: {report.low_count}")
    print("=" * 70)

    if not report.findings:
        print("\n  ✅ No security vulnerabilities found!\n")
        return

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(report.findings, key=lambda f: severity_order.get(f.severity, 5))

    current_category = None
    for f in sorted_findings:
        if f.category != current_category:
            current_category = f.category
            print(f"\n  [{current_category}]")
            print("  " + "-" * 50)

        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(f.severity, "⚪")
        print(f"  {icon} [{f.severity}] {f.file}:{f.line}")
        print(f"    → {f.message}")
        if f.snippet:
            print(f"    | {f.snippet}")
        print()

    print("=" * 70)
    if report.critical_count > 0 or report.high_count > 0:
        print("  ❌ SCAN FAILED - Critical/High vulnerabilities found!")
    else:
        print("  ⚠️  SCAN PASSED with warnings")
    print("=" * 70 + "\n")


def main():
    project_path = os.path.dirname(os.path.abspath(__file__))
    if len(sys.argv) > 1 and sys.argv[1] == "--path":
        project_path = sys.argv[2]

    report = ScanReport(
        timestamp=datetime.utcnow().isoformat(),
        project_path=project_path,
    )

    print(f"\n🔍 Starting security scan of: {project_path}\n")

    print("  [1/4] Scanning dependencies for known vulnerabilities...")
    scan_requirements(project_path, report)

    print("  [2/4] Scanning Python source code for injection patterns...")
    scan_python_files(project_path, report)

    print("  [3/4] Scanning Docker configuration...")
    scan_docker_files(project_path, report)

    print("  [4/4] Scanning YAML/config files...")
    scan_yaml_files(project_path, report)

    print_report(report)

    # Save JSON report
    report_path = os.path.join(project_path, "security_report.json")
    with open(report_path, "w") as f:
        json.dump({
            "timestamp": report.timestamp,
            "files_scanned": report.files_scanned,
            "summary": {
                "total": len(report.findings),
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count,
            },
            "findings": [
                {
                    "severity": fi.severity,
                    "category": fi.category,
                    "file": fi.file,
                    "line": fi.line,
                    "message": fi.message,
                }
                for fi in report.findings
            ],
        }, f, indent=2)
    print(f"  📄 JSON report saved to: {report_path}\n")

    # Exit code: 1 if critical/high found
    if report.critical_count > 0 or report.high_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
