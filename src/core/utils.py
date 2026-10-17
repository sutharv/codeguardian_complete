"""
CodeGuardian Utility Functions
Common utilities for code processing and logging.
"""

import re
import hashlib
import logging
import uuid
from pathlib import Path
from typing import Optional
from functools import lru_cache

from rich.console import Console
from rich.logging import RichHandler

console = Console()


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure application logging."""
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)]
    )
    return logging.getLogger("codeguardian")


logger = setup_logging()


def generate_vuln_id(content: str, location: str) -> str:
    """Generate unique vulnerability ID."""
    hash_input = f"{content}:{location}".encode()
    return f"VULN-{hashlib.sha256(hash_input).hexdigest()[:12].upper()}"


def generate_request_id() -> str:
    """Generate unique request ID."""
    return f"REQ-{uuid.uuid4().hex[:16].upper()}"


def extract_code_snippet(code: str, start_line: int, end_line: int, context_lines: int = 2) -> str:
    """Extract code snippet with context."""
    lines = code.splitlines()
    context_start = max(0, start_line - context_lines - 1)
    context_end = min(len(lines), end_line + context_lines)
    
    snippet_lines = []
    for i in range(context_start, context_end):
        line_num = i + 1
        marker = ">>>" if start_line <= line_num <= end_line else "   "
        snippet_lines.append(f"{marker} {line_num:4d} | {lines[i]}")
    
    return "\n".join(snippet_lines)


def detect_language(file_path: str) -> Optional[str]:
    """Detect language from file extension."""
    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
        ".go": "go", ".rs": "rust", ".cpp": "cpp", ".c": "c"
    }
    return ext_map.get(Path(file_path).suffix.lower())


def sanitize_code_for_llm(code: str, max_length: int = 10000) -> str:
    """Sanitize code for LLM processing."""
    code = code.replace("\x00", "")
    if len(code) > max_length:
        truncation_point = code.rfind("\n", 0, max_length)
        if truncation_point > max_length * 0.8:
            code = code[:truncation_point]
        else:
            code = code[:max_length]
        code += "\n... [truncated]"
    return code


def normalize_severity(severity_str: str) -> str:
    """Normalize severity strings."""
    mapping = {
        "critical": "critical", "crit": "critical",
        "high": "high", "h": "high",
        "medium": "medium", "med": "medium", "moderate": "medium",
        "low": "low", "l": "low",
        "info": "info", "informational": "info"
    }
    return mapping.get(severity_str.lower(), "medium")


@lru_cache(maxsize=100)
def get_cwe_info(cwe_id: str) -> dict:
    """Get CWE information."""
    cwe_db = {
        "CWE-89": {"name": "SQL Injection", "owasp": "A03:2021-Injection"},
        "CWE-79": {"name": "XSS", "owasp": "A03:2021-Injection"},
        "CWE-78": {"name": "Command Injection", "owasp": "A03:2021-Injection"},
        "CWE-22": {"name": "Path Traversal", "owasp": "A01:2021-Broken Access Control"},
        "CWE-798": {"name": "Hardcoded Credentials", "owasp": "A07:2021-Auth Failures"},
        "CWE-502": {"name": "Insecure Deserialization", "owasp": "A08:2021-Integrity Failures"},
        "CWE-287": {"name": "Improper Authentication", "owasp": "A07:2021-Auth Failures"},
        "CWE-918": {"name": "SSRF", "owasp": "A10:2021-SSRF"},
        "CWE-327": {"name": "Broken Crypto", "owasp": "A02:2021-Crypto Failures"},
    }
    return cwe_db.get(cwe_id.upper(), {"name": "Unknown", "owasp": None})


def merge_vulnerability_results(results: list[list], deduplicate: bool = True) -> list:
    """Merge and deduplicate vulnerability results."""
    all_vulns = []
    seen_keys = set()
    
    for result_list in results:
        for vuln in result_list:
            key = (vuln.location.file_path, vuln.location.start_line, vuln.category)
            if deduplicate and key in seen_keys:
                continue
            seen_keys.add(key)
            all_vulns.append(vuln)
    
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_vulns.sort(key=lambda v: (severity_order.get(v.severity, 5), v.location.start_line))
    return all_vulns
