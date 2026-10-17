"""
CodeGuardian Semgrep Scanner
Multi-language security analysis using Semgrep.
"""

import json
import tempfile
import asyncio
from pathlib import Path
from typing import Optional
from datetime import datetime

from .base import BaseScanner
from ..core.models import (
    Vulnerability, VulnerabilityCategory, Severity, Language,
    ScannerType, SourceLocation
)
from ..core.utils import generate_vuln_id, get_cwe_info, logger


LANG_EXTENSIONS = {
    Language.PYTHON: ".py",
    Language.JAVASCRIPT: ".js",
    Language.TYPESCRIPT: ".ts",
    Language.JAVA: ".java",
    Language.GO: ".go",
    Language.RUST: ".rs",
}

CATEGORY_PATTERNS = {
    "sql": VulnerabilityCategory.SQL_INJECTION,
    "sqli": VulnerabilityCategory.SQL_INJECTION,
    "xss": VulnerabilityCategory.XSS,
    "command": VulnerabilityCategory.COMMAND_INJECTION,
    "injection": VulnerabilityCategory.COMMAND_INJECTION,
    "path": VulnerabilityCategory.PATH_TRAVERSAL,
    "traversal": VulnerabilityCategory.PATH_TRAVERSAL,
    "secret": VulnerabilityCategory.HARDCODED_SECRETS,
    "password": VulnerabilityCategory.HARDCODED_SECRETS,
    "credential": VulnerabilityCategory.HARDCODED_SECRETS,
    "deserial": VulnerabilityCategory.INSECURE_DESERIALIZATION,
    "pickle": VulnerabilityCategory.INSECURE_DESERIALIZATION,
    "auth": VulnerabilityCategory.BROKEN_AUTH,
    "ssrf": VulnerabilityCategory.SSRF,
    "crypto": VulnerabilityCategory.INSECURE_CRYPTO,
}


class SemgrepScanner(BaseScanner):
    """Semgrep multi-language security scanner."""
    
    DEFAULT_RULESETS = ["p/security-audit", "p/owasp-top-ten"]
    
    @property
    def scanner_type(self) -> ScannerType:
        return ScannerType.SEMGREP
    
    @property
    def supported_languages(self) -> list[Language]:
        return [Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT,
                Language.JAVA, Language.GO, Language.RUST]
    
    async def initialize(self) -> bool:
        """Check if Semgrep is installed."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            self._initialized = proc.returncode == 0
            if self._initialized:
                logger.info("Semgrep scanner initialized successfully")
            else:
                logger.warning("Semgrep not available")
            return self._initialized
        except FileNotFoundError:
            logger.warning("Semgrep not installed - run: pip install semgrep")
            return False
    
    async def scan(self, code: str, language: Language, file_path: Optional[str] = None) -> list[Vulnerability]:
        """Scan code with Semgrep."""
        if not self.is_supported(language):
            return []
        
        if not self._initialized:
            await self.initialize()
            if not self._initialized:
                return []
        
        vulnerabilities = []
        
        try:
            ext = LANG_EXTENSIONS.get(language, ".txt")
            
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_file = Path(tmp_dir) / f"code{ext}"
                tmp_file.write_text(code)
                
                cmd = ["semgrep", "--json", "--no-git-ignore", "--quiet"]
                for ruleset in self.DEFAULT_RULESETS:
                    cmd.extend(["--config", ruleset])
                cmd.append(str(tmp_file))
                
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self.config.timeout_seconds
                )
                
                if stdout:
                    result = json.loads(stdout.decode())
                    vulnerabilities = self._parse_results(result, code, file_path or str(tmp_file))
                    
        except asyncio.TimeoutError:
            logger.error("Semgrep scan timed out")
        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}")
        
        return self.filter_by_severity(vulnerabilities)
    
    def _parse_results(self, result: dict, code: str, file_path: str) -> list[Vulnerability]:
        """Parse Semgrep JSON output."""
        vulnerabilities = []
        code_lines = code.splitlines()
        
        for finding in result.get("results", []):
            rule_id = finding.get("check_id", "unknown")
            extra = finding.get("extra", {})
            
            start = finding.get("start", {})
            end = finding.get("end", {})
            start_line = start.get("line", 1)
            end_line = end.get("line", start_line)
            
            snippet_start = max(0, start_line - 2)
            snippet_end = min(len(code_lines), end_line + 1)
            snippet = "\n".join(code_lines[snippet_start:snippet_end])
            
            category = self._get_category(rule_id)
            
            severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
            severity = severity_map.get(extra.get("severity", "WARNING"), "medium")
            
            cwe_ids = extra.get("metadata", {}).get("cwe", [])
            cwe_id = cwe_ids[0] if cwe_ids else None
            cwe_info = get_cwe_info(cwe_id) if cwe_id else {}
            
            owasp = extra.get("metadata", {}).get("owasp")
            if isinstance(owasp, list):
                owasp = owasp[0] if owasp else None
            
            vuln = Vulnerability(
                id=generate_vuln_id(rule_id, f"{file_path}:{start_line}"),
                category=category,
                severity=Severity(severity),
                title=rule_id.split(".")[-1].replace("-", " ").title(),
                description=extra.get("message", ""),
                location=SourceLocation(
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    code_snippet=snippet,
                ),
                cwe_id=cwe_id,
                owasp_category=owasp or cwe_info.get("owasp"),
                scanner=ScannerType.SEMGREP,
                confidence=0.8,
                detected_at=datetime.utcnow(),
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _get_category(self, rule_id: str) -> VulnerabilityCategory:
        """Determine category from rule ID."""
        rule_lower = rule_id.lower()
        for pattern, category in CATEGORY_PATTERNS.items():
            if pattern in rule_lower:
                return category
        return VulnerabilityCategory.OTHER
