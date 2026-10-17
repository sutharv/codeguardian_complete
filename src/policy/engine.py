"""
CodeGuardian Policy Engine
Evaluates code against security policies (OWASP, CWE, custom).
"""

import re
import json
from pathlib import Path
from typing import Optional

from ..core.models import (
    PolicyRule, PolicyViolation, VulnerabilityCategory,
    Severity, Language, SourceLocation
)
from ..core.utils import logger


class PolicyEngine:
    """Security policy evaluation engine."""
    
    def __init__(self, policy_path: Optional[str] = None):
        self.policy_path = Path(policy_path) if policy_path else None
        self.rules: dict[str, list[PolicyRule]] = {}
        self._load_builtin_policies()
        if self.policy_path and self.policy_path.exists():
            self._load_custom_policies()
    
    def _load_builtin_policies(self):
        """Load built-in security policies."""
        self.rules["OWASP_TOP_10"] = [
            PolicyRule(
                id="OWASP-A01-001", name="Hardcoded Admin Credentials",
                description="Hardcoded admin or root credentials detected",
                severity=Severity.CRITICAL, category=VulnerabilityCategory.BROKEN_AUTH,
                pattern=r'(?i)(admin|root|administrator)\s*[=:]\s*["\'][^"\']+["\']',
                tags=["owasp", "a01"]
            ),
            PolicyRule(
                id="OWASP-A02-001", name="Weak Cryptographic Algorithm",
                description="Use of weak cryptographic algorithms (MD5, SHA1, DES)",
                severity=Severity.HIGH, category=VulnerabilityCategory.INSECURE_CRYPTO,
                pattern=r'(?i)(md5|sha1|des|rc4)\s*\(',
                tags=["owasp", "a02"]
            ),
            PolicyRule(
                id="OWASP-A02-002", name="Hardcoded Secret Key",
                description="Secret key or password hardcoded in source code",
                severity=Severity.CRITICAL, category=VulnerabilityCategory.HARDCODED_SECRETS,
                pattern=r'(?i)(api_key|secret|password|token|key)\s*=\s*["\'][a-zA-Z0-9_\-]{8,}["\']',
                tags=["owasp", "a02"]
            ),
            PolicyRule(
                id="OWASP-A03-001", name="SQL Injection Risk",
                description="Potential SQL injection via string formatting",
                severity=Severity.CRITICAL, category=VulnerabilityCategory.SQL_INJECTION,
                pattern=r'(execute|query|cursor\.execute)\s*\(\s*f["\']|["\'].*%s.*%|\.format\(',
                tags=["owasp", "a03"]
            ),
            PolicyRule(
                id="OWASP-A03-002", name="Command Injection Risk",
                description="Potential OS command injection",
                severity=Severity.CRITICAL, category=VulnerabilityCategory.COMMAND_INJECTION,
                pattern=r'(os\.system|subprocess\.call|subprocess\.run|exec|eval)\s*\(',
                tags=["owasp", "a03"]
            ),
            PolicyRule(
                id="OWASP-A05-001", name="Debug Mode Enabled",
                description="Debug mode should be disabled in production",
                severity=Severity.HIGH, category=VulnerabilityCategory.OTHER,
                pattern=r'(?i)debug\s*=\s*(True|1|["\']true["\'])',
                tags=["owasp", "a05"]
            ),
            PolicyRule(
                id="OWASP-A08-001", name="Insecure Deserialization",
                description="Use of unsafe deserialization (pickle, yaml.load)",
                severity=Severity.CRITICAL, category=VulnerabilityCategory.INSECURE_DESERIALIZATION,
                pattern=r'(pickle\.loads?|yaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)|marshal\.loads?)\s*\(',
                tags=["owasp", "a08"]
            ),
            PolicyRule(
                id="OWASP-A10-001", name="SSRF Risk",
                description="User-controlled URL in server-side request",
                severity=Severity.HIGH, category=VulnerabilityCategory.SSRF,
                pattern=r'(requests\.(get|post|put)|urllib\.request\.urlopen)\s*\(\s*[a-zA-Z_]+',
                tags=["owasp", "a10"]
            ),
        ]
        
        self.rules["CWE_SANS_25"] = [
            PolicyRule(
                id="CWE-79", name="Cross-Site Scripting (XSS)",
                description="Potential XSS via unsafe HTML rendering",
                severity=Severity.HIGH, category=VulnerabilityCategory.XSS,
                pattern=r'(render_template_string|Markup\(|mark_safe\(|innerHTML)',
                tags=["cwe"]
            ),
            PolicyRule(
                id="CWE-89", name="SQL Injection",
                description="String concatenation in SQL query",
                severity=Severity.CRITICAL, category=VulnerabilityCategory.SQL_INJECTION,
                pattern=r'(SELECT|INSERT|UPDATE|DELETE).*\+\s*[a-zA-Z_]+',
                tags=["cwe"]
            ),
            PolicyRule(
                id="CWE-22", name="Path Traversal",
                description="User input in file path",
                severity=Severity.HIGH, category=VulnerabilityCategory.PATH_TRAVERSAL,
                pattern=r'open\s*\(\s*[a-zA-Z_]+\s*[\+,]',
                tags=["cwe"]
            ),
        ]
        
        self.rules["SECURE_CODING"] = [
            PolicyRule(
                id="SEC-001", name="Sensitive Data Logging",
                description="Logging potentially sensitive data",
                severity=Severity.MEDIUM, category=VulnerabilityCategory.OTHER,
                pattern=r'(log|print|console)\s*\(.*(?i)(password|secret|token|key|ssn)',
                tags=["security"]
            ),
            PolicyRule(
                id="SEC-002", name="Disabled SSL Verification",
                description="SSL certificate verification disabled",
                severity=Severity.HIGH, category=VulnerabilityCategory.OTHER,
                pattern=r'verify\s*=\s*False',
                tags=["security"]
            ),
            PolicyRule(
                id="SEC-003", name="Eval with Variable",
                description="eval() used with variable input",
                severity=Severity.CRITICAL, category=VulnerabilityCategory.COMMAND_INJECTION,
                pattern=r'eval\s*\(\s*[a-zA-Z_]+',
                tags=["security"]
            ),
        ]
        
        total_rules = sum(len(rules) for rules in self.rules.values())
        logger.info(f"Loaded {total_rules} policy rules")
    
    def _load_custom_policies(self):
        """Load custom policies from JSON files."""
        if not self.policy_path:
            return
        
        for policy_file in self.policy_path.glob("*.json"):
            try:
                with open(policy_file) as f:
                    data = json.load(f)
                    policy_name = policy_file.stem.upper()
                    self.rules[policy_name] = [
                        PolicyRule(
                            id=r.get("id", ""),
                            name=r.get("name", ""),
                            description=r.get("description", ""),
                            severity=Severity(r.get("severity", "medium")),
                            category=VulnerabilityCategory(r.get("category", "other")),
                            pattern=r.get("pattern"),
                            enabled=r.get("enabled", True),
                            tags=r.get("tags", [])
                        )
                        for r in data.get("rules", [])
                    ]
                    logger.info(f"Loaded custom policy: {policy_name}")
            except Exception as e:
                logger.error(f"Failed to load {policy_file}: {e}")
    
    async def evaluate(
        self, code: str, language: Language, policy_names: list[str]
    ) -> list[PolicyViolation]:
        """Evaluate code against policies."""
        violations = []
        code_lines = code.splitlines()
        
        for policy_name in policy_names:
            rules = self.rules.get(policy_name.upper(), [])
            
            for rule in rules:
                if not rule.enabled or not rule.pattern:
                    continue
                
                try:
                    for match in re.finditer(rule.pattern, code, re.MULTILINE | re.IGNORECASE):
                        line_num = code[:match.start()].count('\n') + 1
                        
                        start_idx = max(0, line_num - 2)
                        end_idx = min(len(code_lines), line_num + 1)
                        snippet = "\n".join(code_lines[start_idx:end_idx])
                        
                        violations.append(PolicyViolation(
                            rule=rule,
                            location=SourceLocation(
                                file_path="<input>",
                                start_line=line_num,
                                end_line=line_num,
                                code_snippet=snippet,
                            ),
                            message=f"{rule.name}: {rule.description}",
                            context=match.group(0)[:100],
                        ))
                except re.error as e:
                    logger.error(f"Invalid regex in {rule.id}: {e}")
        
        logger.info(f"Policy evaluation found {len(violations)} violations")
        return violations
    
    def get_available_policies(self) -> list[str]:
        """Get available policy names."""
        return list(self.rules.keys())
    
    def get_policy_rules(self, policy_name: str) -> list[PolicyRule]:
        """Get rules for a policy."""
        return self.rules.get(policy_name.upper(), [])
