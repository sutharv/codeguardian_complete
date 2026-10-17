"""
CodeGuardian Remediation Generator
Generates context-aware security fix suggestions.
"""

from typing import Optional

from ..core.models import Vulnerability, Remediation, VulnerabilityCategory, LLMConfig
from ..core.utils import sanitize_code_for_llm, get_cwe_info, logger


# Template-based fixes for common vulnerabilities
FIX_TEMPLATES = {
    VulnerabilityCategory.SQL_INJECTION: {
        "fix": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        "rationale": "Use parameterized queries to prevent SQL injection by separating code from data",
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
    },
    VulnerabilityCategory.COMMAND_INJECTION: {
        "fix": 'subprocess.run(["command", arg1, arg2], shell=False)',
        "rationale": "Use list arguments with shell=False to prevent command injection",
        "references": ["https://docs.python.org/3/library/subprocess.html#security-considerations"]
    },
    VulnerabilityCategory.XSS: {
        "fix": 'from markupsafe import escape; escaped = escape(user_input)',
        "rationale": "Always escape user input before rendering in HTML to prevent XSS",
        "references": ["https://owasp.org/www-community/attacks/xss/"]
    },
    VulnerabilityCategory.PATH_TRAVERSAL: {
        "fix": '''import os
safe_path = os.path.normpath(os.path.join(base_dir, filename))
if not safe_path.startswith(base_dir):
    raise ValueError("Invalid path")''',
        "rationale": "Validate and normalize file paths to prevent directory traversal",
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal"]
    },
    VulnerabilityCategory.HARDCODED_SECRETS: {
        "fix": 'import os; secret = os.environ.get("SECRET_KEY")',
        "rationale": "Store secrets in environment variables, not in source code",
        "references": ["https://12factor.net/config"]
    },
    VulnerabilityCategory.INSECURE_DESERIALIZATION: {
        "fix": '''import json
data = json.loads(user_input)  # Safe alternative
# For YAML: yaml.safe_load(user_input)''',
        "rationale": "Use safe serialization formats like JSON or yaml.safe_load()",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"]
    },
    VulnerabilityCategory.INSECURE_CRYPTO: {
        "fix": '''from hashlib import sha256
# For passwords, use bcrypt:
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())''',
        "rationale": "Use strong cryptographic algorithms (SHA-256+, bcrypt for passwords)",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"]
    },
    VulnerabilityCategory.SSRF: {
        "fix": '''from urllib.parse import urlparse
ALLOWED_HOSTS = ["api.trusted.com"]
parsed = urlparse(url)
if parsed.netloc not in ALLOWED_HOSTS:
    raise ValueError("Host not allowed")''',
        "rationale": "Validate and whitelist allowed URLs/domains for server-side requests",
        "references": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"]
    },
}


class RemediationGenerator:
    """Generates remediation suggestions for vulnerabilities."""
    
    def __init__(self, llm_config: Optional[LLMConfig] = None):
        self.llm_config = llm_config or LLMConfig()
        self._llm_client = None
        
        if self.llm_config.api_key:
            try:
                from anthropic import Anthropic
                self._llm_client = Anthropic(api_key=self.llm_config.api_key)
                logger.info("LLM client initialized for AI-powered remediation")
            except Exception as e:
                logger.warning(f"LLM client not available: {e}")
    
    async def generate(self, code: str, vulnerabilities: list[Vulnerability]) -> list[Remediation]:
        """Generate remediation suggestions."""
        remediations = []
        
        for vuln in vulnerabilities:
            try:
                if self._llm_client:
                    rem = await self._generate_llm_remediation(code, vuln)
                else:
                    rem = self._generate_template_remediation(vuln)
                
                if rem:
                    remediations.append(rem)
            except Exception as e:
                logger.error(f"Remediation generation failed for {vuln.id}: {e}")
                # Fall back to template
                rem = self._generate_template_remediation(vuln)
                if rem:
                    remediations.append(rem)
        
        return remediations
    
    def _generate_template_remediation(self, vuln: Vulnerability) -> Optional[Remediation]:
        """Generate remediation from templates."""
        template = FIX_TEMPLATES.get(vuln.category)
        
        if not template:
            return Remediation(
                vulnerability_id=vuln.id,
                suggested_fix="Review and fix this security issue manually",
                rationale=f"Address the {vuln.category.value} vulnerability",
                security_impact=f"Fixes {vuln.title}",
                confidence=0.5
            )
        
        cwe_info = get_cwe_info(vuln.cwe_id) if vuln.cwe_id else {}
        
        return Remediation(
            vulnerability_id=vuln.id,
            suggested_fix=template["fix"],
            rationale=template["rationale"],
            security_impact=f"Eliminates {vuln.category.value} vulnerability ({vuln.cwe_id or 'security risk'})",
            references=template.get("references", []),
            confidence=0.8
        )
    
    async def _generate_llm_remediation(self, code: str, vuln: Vulnerability) -> Remediation:
        """Generate LLM-powered remediation."""
        template = FIX_TEMPLATES.get(vuln.category, {})
        sanitized_code = sanitize_code_for_llm(vuln.location.code_snippet or code, max_length=2000)
        
        prompt = f"""Analyze this security vulnerability and provide a specific fix.

VULNERABILITY:
- Type: {vuln.category.value}
- Title: {vuln.title}
- Description: {vuln.description}
- Line: {vuln.location.start_line}

CODE:
```
{sanitized_code}
```

{f"Known fix pattern: {template.get('fix', '')}" if template else ""}

Provide your response in this format:
SUGGESTED_FIX:
[corrected code]

RATIONALE:
[why this fix works - 1-2 sentences]

SECURITY_IMPACT:
[what security improvement this provides - 1 sentence]"""

        try:
            response = self._llm_client.messages.create(
                model=self.llm_config.model,
                max_tokens=1024,
                temperature=self.llm_config.temperature,
                messages=[{"role": "user", "content": prompt}]
            )
            
            text = response.content[0].text
            return self._parse_llm_response(vuln, text, template)
            
        except Exception as e:
            logger.error(f"LLM remediation failed: {e}")
            return self._generate_template_remediation(vuln)
    
    def _parse_llm_response(self, vuln: Vulnerability, response: str, template: dict) -> Remediation:
        """Parse LLM response into Remediation."""
        sections = {"SUGGESTED_FIX": "", "RATIONALE": "", "SECURITY_IMPACT": ""}
        
        current_section = None
        current_content = []
        
        for line in response.split("\n"):
            stripped = line.strip()
            for section in sections:
                if stripped.startswith(section + ":"):
                    if current_section:
                        sections[current_section] = "\n".join(current_content).strip()
                    current_section = section
                    current_content = [stripped[len(section)+1:].strip()]
                    break
            else:
                if current_section:
                    current_content.append(line)
        
        if current_section:
            sections[current_section] = "\n".join(current_content).strip()
        
        return Remediation(
            vulnerability_id=vuln.id,
            suggested_fix=sections["SUGGESTED_FIX"] or template.get("fix", "Manual review required"),
            rationale=sections["RATIONALE"] or template.get("rationale", "Apply security best practices"),
            security_impact=sections["SECURITY_IMPACT"] or f"Addresses {vuln.category.value}",
            references=template.get("references", []),
            confidence=0.9 if sections["SUGGESTED_FIX"] else 0.7
        )
