"""
CodeGuardian Data Models
Defines all data structures used throughout the application.
"""

from enum import Enum
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(str, Enum):
    """Security vulnerability categories."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    HARDCODED_SECRETS = "hardcoded_secrets"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    BROKEN_AUTH = "broken_authentication"
    SSRF = "ssrf"
    INSECURE_CRYPTO = "insecure_cryptography"
    OTHER = "other"


class Language(str, Enum):
    """Supported programming languages."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    RUST = "rust"


class ScannerType(str, Enum):
    """Security scanner types."""
    BANDIT = "bandit"
    SEMGREP = "semgrep"
    CUSTOM = "custom"


class SourceLocation(BaseModel):
    """Location in source code."""
    file_path: str = Field(default="<input>")
    start_line: int = Field(default=1, ge=1)
    end_line: int = Field(default=1, ge=1)
    start_column: Optional[int] = None
    end_column: Optional[int] = None
    code_snippet: Optional[str] = None


class Vulnerability(BaseModel):
    """Detected security vulnerability."""
    id: str
    category: VulnerabilityCategory
    severity: Severity
    title: str
    description: str
    location: SourceLocation
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    scanner: ScannerType
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    false_positive_likelihood: Optional[float] = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)


class Remediation(BaseModel):
    """Fix suggestion for a vulnerability."""
    vulnerability_id: str
    suggested_fix: str
    rationale: str
    security_impact: str = ""
    alternative_fixes: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)


class PolicyRule(BaseModel):
    """Security policy rule."""
    id: str
    name: str
    description: str
    severity: Severity
    category: VulnerabilityCategory
    pattern: Optional[str] = None
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)


class PolicyViolation(BaseModel):
    """Policy compliance violation."""
    rule: PolicyRule
    location: SourceLocation
    message: str
    context: Optional[str] = None


class AnalysisRequest(BaseModel):
    """Request for code analysis."""
    code: str = Field(..., min_length=1)
    language: Language
    file_path: Optional[str] = None
    policies: list[str] = Field(default_factory=lambda: ["OWASP_TOP_10"])
    include_remediation: bool = True
    context: Optional[dict] = None


class AnalysisResult(BaseModel):
    """Result of code analysis."""
    request_id: str
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    policy_violations: list[PolicyViolation] = Field(default_factory=list)
    remediations: list[Remediation] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)
    analysis_time_ms: float
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)


class ScannerConfig(BaseModel):
    """Scanner configuration."""
    scanner_type: ScannerType
    enabled: bool = True
    severity_threshold: Severity = Severity.LOW
    timeout_seconds: int = 60
    extra_args: dict = Field(default_factory=dict)


class LLMConfig(BaseModel):
    """LLM configuration."""
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-20250514"
    temperature: float = 0.1
    max_tokens: int = 4096
    api_key: Optional[str] = None
