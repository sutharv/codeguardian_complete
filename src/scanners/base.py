"""
CodeGuardian Base Scanner Interface
Abstract base class for all security scanners.
"""

from abc import ABC, abstractmethod
from typing import Optional

from ..core.models import Vulnerability, Language, ScannerConfig, ScannerType, Severity


class BaseScanner(ABC):
    """Abstract base class for security scanners."""
    
    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or ScannerConfig(scanner_type=self.scanner_type)
        self._initialized = False
    
    @property
    @abstractmethod
    def scanner_type(self) -> ScannerType:
        """Return scanner type."""
        pass
    
    @property
    @abstractmethod
    def supported_languages(self) -> list[Language]:
        """Return supported languages."""
        pass
    
    @abstractmethod
    async def scan(self, code: str, language: Language, file_path: Optional[str] = None) -> list[Vulnerability]:
        """Scan code for vulnerabilities."""
        pass
    
    async def initialize(self) -> bool:
        """Initialize the scanner."""
        self._initialized = True
        return True
    
    async def cleanup(self):
        """Clean up resources."""
        self._initialized = False
    
    def is_supported(self, language: Language) -> bool:
        """Check if language is supported."""
        return language in self.supported_languages
    
    def filter_by_severity(self, vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
        """Filter by configured severity threshold."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        threshold = severity_order.get(self.config.severity_threshold.value, 3)
        return [v for v in vulnerabilities if severity_order.get(v.severity, 5) <= threshold]
