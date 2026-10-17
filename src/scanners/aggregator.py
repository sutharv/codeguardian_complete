"""
CodeGuardian Scanner Aggregator
Coordinates multiple security scanners.
"""

import asyncio
from typing import Optional

from .base import BaseScanner
from .bandit_scanner import BanditScanner
from .semgrep_scanner import SemgrepScanner
from ..core.models import Vulnerability, Language, ScannerConfig, ScannerType
from ..core.utils import logger


class ScannerAggregator:
    """Aggregates results from multiple security scanners."""
    
    def __init__(self, configs: Optional[list[ScannerConfig]] = None):
        self.configs = configs or [
            ScannerConfig(scanner_type=ScannerType.BANDIT, enabled=True),
            ScannerConfig(scanner_type=ScannerType.SEMGREP, enabled=True),
        ]
        self.scanners: dict[str, BaseScanner] = {}
        self._init_scanners()
    
    def _init_scanners(self):
        """Initialize scanner instances."""
        scanner_classes = {
            ScannerType.BANDIT: BanditScanner,
            ScannerType.SEMGREP: SemgrepScanner,
        }
        
        for config in self.configs:
            if not config.enabled:
                continue
            scanner_class = scanner_classes.get(config.scanner_type)
            if scanner_class:
                self.scanners[config.scanner_type.value] = scanner_class(config)
                logger.info(f"Registered scanner: {config.scanner_type.value}")
    
    async def initialize_all(self) -> dict[str, bool]:
        """Initialize all scanners."""
        results = {}
        for name, scanner in self.scanners.items():
            try:
                results[name] = await scanner.initialize()
            except Exception as e:
                logger.error(f"Failed to initialize {name}: {e}")
                results[name] = False
        return results
    
    async def scan(
        self, code: str, language: Language, file_path: Optional[str] = None
    ) -> list[list[Vulnerability]]:
        """Run all applicable scanners."""
        applicable = [
            (name, scanner) for name, scanner in self.scanners.items()
            if scanner.is_supported(language)
        ]
        
        if not applicable:
            logger.warning(f"No scanners for {language}")
            return []
        
        logger.info(f"Running {len(applicable)} scanners: {[n for n, _ in applicable]}")
        
        tasks = [
            self._run_scanner(name, scanner, code, language, file_path)
            for name, scanner in applicable
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for (name, _), result in zip(applicable, results):
            if isinstance(result, Exception):
                logger.error(f"Scanner {name} failed: {result}")
            elif result:
                valid_results.append(result)
        
        return valid_results
    
    async def _run_scanner(
        self, name: str, scanner: BaseScanner, code: str,
        language: Language, file_path: Optional[str]
    ) -> list[Vulnerability]:
        """Run single scanner."""
        try:
            return await scanner.scan(code, language, file_path)
        except Exception as e:
            logger.error(f"Scanner {name} error: {e}")
            return []
    
    def get_available_scanners(self) -> list[str]:
        """Get available scanner names."""
        return list(self.scanners.keys())
    
    async def cleanup(self):
        """Clean up all scanners."""
        for name, scanner in self.scanners.items():
            try:
                await scanner.cleanup()
            except Exception as e:
                logger.error(f"Cleanup failed for {name}: {e}")
