"""
CodeGuardian Core Analyzer
Main orchestration module for security analysis.
"""

import asyncio
import time
import os
from typing import Optional
from datetime import datetime

from .models import (
    AnalysisRequest, AnalysisResult, Vulnerability, Remediation,
    PolicyViolation, Severity, ScannerConfig, LLMConfig, ScannerType
)
from .utils import generate_request_id, merge_vulnerability_results, logger
from ..scanners.aggregator import ScannerAggregator
from ..policy.engine import PolicyEngine
from ..remediation.generator import RemediationGenerator


class CodeGuardianAnalyzer:
    """Main analyzer coordinating all security analysis components."""
    
    def __init__(
        self,
        llm_config: Optional[LLMConfig] = None,
        scanner_configs: Optional[list[ScannerConfig]] = None,
        policy_path: Optional[str] = None,
    ):
        self.llm_config = llm_config or LLMConfig()
        
        # Try to get API key from environment if not provided
        if not self.llm_config.api_key:
            self.llm_config.api_key = os.environ.get("ANTHROPIC_API_KEY")
        
        self.scanner_aggregator = ScannerAggregator(scanner_configs)
        self.policy_engine = PolicyEngine(policy_path)
        self.remediation_generator = RemediationGenerator(self.llm_config)
    
    async def analyze(self, request: AnalysisRequest) -> AnalysisResult:
        """Perform comprehensive security analysis."""
        start_time = time.perf_counter()
        request_id = generate_request_id()
        
        logger.info(f"Starting analysis {request_id} for {request.language} code")
        
        try:
            # Run scanners
            scanner_results = await self._run_scanners(request)
            vulnerabilities = merge_vulnerability_results(scanner_results)
            
            # Check policies
            policy_violations = await self._check_policies(request)
            
            # Generate remediations
            remediations = []
            if request.include_remediation and vulnerabilities:
                remediations = await self.remediation_generator.generate(
                    request.code, vulnerabilities
                )
            
            analysis_time_ms = (time.perf_counter() - start_time) * 1000
            summary = self._build_summary(vulnerabilities, policy_violations)
            
            result = AnalysisResult(
                request_id=request_id,
                vulnerabilities=vulnerabilities,
                policy_violations=policy_violations,
                remediations=remediations,
                summary=summary,
                analysis_time_ms=analysis_time_ms,
                analyzed_at=datetime.utcnow(),
            )
            
            logger.info(
                f"Analysis {request_id} complete: {len(vulnerabilities)} vulnerabilities, "
                f"{len(policy_violations)} policy violations in {analysis_time_ms:.2f}ms"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Analysis {request_id} failed: {e}")
            raise
    
    async def _run_scanners(self, request: AnalysisRequest) -> list[list[Vulnerability]]:
        """Run all security scanners."""
        return await self.scanner_aggregator.scan(
            code=request.code,
            language=request.language,
            file_path=request.file_path,
        )
    
    async def _check_policies(self, request: AnalysisRequest) -> list[PolicyViolation]:
        """Check code against policies."""
        if not request.policies:
            return []
        return await self.policy_engine.evaluate(
            code=request.code,
            language=request.language,
            policy_names=request.policies,
        )
    
    def _build_summary(self, vulnerabilities: list[Vulnerability], policy_violations: list[PolicyViolation]) -> dict:
        """Build analysis summary."""
        severity_counts = {s.value: 0 for s in Severity}
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] += 1
        
        return {
            "total_vulnerabilities": len(vulnerabilities),
            "total_policy_violations": len(policy_violations),
            "severity_breakdown": severity_counts,
            "has_critical": any(v.severity == Severity.CRITICAL for v in vulnerabilities),
            "has_high": any(v.severity == Severity.HIGH for v in vulnerabilities),
        }


class RealTimeAnalyzer:
    """Real-time analyzer with caching for IDE integration."""
    
    def __init__(self, base_analyzer: CodeGuardianAnalyzer):
        self.analyzer = base_analyzer
        self._cache: dict[str, AnalysisResult] = {}
    
    async def analyze_incremental(
        self, file_path: str, code: str, language: str
    ) -> AnalysisResult:
        """Perform incremental analysis with caching."""
        import hashlib
        cache_key = hashlib.md5(f"{file_path}:{code}".encode()).hexdigest()
        
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        from .models import Language
        request = AnalysisRequest(
            code=code,
            language=Language(language),
            file_path=file_path,
            include_remediation=True,
        )
        
        result = await self.analyzer.analyze(request)
        self._cache[cache_key] = result
        return result
    
    def clear_cache(self, file_path: Optional[str] = None):
        """Clear analysis cache."""
        if file_path:
            self._cache = {k: v for k, v in self._cache.items() if file_path not in k}
        else:
            self._cache.clear()
