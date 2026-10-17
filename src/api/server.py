"""
CodeGuardian API Server
FastAPI-based REST API for security analysis.
"""

import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ..core.analyzer import CodeGuardianAnalyzer, RealTimeAnalyzer
from ..core.models import (
    AnalysisRequest, AnalysisResult, Language, LLMConfig,
    ScannerConfig, ScannerType, Severity, Vulnerability,
    VulnerabilityCategory, SourceLocation
)
from ..core.utils import logger


# Global instances
analyzer: Optional[CodeGuardianAnalyzer] = None
realtime_analyzer: Optional[RealTimeAnalyzer] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    global analyzer, realtime_analyzer
    
    logger.info("Initializing CodeGuardian API...")
    
    llm_config = LLMConfig(
        provider=os.environ.get("LLM_PROVIDER", "anthropic"),
        model=os.environ.get("LLM_MODEL", "claude-sonnet-4-20250514"),
        api_key=os.environ.get("ANTHROPIC_API_KEY"),
    )
    
    scanner_configs = [
        ScannerConfig(scanner_type=ScannerType.BANDIT, enabled=True),
        ScannerConfig(scanner_type=ScannerType.SEMGREP, enabled=True),
    ]
    
    analyzer = CodeGuardianAnalyzer(
        llm_config=llm_config,
        scanner_configs=scanner_configs,
        policy_path=os.environ.get("POLICY_PATH", "./configs/policies/"),
    )
    
    realtime_analyzer = RealTimeAnalyzer(analyzer)
    
    # Initialize scanners
    await analyzer.scanner_aggregator.initialize_all()
    
    logger.info("CodeGuardian API initialized successfully")
    
    yield
    
    logger.info("Shutting down CodeGuardian API...")
    await analyzer.scanner_aggregator.cleanup()


# Create FastAPI app
app = FastAPI(
    title="CodeGuardian API",
    description="Policy-Aware Secure Coding Assistant with LLM Integration",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request Models
class AnalyzeRequest(BaseModel):
    code: str = Field(..., min_length=1, description="Source code to analyze")
    language: str = Field(..., description="Programming language")
    file_path: Optional[str] = None
    policies: list[str] = Field(default=["OWASP_TOP_10"])
    include_remediation: bool = True


class PolicyCheckRequest(BaseModel):
    code: str = Field(..., min_length=1)
    language: str = "python"
    policies: list[str] = Field(..., min_length=1)


class HealthResponse(BaseModel):
    status: str
    version: str
    scanners: dict[str, bool]


# API Endpoints
@app.get("/", tags=["Root"])
async def root():
    """API root - redirect to docs."""
    return {
        "message": "CodeGuardian API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Check API health and scanner status."""
    scanner_status = {}
    if analyzer:
        for name, scanner in analyzer.scanner_aggregator.scanners.items():
            scanner_status[name] = scanner._initialized
    
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        scanners=scanner_status,
    )


@app.post("/api/analyze", response_model=AnalysisResult, tags=["Analysis"])
async def analyze_code(request: AnalyzeRequest):
    """Analyze code for security vulnerabilities."""
    if not analyzer:
        raise HTTPException(status_code=503, detail="Analyzer not initialized")
    
    try:
        language = Language(request.language.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unsupported language: {request.language}")
    
    analysis_request = AnalysisRequest(
        code=request.code,
        language=language,
        file_path=request.file_path,
        policies=request.policies,
        include_remediation=request.include_remediation,
    )
    
    try:
        return await analyzer.analyze(analysis_request)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze/realtime", response_model=AnalysisResult, tags=["Analysis"])
async def analyze_realtime(request: AnalyzeRequest):
    """Real-time analysis for IDE integration (cached)."""
    if not realtime_analyzer:
        raise HTTPException(status_code=503, detail="Analyzer not initialized")
    
    try:
        return await realtime_analyzer.analyze_incremental(
            file_path=request.file_path or "<input>",
            code=request.code,
            language=request.language.lower(),
        )
    except Exception as e:
        logger.error(f"Real-time analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/policy/check", tags=["Policy"])
async def check_policy(request: PolicyCheckRequest):
    """Check code against security policies."""
    if not analyzer:
        raise HTTPException(status_code=503, detail="Analyzer not initialized")
    
    try:
        language = Language(request.language.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unsupported language: {request.language}")
    
    violations = await analyzer.policy_engine.evaluate(
        code=request.code,
        language=language,
        policy_names=request.policies,
    )
    
    return {
        "compliant": len(violations) == 0,
        "violation_count": len(violations),
        "violations": [
            {
                "rule_id": v.rule.id,
                "rule_name": v.rule.name,
                "severity": v.rule.severity.value,
                "message": v.message,
                "line": v.location.start_line,
            }
            for v in violations
        ],
    }


@app.get("/api/policy/list", tags=["Policy"])
async def list_policies():
    """List available security policies."""
    if not analyzer:
        raise HTTPException(status_code=503, detail="Analyzer not initialized")
    
    policies = {}
    for name in analyzer.policy_engine.get_available_policies():
        rules = analyzer.policy_engine.get_policy_rules(name)
        policies[name] = {
            "rule_count": len(rules),
            "rules": [
                {"id": r.id, "name": r.name, "severity": r.severity.value, "category": r.category.value}
                for r in rules
            ],
        }
    
    return {"policies": policies}


@app.get("/api/scanners", tags=["Scanners"])
async def list_scanners():
    """List available security scanners."""
    if not analyzer:
        raise HTTPException(status_code=503, detail="Analyzer not initialized")
    
    scanners = []
    for name, scanner in analyzer.scanner_aggregator.scanners.items():
        scanners.append({
            "name": name,
            "initialized": scanner._initialized,
            "languages": [lang.value for lang in scanner.supported_languages],
        })
    
    return {"scanners": scanners}


@app.post("/api/cache/clear", tags=["Admin"])
async def clear_cache(file_path: Optional[str] = None):
    """Clear analysis cache."""
    if realtime_analyzer:
        realtime_analyzer.clear_cache(file_path)
    return {"status": "cache cleared"}


# Run with: python -m uvicorn src.api.server:app --reload --port 8080
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.api.server:app",
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", 8080)),
        reload=True,
    )
