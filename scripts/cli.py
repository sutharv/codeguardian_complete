#!/usr/bin/env python3
"""
CodeGuardian CLI - Command-line interface for security analysis.
"""

import sys
import asyncio
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.analyzer import CodeGuardianAnalyzer
from src.core.models import AnalysisRequest, Language, LLMConfig

console = Console()


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """CodeGuardian - Policy-Aware Secure Coding Assistant"""
    pass


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--language", "-l", default=None, help="Programming language")
@click.option("--policy", "-p", multiple=True, default=["OWASP_TOP_10"])
def analyze(file_path, language, policy):
    """Analyze a file for security vulnerabilities."""
    path = Path(file_path)
    
    if not language:
        ext_map = {".py": "python", ".js": "javascript", ".ts": "typescript", ".java": "java", ".go": "go"}
        language = ext_map.get(path.suffix, "python")
    
    console.print(f"\n[bold blue]🔍 Analyzing:[/bold blue] {file_path}")
    console.print(f"[dim]Language: {language} | Policies: {', '.join(policy)}[/dim]\n")
    
    code = path.read_text()
    result = asyncio.run(_analyze(code, language, str(path), list(policy)))
    _display_results(result)


@cli.command()
@click.argument("code", required=False)
@click.option("--stdin", is_flag=True, help="Read from stdin")
@click.option("--language", "-l", default="python")
def quick(code, stdin, language):
    """Quick analysis of a code snippet."""
    if stdin:
        code = sys.stdin.read()
    elif not code:
        console.print("[yellow]Enter code (Ctrl+D when done):[/yellow]")
        code = sys.stdin.read()
    
    if not code.strip():
        console.print("[red]No code provided[/red]")
        return
    
    console.print("\n[bold blue]🔍 Quick Analysis[/bold blue]\n")
    result = asyncio.run(_analyze(code, language, "<stdin>", ["OWASP_TOP_10", "SECURE_CODING"]))
    _display_results(result)


@cli.command()
def policies():
    """List available security policies."""
    from src.policy.engine import PolicyEngine
    engine = PolicyEngine()
    
    console.print("\n[bold]Available Security Policies:[/bold]\n")
    
    for name in engine.get_available_policies():
        rules = engine.get_policy_rules(name)
        table = Table(title=f"[bold]{name}[/bold] ({len(rules)} rules)")
        table.add_column("ID", width=15)
        table.add_column("Name", width=35)
        table.add_column("Severity", width=10)
        
        for rule in rules[:8]:
            table.add_row(rule.id, rule.name, rule.severity.value)
        
        if len(rules) > 8:
            table.add_row("...", f"[dim]+{len(rules) - 8} more[/dim]", "")
        
        console.print(table)
        console.print()


@cli.command()
def server():
    """Start the CodeGuardian API server."""
    import uvicorn
    console.print("\n[bold green]🚀 Starting CodeGuardian API Server[/bold green]\n")
    uvicorn.run("src.api.server:app", host="127.0.0.1", port=8080, reload=True)


async def _analyze(code, language, file_path, policies):
    """Run analysis."""
    analyzer = CodeGuardianAnalyzer(llm_config=LLMConfig(api_key=None))
    await analyzer.scanner_aggregator.initialize_all()
    
    request = AnalysisRequest(
        code=code,
        language=Language(language),
        file_path=file_path,
        policies=policies,
        include_remediation=True,
    )
    return await analyzer.analyze(request)


def _display_results(result):
    """Display analysis results."""
    vulns = result.vulnerabilities
    violations = result.policy_violations
    
    if not vulns and not violations:
        console.print("[green]✅ No security issues found![/green]\n")
        return
    
    # Summary
    summary = result.summary
    console.print(Panel(
        f"[bold]Vulnerabilities:[/bold] {summary.get('total_vulnerabilities', 0)}\n"
        f"[bold]Policy Violations:[/bold] {summary.get('total_policy_violations', 0)}\n"
        f"[bold]Analysis Time:[/bold] {result.analysis_time_ms:.2f}ms",
        title="Analysis Summary",
        border_style="red" if summary.get("has_critical") else "yellow"
    ))
    
    # Vulnerabilities
    if vulns:
        table = Table(title="Security Vulnerabilities", show_lines=True)
        table.add_column("Severity", width=10)
        table.add_column("Type", width=20)
        table.add_column("Line", width=6)
        table.add_column("Description", width=50)
        
        colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "green"}
        
        for v in vulns:
            color = colors.get(v.severity, "white")
            table.add_row(
                f"[{color}]{v.severity.upper()}[/{color}]",
                v.category.value.replace("_", " ").title(),
                str(v.location.start_line),
                v.description[:60] + "..." if len(v.description) > 60 else v.description
            )
        
        console.print(table)
    
    # Remediations
    if result.remediations:
        console.print("\n[bold green]💡 Suggested Fixes:[/bold green]")
        for rem in result.remediations[:3]:
            console.print(Panel(
                f"[cyan]{rem.suggested_fix}[/cyan]\n\n[dim]{rem.rationale}[/dim]",
                title=f"Fix for {rem.vulnerability_id}",
                border_style="green"
            ))


if __name__ == "__main__":
    cli()
