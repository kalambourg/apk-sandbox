import argparse
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from analyzers.static_analyzer import StaticAnalyzer
from analyzers.dynamic_analyzer import DynamicAnalyzer
from report_generator import ReportGenerator
from models import SandboxReport

console = Console()


def compute_verdict(score: int) -> str:
    if score < 20:
        return "CLEAN"
    elif score < 50:
        return "SUSPICIOUS"
    else:
        return "MALICIOUS"


def verdict_color(verdict: str) -> str:
    return {"CLEAN": "green", "SUSPICIOUS": "yellow", "MALICIOUS": "red"}.get(verdict, "white")


def print_summary(report: SandboxReport) -> None:
    verdict = report.verdict
    color = verdict_color(verdict)
    score = report.total_score

    # Score panel
    score_bar_width = 40
    filled = int(score_bar_width * score / 100)
    bar = "#" * filled + "-" * (score_bar_width - filled)

    panel_content = (
        f"Package  : {report.package_name}\n"
        f"Score    : {score}/100  [{bar}]\n"
        f"Verdict  : {verdict}"
    )
    console.print(Panel(
        Text(panel_content, style=color),
        title="[bold]Analysis Result[/bold]",
        border_style=color,
        padding=(1, 2)
    ))

    # Findings table
    table = Table(title="Findings", show_header=True, header_style="bold cyan")
    table.add_column("Severity", style="bold", width=8)
    table.add_column("Description")

    severity_color = {"HIGH": "red", "MED": "yellow", "WARN": "yellow", "INFO": "cyan"}

    all_findings = report.static.findings_summary[:]
    if report.dynamic:
        all_findings += report.dynamic.findings_summary

    for finding in all_findings:
        severity = "INFO"
        for s in ["HIGH", "MED", "WARN"]:
            if f"[{s}]" in finding:
                severity = s
                break
        description = finding.split("] ", 1)[-1] if "]" in finding else finding
        scolor = severity_color.get(severity, "white")
        table.add_row(f"[{scolor}]{severity}[/{scolor}]", description)

    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="APK Sandbox — static + dynamic analysis pipeline"
    )
    parser.add_argument("apk", help="Path to the APK to analyze")
    parser.add_argument(
        "--dynamic", action="store_true",
        help="Enable dynamic analysis via Frida"
    )
    parser.add_argument(
        "--duration", type=int, default=60,
        help="Dynamic analysis duration in seconds (default: 60)"
    )
    parser.add_argument(
        "--output", default="reports",
        help="Output directory for reports"
    )
    args = parser.parse_args()

    apk_path = Path(args.apk)
    if not apk_path.exists():
        console.print(f"[red][!][/red] APK not found: {apk_path}")
        sys.exit(1)

    # Static analysis
    static = StaticAnalyzer(str(apk_path))
    static_result = static.analyze()

    # Dynamic analysis (optional)
    dynamic_result = None
    if args.dynamic:
        dynamic = DynamicAnalyzer(static_result.package_name)
        dynamic_result = dynamic.analyze(duration_seconds=args.duration)

    # Total score
    total = static_result.static_score
    if dynamic_result:
        total = min(total + dynamic_result.dynamic_score, 100)

    verdict = compute_verdict(total)

    report = SandboxReport(
        apk_path=str(apk_path),
        package_name=static_result.package_name,
        static=static_result,
        dynamic=dynamic_result,
        total_score=total,
        verdict=verdict
    )

    # Save JSON
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    json_path = output_dir / f"{static_result.package_name}.json"
    json_path.write_text(report.model_dump_json(indent=2))

    # Generate HTML report
    generator = ReportGenerator()
    html_path = generator.generate(report, args.output)

    # Print summary
    console.print()
    print_summary(report)
    console.print()
    console.print(f"[green][+][/green] JSON report : {json_path}")
    console.print(f"[green][+][/green] HTML report : {html_path}")


if __name__ == "__main__":
    main()