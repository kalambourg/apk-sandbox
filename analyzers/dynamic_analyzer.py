import frida
import time
from pathlib import Path
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text
from models import DynamicFinding, DynamicAnalysisResult

console = Console()


class DynamicAnalyzer:

    def __init__(self, package_name: str, script_path: str = "frida-scripts/tracer.js"):
        self.package_name = package_name
        self.script_path = Path(script_path)
        self.findings: list[DynamicFinding] = []

    def analyze(self, duration_seconds: int = 60) -> DynamicAnalysisResult:
        console.rule("[bold cyan]Dynamic Analysis[/bold cyan]")
        console.print(f"[cyan][*][/cyan] Target: [bold]{self.package_name}[/bold]")
        console.print(f"[cyan][*][/cyan] Duration: {duration_seconds}s")

        script_content = self.script_path.read_text()
        start_time = time.time()

        device = frida.get_usb_device()
        pid = device.spawn([self.package_name])
        session = device.attach(pid)
        script = session.create_script(script_content)

        script.on("message", self._on_message)
        script.load()
        device.resume(pid)

        console.print(f"[green][+][/green] App spawned — interacting with the device now...")

        with Live(self._render_status(0, duration_seconds), refresh_per_second=4, console=console) as live:
            for elapsed in range(duration_seconds):
                time.sleep(1)
                live.update(self._render_status(elapsed + 1, duration_seconds))

        session.detach()
        total_elapsed = time.time() - start_time

        score = self._compute_score()
        findings_summary = self._generate_findings()

        console.print(
            f"[green][+][/green] Dynamic analysis complete — "
            f"[bold]{len(self.findings)}[/bold] finding(s) in {total_elapsed:.1f}s"
        )

        return DynamicAnalysisResult(
            package_name=self.package_name,
            duration_seconds=total_elapsed,
            findings=self.findings,
            dynamic_score=score,
            findings_summary=findings_summary
        )

    def _render_status(self, elapsed: int, total: int) -> Text:
        pct = elapsed / total
        bar_width = 30
        filled = int(bar_width * pct)
        bar = "[" + "#" * filled + "-" * (bar_width - filled) + "]"
        findings_count = len(self.findings)
        color = "green" if findings_count == 0 else "yellow" if findings_count < 5 else "red"
        return Text(
            f"Instrumentation active  {bar}  {elapsed}/{total}s  |  findings: {findings_count}",
            style=color
        )

    def _on_message(self, message: dict, data) -> None:
        if message.get("type") != "send":
            return

        payload = message.get("payload", {})
        if not isinstance(payload, dict):
            return

        finding = DynamicFinding(
            timestamp=time.time(),
            category=payload.get("category", "unknown"),
            method=payload.get("method", "unknown"),
            args=payload.get("args", []),
            score=self._score_for_category(payload.get("category", "unknown"))
        )
        self.findings.append(finding)

        color = "red" if finding.score >= 10 else "yellow" if finding.score >= 5 else "cyan"
        args_preview = ", ".join(finding.args[:2])
        console.print(
            f"  [{color}][{finding.category.upper()}][/{color}] "
            f"{finding.method}({args_preview})"
        )

    def _score_for_category(self, category: str) -> int:
        scores = {
            "sms": 15,
            "contacts": 10,
            "camera": 8,
            "network": 5,
            "crypto": 5,
            "file": 3,
            "clipboard": 8,
            "location": 8,
            "call": 12,
        }
        return scores.get(category, 3)

    def _compute_score(self) -> int:
        score = sum(f.score for f in self.findings)
        return min(score, 100)

    def _generate_findings(self) -> list[str]:
        findings = []
        categories: dict[str, int] = {}

        for f in self.findings:
            categories[f.category] = categories.get(f.category, 0) + 1

        category_labels = {
            "sms": "[HIGH] SMS access",
            "contacts": "[HIGH] Contacts access",
            "camera": "[MED]  Camera access",
            "network": "[MED]  Network calls",
            "crypto": "[INFO] Crypto operations",
            "file": "[INFO] File access",
            "clipboard": "[MED]  Clipboard access",
            "location": "[HIGH] Location access",
            "call": "[HIGH] Call log access",
        }

        for category, count in sorted(categories.items(), key=lambda x: -x[1]):
            label = category_labels.get(category, f"[INFO] {category}")
            findings.append(f"{label} — {count} call(s) detected")

        return findings