from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from models import SandboxReport


class ReportGenerator:

    def __init__(self, template_dir: str = "templates"):
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def generate(self, report: SandboxReport, output_dir: str = "reports") -> Path:
        template = self.env.get_template("report.html")
        html = template.render(report=report)

        output_path = Path(output_dir) / f"{report.package_name}.html"
        output_path.write_text(html)
        print(f"[+] Rapport HTML : {output_path}")
        return output_path
