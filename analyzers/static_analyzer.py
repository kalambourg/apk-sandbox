import subprocess
import re
from pathlib import Path
from xml.etree import ElementTree as ET
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from models import (
    Permission, ExportedComponent, SuspiciousString,
    NativeLibrary, StaticAnalysisResult
)

console = Console()

PERMISSION_GROUPS = {
    "sms": [
        "android.permission.SEND_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_CELL_BROADCASTS",
    ],
    "phone": [
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
    ],
    "location": [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
    ],
    "camera": ["android.permission.CAMERA"],
    "microphone": ["android.permission.RECORD_AUDIO"],
    "contacts": [
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
    ],
    "storage": [
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
    ],
    "system_alert": ["android.permission.SYSTEM_ALERT_WINDOW"],
    "boot_completed": ["android.permission.RECEIVE_BOOT_COMPLETED"],
    "install_packages": [
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.INSTALL_PACKAGES",
    ],
    "accessibility": ["android.permission.BIND_ACCESSIBILITY_SERVICE"],
    "device_admin": ["android.permission.BIND_DEVICE_ADMIN"],
    "biometric": [
        "android.permission.USE_BIOMETRIC",
        "android.permission.USE_FINGERPRINT",
    ],
    "accounts": [
        "android.permission.GET_ACCOUNTS",
        "android.permission.MANAGE_ACCOUNTS",
        "android.permission.AUTHENTICATE_ACCOUNTS",
    ],
}

PERMISSION_GROUP_SCORE = {
    "sms": 15,
    "phone": 12,
    "location": 8,
    "camera": 8,
    "microphone": 10,
    "contacts": 10,
    "storage": 5,
    "system_alert": 10,
    "boot_completed": 8,
    "install_packages": 15,
    "accessibility": 15,
    "device_admin": 15,
    "biometric": 5,
    "accounts": 8,
}

EXPORTED_COMPONENT_SCORES = {
    "activity": 5,
    "service": 12,
    "receiver": 8,
    "provider": 15,
}

_PERM_TO_GROUP: dict[str, str] = {}
for group, perms in PERMISSION_GROUPS.items():
    for perm in perms:
        _PERM_TO_GROUP[perm] = group

DANGEROUS_PERMISSIONS_DISPLAY: dict[str, int] = {
    perm: PERMISSION_GROUP_SCORE.get(_PERM_TO_GROUP.get(perm, ""), 0)
    for group, perms in PERMISSION_GROUPS.items()
    for perm in perms
}

SUSPICIOUS_PATTERNS: list[tuple[str, str, int]] = [
    (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'ip_url', 10),
    (r'(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']?\w{10,}', 'api_key', 12),
    (r'(password|passwd|pwd)\s*[=:]\s*["\']?\w{6,}', 'hardcoded_password', 15),
    (r'[A-Za-z0-9+/]{100,}={0,2}', 'base64_blob', 0),
    (r'(telegram|t\.me|discord\.gg)', 'c2_platform', 5),
    (r'\b(?:\d{1,3}\.){3}\d{1,3}:\d{4,5}\b', 'ip_port', 10),
    (r'(/system/(app|priv-app)/Superuser\.apk|/sbin/su\b|/system/(bin|xbin)/su\b|which su\b|magisk|com\.topjohnwu\.magisk|RootBeer|RootCheck|isDeviceRooted)', 'root_check', 5),
]

STRING_CATEGORY_SCORES: dict[str, int] = {
    "ip_url": 10,
    "api_key": 12,
    "hardcoded_password": 15,
    "base64_blob": 0,
    "c2_platform": 5,
    "ip_port": 10,
    "root_check": 5,
}

ANDROID_NS = "http://schemas.android.com/apk/res/android"

IGNORED_PACKAGE_PREFIXES = [
    "androidx.",
    "com.google.android.",
    "com.android.",
    "kotlin.",
    "java.",
    "javax.",
]


class StaticAnalyzer:

    def __init__(self, apk_path: str, work_dir: str = "/tmp/sandbox"):
        self.apk_path = Path(apk_path)
        self.work_dir = Path(work_dir)
        self.decompiled_dir = self.work_dir / self.apk_path.stem
        self.work_dir.mkdir(parents=True, exist_ok=True)

    def analyze(self) -> StaticAnalysisResult:
        console.rule("[bold cyan]Static Analysis[/bold cyan]")
        console.print(f"[cyan][*][/cyan] Target: [bold]{self.apk_path.name}[/bold]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            steps = [
                "Decompiling APK      ",
                "Parsing manifest     ",
                "Extracting strings   ",
                "Scanning native libs ",
            ]
            task = progress.add_task("Analyzing...", total=len(steps))

            progress.update(task, description=steps[0])
            self._decompile_apktool()
            progress.advance(task)

            progress.update(task, description=steps[1])
            manifest_data = self._parse_manifest()
            progress.advance(task)

            progress.update(task, description=steps[2])
            strings = self._extract_suspicious_strings()
            progress.advance(task)

            progress.update(task, description=steps[3])
            libs = self._extract_native_libs()
            progress.advance(task)

        score = self._compute_score(
            manifest_data["permissions"],
            manifest_data["components"],
            strings
        )
        findings = self._generate_findings(manifest_data, strings, libs)

        console.print(f"[green][+][/green] Static analysis complete — score: [bold]{score}/100[/bold]")
        return StaticAnalysisResult(
            apk_path=str(self.apk_path),
            package_name=manifest_data["package"],
            min_sdk=manifest_data["min_sdk"],
            target_sdk=manifest_data["target_sdk"],
            debuggable=manifest_data["debuggable"],
            allow_backup=manifest_data["allow_backup"],
            permissions=manifest_data["permissions"],
            exported_components=manifest_data["components"],
            suspicious_strings=strings,
            native_libraries=libs,
            static_score=score,
            findings_summary=findings
        )

    def _decompile_apktool(self) -> None:
        if self.decompiled_dir.exists():
            console.print(f"[yellow][*][/yellow] Decompiled directory already exists — skipping apktool")
            return
        result = subprocess.run(
            ["apktool", "d", str(self.apk_path), "-o", str(self.decompiled_dir), "-f"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            console.print(f"[red][!][/red] apktool failed")
            raise RuntimeError(f"apktool failed: {result.stderr}")

    def _parse_manifest(self) -> dict:
        manifest_path = self.decompiled_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            raise FileNotFoundError("AndroidManifest.xml not found")

        tree = ET.parse(manifest_path)
        root = tree.getroot()

        package = root.get("package", "unknown")
        min_sdk = 0
        target_sdk = "unknown"
        debuggable = False
        allow_backup = True

        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            min_sdk = int(uses_sdk.get(f"{{{ANDROID_NS}}}minSdkVersion", "0"))
            target_sdk = uses_sdk.get(f"{{{ANDROID_NS}}}targetSdkVersion", "unknown")

        # Fallback: read from apktool.yml if manifest doesn't have sdk info
        if min_sdk == 0 or target_sdk == "unknown":
            yml_path = self.decompiled_dir / "apktool.yml"
            if yml_path.exists():
                yml_content = yml_path.read_text()
                for line in yml_content.splitlines():
                    line = line.strip()
                    if "minSdkVersion:" in line and min_sdk == 0:
                        try:
                            min_sdk = int(line.split(":")[-1].strip().strip("'\""))
                        except ValueError:
                            pass
                    if "targetSdkVersion:" in line and target_sdk == "unknown":
                        try:
                            target_sdk = line.split(":")[-1].strip().strip("'\"")
                        except ValueError:
                            pass

        application = root.find("application")
        if application is not None:
            debuggable = application.get(f"{{{ANDROID_NS}}}debuggable", "false") == "true"
            allow_backup = application.get(f"{{{ANDROID_NS}}}allowBackup", "true") == "true"

        permissions = self._parse_permissions(root)
        components = self._parse_exported_components(root)

        return {
            "package": package,
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
            "debuggable": debuggable,
            "allow_backup": allow_backup,
            "permissions": permissions,
            "components": components,
        }

    def _parse_permissions(self, root: ET.Element) -> list[Permission]:
        permissions = []
        for elem in root.findall("uses-permission"):
            name = elem.get(f"{{{ANDROID_NS}}}name", "")
            if not name:
                continue
            display_score = DANGEROUS_PERMISSIONS_DISPLAY.get(name, 0)
            permissions.append(Permission(
                name=name,
                dangerous=display_score > 0,
                score=display_score
            ))
        return permissions

    def _parse_exported_components(self, root: ET.Element) -> list[ExportedComponent]:
        components = []
        app = root.find("application")
        if app is None:
            return components

        tags = {
            "activity": "activity",
            "service": "service",
            "receiver": "receiver",
            "provider": "provider"
        }

        for tag, comp_type in tags.items():
            for elem in app.findall(tag):
                exported = elem.get(f"{{{ANDROID_NS}}}exported", "false")
                if exported != "true":
                    continue
                name = elem.get(f"{{{ANDROID_NS}}}name", "unknown")
                if any(name.startswith(prefix) for prefix in IGNORED_PACKAGE_PREFIXES):
                    continue
                permission = elem.get(f"{{{ANDROID_NS}}}permission")
                has_permission = permission is not None
                base_score = EXPORTED_COMPONENT_SCORES.get(comp_type, 10)
                score = 0 if has_permission else base_score
                components.append(ExportedComponent(
                    name=name,
                    component_type=comp_type,
                    has_permission=has_permission,
                    score=score
                ))

        return components

    def _is_library_smali(self, smali_file: Path) -> bool:
        relative = str(smali_file.relative_to(self.decompiled_dir))
        for prefix in IGNORED_PACKAGE_PREFIXES:
            lib_path = "smali/" + prefix.replace(".", "/")
            if relative.startswith(lib_path):
                return True
        return False

    def _extract_suspicious_strings(self) -> list[SuspiciousString]:
        findings: list[SuspiciousString] = []

        smali_dir = self.decompiled_dir / "smali"
        if not smali_dir.exists():
            return findings

        for smali_file in smali_dir.rglob("*.smali"):
            if self._is_library_smali(smali_file):
                continue
            try:
                content = smali_file.read_text(errors="ignore")
                for pattern, category, score in SUSPICIOUS_PATTERNS:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        value = match.group(0)
                        if len(value) > 200:
                            value = value[:200] + "..."
                        findings.append(SuspiciousString(
                            value=value,
                            category=category,
                            location=str(smali_file.relative_to(self.decompiled_dir)),
                            score=score
                        ))
            except Exception:
                continue

        seen: set[str] = set()
        unique: list[SuspiciousString] = []
        for f in findings:
            if f.value not in seen:
                seen.add(f.value)
                unique.append(f)

        return unique

    def _extract_native_libs(self) -> list[NativeLibrary]:
        libs: list[NativeLibrary] = []
        lib_dir = self.decompiled_dir / "lib"
        if not lib_dir.exists():
            return libs

        for arch_dir in lib_dir.iterdir():
            if arch_dir.is_dir():
                for so_file in arch_dir.glob("*.so"):
                    libs.append(NativeLibrary(
                        name=so_file.name,
                        architecture=arch_dir.name
                    ))
        return libs

    def _compute_score(
        self,
        permissions: list[Permission],
        components: list[ExportedComponent],
        strings: list[SuspiciousString]
    ) -> int:
        found_groups: set[str] = set()
        for p in permissions:
            group = _PERM_TO_GROUP.get(p.name)
            if group:
                found_groups.add(group)
        permission_score = min(
            sum(PERMISSION_GROUP_SCORE.get(g, 0) for g in found_groups),
            40
        )

        component_types: set[str] = set()
        for c in components:
            if not c.has_permission:
                component_types.add(c.component_type)
        component_score = min(
            sum(EXPORTED_COMPONENT_SCORES.get(t, 10) for t in component_types),
            25
        )

        string_categories: set[str] = set()
        for s in strings:
            string_categories.add(s.category)
        string_score = min(
            sum(STRING_CATEGORY_SCORES.get(c, 0) for c in string_categories),
            35
        )

        return min(permission_score + component_score + string_score, 100)

    def _generate_findings(
        self,
        manifest_data: dict,
        strings: list[SuspiciousString],
        libs: list[NativeLibrary]
    ) -> list[str]:
        findings = []

        if manifest_data["debuggable"]:
            findings.append("[WARN] App is debuggable — should not be in production")
        if manifest_data["allow_backup"]:
            findings.append("[WARN] ADB backup enabled (allowBackup=true)")

        dangerous_perms = [p for p in manifest_data["permissions"] if p.dangerous]
        if dangerous_perms:
            findings.append(f"[HIGH] {len(dangerous_perms)} dangerous permission(s) declared")

        exported_no_perm = [c for c in manifest_data["components"] if not c.has_permission]
        if exported_no_perm:
            findings.append(f"[HIGH] {len(exported_no_perm)} exported component(s) with no permission")

        scored_strings = [s for s in strings if s.score > 0]
        if scored_strings:
            findings.append(f"[MED]  {len(scored_strings)} suspicious string(s) found")

        if libs:
            findings.append(f"[INFO] {len(libs)} native library/libraries present")

        return findings