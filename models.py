from pydantic import BaseModel
from typing import Optional


class Permission(BaseModel):
    name: str
    dangerous: bool
    score: int


class ExportedComponent(BaseModel):
    name: str
    component_type: str  # activity, service, receiver, provider
    has_permission: bool
    score: int


class SuspiciousString(BaseModel):
    value: str
    category: str  # url, base64, api_key, ip_address
    location: str
    score: int


class NativeLibrary(BaseModel):
    name: str
    architecture: str


class StaticAnalysisResult(BaseModel):
    apk_path: str
    package_name: str
    min_sdk: int
    target_sdk: str
    debuggable: bool
    allow_backup: bool
    permissions: list[Permission]
    exported_components: list[ExportedComponent]
    suspicious_strings: list[SuspiciousString]
    native_libraries: list[NativeLibrary]
    static_score: int
    findings_summary: list[str]


class DynamicFinding(BaseModel):
    timestamp: float
    category: str  # sms, contacts, camera, network, crypto, file
    method: str
    args: list[str]
    score: int


class DynamicAnalysisResult(BaseModel):
    package_name: str
    duration_seconds: float
    findings: list[DynamicFinding]
    dynamic_score: int
    findings_summary: list[str]


class SandboxReport(BaseModel):
    apk_path: str
    package_name: str
    static: StaticAnalysisResult
    dynamic: Optional[DynamicAnalysisResult] = None
    total_score: int
    verdict: str  # CLEAN, SUSPICIOUS, MALICIOUS
