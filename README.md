# APK Sandbox

Static + dynamic Android APK analysis pipeline. Scores APKs on a 0–100 suspicion scale and generates HTML reports.

Built as a portfolio project to demonstrate Android reverse engineering and mobile security analysis skills.

---

## What it does

```
APK
 │
 ├── Static Analysis
 │     ├── Manifest parsing      — permissions, exported components, SDK info
 │     ├── String extraction     — IP addresses, hardcoded credentials, C2 indicators
 │     ├── Heuristics            — RAT permission combos, package name, obfuscation
 │     └── Suspicion score       — 0-100, capped per category
 │
 └── Dynamic Analysis (optional, requires rooted device + Frida)
       ├── Runtime tracing       — SMS, contacts, camera, network, crypto, clipboard
       └── Behavioral score      — added to static score
```

Output: JSON report + styled HTML report per APK.

---

## Usage

```bash
# Static only
uv run python sandbox.py samples/target.apk

# Static + dynamic (rooted device required)
uv run python sandbox.py samples/target.apk --dynamic --duration 60

# Custom output directory
uv run python sandbox.py samples/target.apk --output /tmp/reports
```

---

## Scoring model

Score is capped at 100. Each category has its own ceiling to prevent a single signal from dominating.

### Permissions — max 60

Permissions are grouped by capability. Each group scores once, regardless of how many individual permissions from that group are declared.

| Group | Score | Key permissions |
|---|---|---|
| sms | 15 | SEND_SMS, READ_SMS, RECEIVE_SMS |
| install_packages | 15 | REQUEST_INSTALL_PACKAGES |
| accessibility | 15 | BIND_ACCESSIBILITY_SERVICE |
| device_admin | 15 | BIND_DEVICE_ADMIN |
| phone | 12 | CALL_PHONE, READ_CALL_LOG |
| microphone | 10 | RECORD_AUDIO |
| contacts | 10 | READ_CONTACTS |
| system_alert | 10 | SYSTEM_ALERT_WINDOW |
| camera | 8 | CAMERA |
| location | 8 | ACCESS_FINE_LOCATION |
| boot_completed | 8 | RECEIVE_BOOT_COMPLETED |
| accounts | 8 | GET_ACCOUNTS |
| storage | 5 | READ/WRITE_EXTERNAL_STORAGE |
| biometric | 5 | USE_BIOMETRIC |

### RAT combo bonus — +15

If an app declares all six of: `sms + phone + camera + microphone + contacts + location` simultaneously, +15 points. Legitimate apps rarely need all six together. Stalkerware and RATs always do.

### Exported components — max 25

Components exported without a permission attribute are reachable by any app on the device.

| Type | Score |
|---|---|
| provider | 15 |
| service | 12 |
| receiver | 8 |
| activity | 5 |

### Strings — max 35

Extracted from smali bytecode, library packages excluded.

| Category | Score | Signal |
|---|---|---|
| hardcoded_password | 15 | `password=`, `pwd=` followed by value |
| api_key | 12 | `api_key=`, `apikey=` with value |
| ip_url | 10 | HTTP URL pointing to a raw IP address |
| ip_port | 10 | IP:port pattern |
| c2_platform | 5 | Telegram, Discord references |
| root_check | 5 | Explicit su/Magisk/RootBeer strings |
| base64_blob | 0 | Long base64 strings — displayed, not scored |

### Package name heuristics — max 20

- Suspicious TLD (`.ru`, `.xyz`, `.top`, `.tk`, `.pw`, `.cc`, `.su`, `.to`): +10
- Suspicious keyword (`spy`, `rat`, `hack`, `monitor`, `stalker`, `track`, `stealer`, `keylog`): +10

### Obfuscation — +10

Component name longer than 50 characters in the last segment. Random string generation is a common SpyNote/CypherRAT signature.

### Verdicts

| Score | Verdict |
|---|---|
| 0–19 | CLEAN |
| 20–49 | SUSPICIOUS |
| 50–100 | MALICIOUS |

---

## Case study 1 — AntennaPod 3.3.2 (legitimate app)

**Score: 33/100 — SUSPICIOUS**

```
[WARN] ADB backup enabled (allowBackup=true)
[HIGH] 1 dangerous permission(s) declared     — RECEIVE_BOOT_COMPLETED
[HIGH] 12 exported component(s) with no permission
[MED]  0 suspicious string(s) found
[INFO] 4 native library/libraries present     — libconscrypt_jni.so
```

**Analysis:** SUSPICIOUS is correct here. AntennaPod is a podcast player — `RECEIVE_BOOT_COMPLETED` makes sense (resume playback after reboot), and the exported components are standard media player services (PlaybackService, MediaButtonReceiver). The score reflects real risk surface without false positives. No RAT combo, no suspicious package name, no obfuscated component names.

The `allowBackup=true` is a legitimate finding — ADB backup extraction works without root on Android 9+ and could expose the podcast subscription list and app preferences.

---

## Case study 2 — SpyNote RAT (sample: app.everspy.ru)

**Score: 100/100 — MALICIOUS**

```
[WARN] ADB backup enabled (allowBackup=true)
[HIGH] 16 dangerous permission(s) declared
[HIGH] RAT-like permission combo detected (SMS+phone+camera+mic+contacts+location)
[HIGH] 2 exported component(s) with no permission
[HIGH] Suspicious TLD in package name: .ru
[HIGH] Suspicious keyword in package name: 'spy'
[HIGH] 2 component name(s) appear obfuscated (>50 chars)
```

**Permission breakdown:**

The app requests the full RAT toolkit in a single manifest:

```
READ_SMS / SEND_SMS          — intercept and send messages
READ_CALL_LOG / CALL_PHONE   — monitor and initiate calls
READ_CONTACTS                — exfiltrate contact list
CAMERA                       — remote camera activation
RECORD_AUDIO                 — microphone surveillance
ACCESS_FINE_LOCATION         — GPS tracking
SYSTEM_ALERT_WINDOW          — overlay attacks (credential phishing)
REQUEST_INSTALL_PACKAGES     — install additional payloads
RECEIVE_BOOT_COMPLETED       — persistence across reboots
```

No legitimate application requires all of these simultaneously. The combination triggers the RAT combo bonus.

**Obfuscation:**

The service and receiver component names are randomly generated strings exceeding 80 characters:

```
app.everspy.serbiajemissionsqdriveygeneratoraupperkonsfclassicsklensxeveryonenstayingoaddwratesgglenjdisplayedi32
```

This is a known SpyNote/CypherRAT evasion technique — random names make static signature detection harder and prevent easy identification via `adb shell dumpsys package`.

**Package name:**

`app.everspy.ru` — `.ru` TLD and the word `everspy` both score independently. Combined with the permission set, this is an unambiguous indicator.

**String analysis:**

106 strings matched suspicious patterns across the smali bytecode, including IP addresses, credential patterns, and C2 indicators. Library smali files (androidx, kotlin, com.google.android) are excluded from scanning to reduce false positives.

---

## Architecture

```
apk-sandbox/
├── sandbox.py                  — CLI entrypoint, orchestrates pipeline
├── models.py                   — Pydantic types (StaticAnalysisResult, SandboxReport...)
├── report_generator.py         — Jinja2 HTML report generation
├── analyzers/
│   ├── static_analyzer.py      — apktool decompilation, manifest parsing, string extraction
│   └── dynamic_analyzer.py     — Frida USB device instrumentation
├── frida-scripts/
│   └── tracer.js               — Runtime hooks (SMS, contacts, camera, network, crypto...)
└── templates/
    └── report.html             — Dark theme HTML report template
```

**Dependencies:** `frida`, `frida-tools`, `pydantic`, `jinja2`, `rich`  
**External tools:** `apktool` (decompilation), `adb` (device communication)

---

## What this detects that generic scanners miss

**MobSF** runs the same permission checks but scores them individually — three SMS permissions score three times. This pipeline groups by capability, which eliminates inflation on apps that simply declare multiple permissions for the same feature.

**Generic unpinners and SSL kill switches** don't need to understand the app — they bypass everything. This pipeline's static analysis identifies *why* an app is suspicious before any execution, which matters when you can't safely run the sample.

**The RAT combo heuristic** is not a signature — it's behavioral reasoning applied statically. SpyNote, Cerberus, Anubis, and most Android RATs need the same six permission groups. A single check catches the family without needing individual signatures.

---

## Setup

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync

# Run
uv run python sandbox.py samples/target.apk
```

For dynamic analysis: root the target device, push and start `frida-server`, then add `--dynamic`.

---

## Related projects

- [android-vault](https://github.com/kalambourg/android-vault) — Android Keystore, AES-256-GCM, BiometricPrompt, MASVS L1/L2
- [android-pinning-lab](https://github.com/kalambourg/android-pinning-lab) — Certificate pinning implementation + Frida bypass scripts