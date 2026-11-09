# Threat Model: SecureVault API Testbed

## Scope & Target Boundary
The primary target of vulnerability testing is the local, intentionally vulnerable/hardened test application (`app/`). No external, unauthorized, or production systems are targeted.

## Target Vulnerability Classes (CWEs)

| CWE ID | Vulnerability Class | Associated API Functionality | Primary Attack Vector |
| :--- | :--- | :--- | :--- |
| **CWE-918** | Server-Side Request Forgery (SSRF) | Resource Request APIs (sync, remote fetch) | Internal network port scanning, cloud metadata access |
| **CWE-434** | Unrestricted File Upload | File Upload APIs (upload, avatar, attachment) | Arbitrary script upload, executable MIME bypass |
| **CWE-22** | Path Traversal | Path Processing APIs (download, read, file) | Dot-dot-slash (`../`) directory breakout |
| **CWE-78** | OS Command Injection | System Configuration APIs (ping, backup, exec) | Shell metacharacter chaining (`|`, `;`, `&&`) |
| **CWE-89** | SQL Injection | Database Operation APIs (query, search, filter) | Raw string concatenation, tautology (`OR 1=1`) |
| **CWE-79** | Cross-Site Scripting (XSS) | Text Display APIs (comments, logs, profile) | Unsanitized script tag injection (`<script>`, `<img>`) |

## Environment Boundary
- Localhost execution only (`127.0.0.1`).
- File access isolated to `app/storage/uploads/` sandbox.
- Command execution restricted to non-destructive echo/ping simulations.

