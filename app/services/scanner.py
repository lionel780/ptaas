"""Moteur de scan : checks HTTP/TLS intégrés + outils externes
(nmap, sqlmap, nikto, zap-baseline) quand installés.
Ne tourne que sur des cibles vérifiées par scope_service.
"""
import asyncio
import re
import shutil
import ssl
import socket
from typing import Dict, Any, List
from urllib.parse import urlparse, urlencode

import httpx

SECURITY_HEADERS = {
    "strict-transport-security": "high",
    "content-security-policy": "medium",
    "x-frame-options": "medium",
    "x-content-type-options": "low",
    "referrer-policy": "low",
    "permissions-policy": "low",
}
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/backup.sql", "/config.php",
    "/phpinfo.php", "/server-status", "/.well-known/security.txt",
    "/admin", "/wp-admin", "/.htpasswd", "/composer.json", "/package.json",
]
DANGEROUS_METHODS = {"TRACE", "PUT", "DELETE", "CONNECT"}
SQL_ERRORS = ["sql syntax", "mysql_fetch", "ora-", "pg_query",
              "sqlite3::", "unclosed quotation", "odbc driver"]
XSS_MARKER = "ptaasxss9"


async def _check_headers(client: httpx.AsyncClient, base: str) -> List[Dict[str, Any]]:
    findings = []
    r = await client.get(base)
    hdrs = {k.lower(): v for k, v in r.headers.items()}
    for h, sev in SECURITY_HEADERS.items():
        if h not in hdrs:
            findings.append({
                "type": "missing_header", "severity": sev,
                "title": f"En-tête de sécurité manquant : {h}",
                "detail": "Recommandé contre XSS, clickjacking, MITM.",
                "cwe": "CWE-693", "compliance": ["NIS2", "ISO27001:A.8"],
            })
    server = hdrs.get("server") or r.headers.get("Server", "")
    if server:
        findings.append({
            "type": "info_disclosure", "severity": "low",
            "title": "Version du serveur exposée",
            "detail": f"{server} — masquez-la pour limiter l'énumération.",
            "cwe": "CWE-200", "compliance": ["ISO27001:A.8"],
        })
    return findings


async def _check_methods(client: httpx.AsyncClient, base: str) -> List[Dict[str, Any]]:
    try:
        r = await client.request("OPTIONS", base)
        allow = r.headers.get("Allow", "") + r.headers.get("Public", "")
        bad = [m for m in DANGEROUS_METHODS if m in allow.upper()]
        if bad:
            return [{
                "type": "dangerous_methods", "severity": "medium",
                "title": f"Méthodes HTTP à risque activées : {', '.join(bad)}",
                "detail": "TRACE permet le cross-site tracing ; PUT/DELETE exposés sont à restreindre.",
                "cwe": "CWE-749", "compliance": ["NIS2", "ISO27001:A.8"],
            }]
    except Exception:
        pass
    return []


async def _check_paths(client: httpx.AsyncClient, base: str) -> List[Dict[str, Any]]:
    async def probe(p):
        try:
            r = await client.get(base.rstrip("/") + p)
            if r.status_code == 200 and len(r.content) > 20:
                return {
                    "type": "sensitive_path", "severity": "high",
                    "title": f"Chemin sensible exposé : {p}",
                    "detail": f"HTTP 200, {len(r.content)} octets accessibles sans auth.",
                    "cwe": "CWE-548", "compliance": ["NIS2", "ISO27001:A.8"],
                }
        except Exception:
            return None
        return None
    results = await asyncio.gather(*[probe(p) for p in SENSITIVE_PATHS])
    return [f for f in results if f]


async def _check_tls(base: str) -> List[Dict[str, Any]]:
    parsed = urlparse(base)
    if parsed.scheme != "https":
        return [{
            "type": "no_tls", "severity": "high",
            "title": "Trafic en clair (HTTP)",
            "detail": "Pas de TLS : interception possible.",
            "cwe": "CWE-319", "compliance": ["NIS2", "ISO27001:A.8"],
        }]
    host, port = parsed.netloc.split(":")[0], int(parsed.port or 443)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                if s.version() in ("TLSv1", "TLSv1.1"):
                    return [{
                        "type": "weak_tls", "severity": "high",
                        "title": f"TLS obsolète : {s.version()}",
                        "detail": "TLS < 1.2 vulnérable (POODLE, BEAST).",
                        "cwe": "CWE-326", "compliance": ["NIS2", "ISO27001:A.8"],
                    }]
    except Exception as e:
        return [{"type": "tls_error", "severity": "medium",
                 "title": "Échec de négociation TLS", "detail": str(e),
                 "cwe": "CWE-326", "compliance": ["NIS2"]}]
    return []


async def _check_xss(client: httpx.AsyncClient, base: str) -> List[Dict[str, Any]]:
    url = base + ("&" if "?" in base else "?") + urlencode({"q": f"<{XSS_MARKER}>"})
    try:
        r = await client.get(url)
        if XSS_MARKER in r.text:
            return [{
                "type": "xss_reflected", "severity": "high",
                "title": "XSS réfléchi possible (paramètre q)",
                "detail": "Le marqueur injecté est renvoyé non échappé.",
                "cwe": "CWE-79", "compliance": ["NIS2", "ISO27001:A.8"],
            }]
    except Exception:
        pass
    return []


async def _check_sqli_errors(client: httpx.AsyncClient, base: str) -> List[Dict[str, Any]]:
    url = base + ("&" if "?" in base else "?") + urlencode({"id": "'"})
    try:
        r = await client.get(url)
        body = r.text.lower()
        for pat in SQL_ERRORS:
            if pat in body:
                return [{
                    "type": "sqli_error", "severity": "critical",
                    "title": f"Erreur SQL exposée (pattern «{pat}»)",
                    "detail": "Injection SQL probable — sqlmap confirmera en mode exploit.",
                    "cwe": "CWE-89", "compliance": ["NIS2", "ISO27001:A.8"],
                }]
    except Exception:
        pass
    return []


def _tool(cmd: List[str], name: str, timeout: int = 900) -> Dict[str, Any]:
    import subprocess
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"tool": name, "output": (proc.stdout + proc.stderr)[:50000]}
    except FileNotFoundError:
        return {"tool": name, "skipped": "non installé"}
    except subprocess.TimeoutExpired:
        return {"tool": name, "skipped": f"timeout {timeout}s"}


def _parse_findings(tool: str, output: str) -> List[Dict[str, Any]]:
    findings = []
    if tool == "nmap":
        for line in output.splitlines():
            if "NOT VULNERABLE" in line:
                continue
            if "VULNERABLE" in line or re.search(r"\d+/tcp\s+open", line):
                sev = "high" if "VULNERABLE" in line else "info"
                findings.append({"type": "nmap", "severity": sev,
                                 "title": f"[nmap] {line.strip()[:200]}",
                                 "detail": "", "compliance": ["NIS2"]})
    elif tool == "sqlmap":
        if re.search(r"is vulnerable|injectable|sqlmap identified", output, re.I):
            findings.append({
                "type": "sqli_confirmed", "severity": "critical",
                "title": "Injection SQL confirmée et exploitée par sqlmap",
                "detail": output[:1000],
                "cwe": "CWE-89", "exploitability": "prouvée",
                "compliance": ["NIS2", "ISO27001:A.8"],
            })
    return findings


async def run_scan(target: str, deep: bool = False, exploit: bool = False) -> Dict[str, Any]:
    """Scan complet — target déjà vérifié par scope_service."""
    parsed = urlparse(target if "://" in target else "https://" + target)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}"
    findings: List[Dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=30.0, verify=False,
                                 follow_redirects=True) as client:
        results = await asyncio.gather(
            _check_headers(client, base), _check_methods(client, base),
            _check_paths(client, base), _check_xss(client, base),
            _check_sqli_errors(client, base), _check_tls(base),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
    tools = []
    if deep:
        host = parsed.netloc.split(":")[0]
        tasks = []
        if shutil.which("nmap"):
            tasks.append(asyncio.to_thread(
                _tool, ["nmap", "-sV", "--script", "vuln", "-T4", host],
                "nmap", 900))
        if shutil.which("nikto") or shutil.which("nikto.pl"):
            exe = shutil.which("nikto") or shutil.which("nikto.pl")
            tasks.append(asyncio.to_thread(
                _tool, [exe, "-h", base], "nikto", 1200))
        if exploit and (shutil.which("sqlmap") or shutil.which("sqlmap.py")):
            exe = shutil.which("sqlmap") or shutil.which("sqlmap.py")
            tasks.append(asyncio.to_thread(
                _tool, [exe, "-u", base, "--batch", "--level=2",
                        "--risk=2", "--forms"],
                "sqlmap", 1200))
        for cand in ("zap-baseline.py", "zap-baseline", "zap-baseline.bat"):
            exe = shutil.which(cand)
            if exe:
                tasks.append(asyncio.to_thread(
                    _tool, [exe, "-t", base, "-I"], "zap", 1200))
                break
        for res in await asyncio.gather(*tasks):
            tools.append(res)
            findings.extend(_parse_findings(res["tool"], res.get("output", "")))
    return {"target": target, "deep": deep, "exploit": exploit,
            "findings": findings, "total_findings": len(findings),
            "tools_used": [t["tool"] for t in tools]}
