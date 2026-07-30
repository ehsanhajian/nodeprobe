from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from nodeprobe.models import CheckKind, Confidence, Severity
from nodeprobe.rules.base import Rule, RuleMeta


class TlsCertificateRule(Rule):
    meta = RuleMeta(
        rule_id="EVM-TLS-001",
        title="TLS certificate validation",
        description="Validate TLS certificate hostname and expiration.",
        category="TLS Security",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.FINDING,
        impact="Invalid or expiring TLS weakens transport integrity for RPC clients.",
        remediation="Issue a valid certificate covering the RPC hostname and renew before expiry.",
        score_impact=20,
    )

    def run(self, client, context):
        url = client.target.original_url
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return [
                self.finding(
                    title="RPC endpoint not using HTTPS",
                    severity=Severity.MEDIUM,
                    score_impact=10,
                    evidence={"scheme": parsed.scheme},
                    description="Endpoint is not served over HTTPS.",
                )
            ]
        hostname = parsed.hostname
        port = parsed.port or 443
        if not hostname:
            return []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
        except ssl.SSLCertVerificationError as exc:
            return [
                self.finding(
                    evidence={"error": str(exc)},
                    description=f"TLS certificate verification failed: {exc}",
                )
            ]
        except OSError as exc:
            return [
                self.finding(
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LIKELY,
                    score_impact=10,
                    evidence={"error": str(exc)},
                    description=f"TLS probe failed: {exc}",
                )
            ]

        not_after = cert.get("notAfter")
        days_left = None
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = (expiry - datetime.now(timezone.utc)).days
            context["tls_days_left"] = days_left
            if days_left < 0:
                return [
                    self.finding(
                        evidence={"not_after": not_after, "days_left": days_left},
                        description="TLS certificate has expired.",
                    )
                ]
            if days_left <= 30:
                return [
                    self.finding(
                        title="TLS certificate expiring soon",
                        severity=Severity.MEDIUM,
                        score_impact=10,
                        evidence={"not_after": not_after, "days_left": days_left},
                        description=f"TLS certificate expires in {days_left} days.",
                    )
                ]
        return [
            self.finding(
                kind=CheckKind.EXPECTED_SURFACE,
                severity=Severity.INFO,
                score_impact=0,
                evidence={"not_after": not_after, "days_left": days_left},
                description="TLS certificate is valid for this hostname.",
            )
        ]


class CorsCredentialsRule(Rule):
    meta = RuleMeta(
        rule_id="EVM-HTTP-002",
        title="Dangerous CORS with credentials",
        description="Detect Access-Control-Allow-Origin: * combined with credentials.",
        category="HTTP Security",
        severity=Severity.HIGH,
        confidence=Confidence.LIKELY,
        kind=CheckKind.FINDING,
        impact="Credentialed CORS misconfiguration can enable browser-based abuse.",
        remediation="Avoid ACAO=* with Access-Control-Allow-Credentials: true.",
        score_impact=20,
    )

    def run(self, client, context):
        # Probe with Origin header via a dedicated request
        origin = "https://evil.example"
        # Use underlying client with Origin for one OPTIONS/POST
        from nodeprobe import killswitch

        killswitch.check()
        if client.requests_made >= client.limits.max_requests:
            return []
        started = __import__("time").monotonic()
        response = client._client.request(
            "POST",
            client.target.original_url,
            headers={"Origin": origin, "Content-Type": "application/json"},
            json={
                "jsonrpc": "2.0",
                "id": 999001,
                "method": "eth_chainId",
                "params": [],
            },
        )
        client._record(response, started)
        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "").lower()
        context["cors"] = {"acao": acao, "acac": acac}
        if acao == "*" and acac == "true":
            return [
                self.finding(
                    evidence={"acao": acao, "acac": acac},
                    description="CORS allows any origin with credentials enabled.",
                )
            ]
        if acao == origin and acac == "true":
            return [
                self.finding(
                    severity=Severity.MEDIUM,
                    score_impact=12,
                    evidence={"acao": acao, "acac": acac},
                    description="Endpoint reflects arbitrary Origin with credentials.",
                )
            ]
        return []
