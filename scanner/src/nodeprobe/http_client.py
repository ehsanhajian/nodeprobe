"""Budgeted HTTP client for website surface scans."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from nodeprobe import killswitch
from nodeprobe.profiles import ProfileLimits
from nodeprobe.rpc import BudgetExceeded
from nodeprobe.safety import SafeTarget, UnsafeTargetError, validate_redirect_target


@dataclass
class HttpExchange:
    url: str
    method: str
    status_code: int
    headers: dict[str, str]
    body_text: str
    final_url: str
    redirect_chain: list[str] = field(default_factory=list)


class BudgetedHttpClient:
    def __init__(
        self,
        target: SafeTarget,
        limits: ProfileLimits,
        *,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
        max_redirects: int = 5,
    ):
        self.target = target
        self.limits = limits
        self.timeout = timeout
        self.max_redirects = max_redirects
        self._client = client or httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            headers={
                "User-Agent": "Nodeprobe/0.1 (+https://github.com/ehsanhajian/nodeprobe)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        self._owns_client = client is None
        self.requests_made = 0
        self._started = time.monotonic()
        self._last_request_at = 0.0
        self.last_exchange: HttpExchange | None = None
        self.exchanges: list[HttpExchange] = []

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> BudgetedHttpClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _enforce_budget(self) -> None:
        killswitch.check()
        elapsed = time.monotonic() - self._started
        if elapsed > self.limits.max_duration_seconds:
            raise BudgetExceeded(
                f"Scan duration exceeded {self.limits.max_duration_seconds}s"
            )
        if self.requests_made >= self.limits.max_requests:
            raise BudgetExceeded(
                f"Request budget exceeded ({self.limits.max_requests})"
            )
        min_interval = 1.0 / self.limits.max_rps if self.limits.max_rps > 0 else 0
        since_last = time.monotonic() - self._last_request_at
        if self._last_request_at and since_last < min_interval:
            time.sleep(min_interval - since_last)

    def absolute_url(self, path_or_url: str) -> str:
        return urljoin(self.target.original_url.rstrip("/") + "/", path_or_url.lstrip("/"))

    def get(
        self,
        path_or_url: str | None = None,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        max_body: int = 200_000,
    ) -> HttpExchange:
        url = self.target.original_url if path_or_url is None else (
            path_or_url
            if path_or_url.startswith("http://") or path_or_url.startswith("https://")
            else self.absolute_url(path_or_url)
        )
        return self.request(
            "GET",
            url,
            headers=headers,
            follow_redirects=follow_redirects,
            max_body=max_body,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        max_body: int = 200_000,
    ) -> HttpExchange:
        current = url
        chain: list[str] = []
        response: httpx.Response | None = None

        for _ in range(self.max_redirects + 1):
            self._enforce_budget()
            started = time.monotonic()
            response = self._client.request(method, current, headers=headers)
            self.requests_made += 1
            self._last_request_at = time.monotonic()
            _ = started  # latency reserved for future use

            if response.status_code not in {301, 302, 303, 307, 308}:
                break
            location = response.headers.get("location")
            if not location or not follow_redirects:
                break
            next_url = str(httpx.URL(response.url).join(location))
            try:
                validate_redirect_target(next_url)
            except UnsafeTargetError as exc:
                raise UnsafeTargetError(f"Blocked redirect target: {exc}") from exc
            chain.append(next_url)
            current = next_url
            # After first redirect, subsequent hops are GET
            method = "GET" if response.status_code in {301, 302, 303} else method
        else:
            raise UnsafeTargetError("Too many redirects")

        assert response is not None
        body = response.text[:max_body] if response.content else ""
        exchange = HttpExchange(
            url=url,
            method=method,
            status_code=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            body_text=body,
            final_url=str(response.url),
            redirect_chain=chain,
        )
        self.last_exchange = exchange
        self.exchanges.append(exchange)
        return exchange

    def same_origin(self, url: str) -> bool:
        base = urlparse(self.target.original_url)
        other = urlparse(url)
        return (
            base.scheme == other.scheme
            and (base.hostname or "").lower() == (other.hostname or "").lower()
            and (base.port or (443 if base.scheme == "https" else 80))
            == (other.port or (443 if other.scheme == "https" else 80))
        )
