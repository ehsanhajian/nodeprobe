"""Budgeted JSON-RPC HTTP client with rate limits and safety checks."""

from __future__ import annotations

import time
from typing import Any

import httpx

from dapptility_scanner import killswitch
from dapptility_scanner.profiles import ProfileLimits
from dapptility_scanner.safety import SafeTarget, UnsafeTargetError, validate_redirect_target


class BudgetExceeded(RuntimeError):
    pass


class ScanAborted(RuntimeError):
    pass


class RpcClient:
    def __init__(
        self,
        target: SafeTarget,
        limits: ProfileLimits,
        *,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
    ):
        self.target = target
        self.limits = limits
        self.timeout = timeout
        self._client = client or httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            headers={
                "User-Agent": "DapptilityScanner/0.1 (+https://dapptility.com)",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        self._owns_client = client is None
        self.requests_made = 0
        self._started = time.monotonic()
        self._last_request_at = 0.0
        self._rpc_id = 0
        self.last_headers: dict[str, str] = {}
        self.last_status: int | None = None
        self.last_content_type: str | None = None
        self.latencies_ms: list[float] = []

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> RpcClient:
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

    def _record(self, response: httpx.Response, started: float) -> None:
        self.requests_made += 1
        self._last_request_at = time.monotonic()
        self.latencies_ms.append((time.monotonic() - started) * 1000)
        self.last_status = response.status_code
        self.last_headers = {k.lower(): v for k, v in response.headers.items()}
        self.last_content_type = self.last_headers.get("content-type")

    def _handle_redirect(self, response: httpx.Response) -> httpx.Response:
        location = response.headers.get("location")
        if not location:
            return response
        # Absolute or relative — rebuild carefully
        next_url = httpx.URL(response.url).join(location)
        try:
            validate_redirect_target(str(next_url))
        except UnsafeTargetError as exc:
            raise UnsafeTargetError(f"Blocked redirect target: {exc}") from exc
        # Do not auto-follow; callers can decide. For RPC we reject redirects by default.
        raise UnsafeTargetError(
            f"Refusing to follow redirect to {next_url} (SSRF/redirect policy)"
        )

    def request_raw(self, method: str = "POST", *, json_body: dict | None = None) -> httpx.Response:
        self._enforce_budget()
        started = time.monotonic()
        response = self._client.request(
            method,
            self.target.original_url,
            json=json_body,
        )
        self._record(response, started)
        if response.status_code in {301, 302, 303, 307, 308}:
            self._handle_redirect(response)
        return response

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        self._rpc_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._rpc_id,
            "method": method,
            "params": params or [],
        }
        response = self.request_raw(json_body=payload)
        if response.status_code == 429:
            return {"__http_error__": 429, "headers": dict(response.headers)}
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise RuntimeError("Invalid JSON-RPC response: not an object")
        if "error" in data and data["error"]:
            return {"__rpc_error__": data["error"]}
        return data.get("result")

    def method_available(self, method: str, params: list[Any] | None = None) -> tuple[bool, Any]:
        """Presence probe — treats method-not-found as unavailable, not as finding."""
        result = self.call(method, params)
        if isinstance(result, dict) and "__rpc_error__" in result:
            err = result["__rpc_error__"]
            code = err.get("code") if isinstance(err, dict) else None
            message = str(err.get("message", "") if isinstance(err, dict) else err).lower()
            # JSON-RPC method not found / unavailable
            if code in (-32601, -32004) or "not found" in message or "not available" in message:
                return False, err
            if "method" in message and ("exist" in message or "unsupported" in message):
                return False, err
            # Other errors often still mean the method namespace is exposed
            return True, err
        if isinstance(result, dict) and "__http_error__" in result:
            return False, result
        return True, result
