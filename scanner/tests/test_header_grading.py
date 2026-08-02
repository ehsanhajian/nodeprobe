from __future__ import annotations

from nodeprobe.rules.web.headers import grade_csp, grade_hsts


def test_grade_hsts_weak_max_age_and_missing_subdomains():
    issues = grade_hsts("max-age=3600")
    codes = {i.evidence["issue"] for i in issues}
    assert "weak_max_age" in codes
    assert "missing_includesubdomains" in codes


def test_grade_hsts_strong_policy_clean():
    issues = grade_hsts("max-age=31536000; includeSubDomains; preload")
    assert issues == []


def test_grade_hsts_preload_not_ready():
    issues = grade_hsts("max-age=31536000; preload")
    codes = {i.evidence["issue"] for i in issues}
    assert "missing_includesubdomains" in codes
    assert "preload_not_ready" in codes


def test_grade_csp_unsafe_inline_and_wildcard():
    issues = grade_csp(
        "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval'",
        has_xfo=False,
    )
    codes = {i.evidence["issue"] for i in issues}
    assert "unsafe_inline" in codes
    assert "unsafe_eval" in codes
    assert "wildcard_source" in codes
    assert "missing_frame_ancestors" in codes


def test_grade_csp_strict_with_frame_ancestors():
    issues = grade_csp(
        "default-src 'self'; script-src 'self'; frame-ancestors 'none'; object-src 'none'",
        has_xfo=False,
    )
    assert issues == []
