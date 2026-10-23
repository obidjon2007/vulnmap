import json

import httpx
import pytest
from fastapi.testclient import TestClient

from vulnmap import main

client = TestClient(main.app)

# Keep a reference to the real class before any test replaces it.
RealAsyncClient = httpx.AsyncClient

REQUEST_BODY = {
    "project": "demo",
    "packages": [
        {"ecosystem": "PyPI", "name": "django", "version": "4.2.0"},
        {"ecosystem": "PyPI", "name": "httpx", "version": "0.27.0"},
    ],
}

ONE_PACKAGE_BODY = {
    "project": "demo",
    "packages": [{"ecosystem": "PyPI", "name": "django", "version": "4.2.0"}],
}


def fake_osv(monkeypatch, handler):
    """Make /scan talk to a fake OSV server instead of the real internet."""

    def factory(*args, **kwargs):
        return RealAsyncClient(
            *args,
            transport=httpx.MockTransport(handler),
            **kwargs,
        )

    monkeypatch.setattr(main.httpx, "AsyncClient", factory)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        ("9.8", "critical"),
        ("9.0", "critical"),
        ("7.5", "high"),
        ("5.0", "medium"),
        ("2.0", "unknown"),
                ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"),
    ],
)
def test_classify_priority(score, expected):
    vulnerability = {"severity": [{"type": "CVSS_V3", "score": score}]}

    assert main.classify_priority(vulnerability) == expected


def test_classify_priority_without_severity():
    assert main.classify_priority({}) == "unknown"


def test_scan_returns_findings(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-xxxx-xxxx-xxxx",
                                "summary": "Example issue",
                                "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                                "references": [
                                    {
                                        "type": "ADVISORY",
                                        "url": "https://example.com/advisory",
                                    },
                                    {"type": "WEB"},
                                ],
                            }
                        ]
                    },
                    {},
                ]
            },
        )

    fake_osv(monkeypatch, handler)

    response = client.post("/scan", json=REQUEST_BODY)

    assert response.status_code == 200
    assert response.json() == [
        {
            "project": "demo",
            "ecosystem": "PyPI",
            "package": "django",
            "version": "4.2.0",
            "advisory_id": "GHSA-xxxx-xxxx-xxxx",
            "summary": "Example issue",
            "severity": "unknown",
            "priority": "critical",
            "references": ["https://example.com/advisory"],
        }
    ]

    assert len(seen) == 1
    assert str(seen[0].url) == main.OSV_BATCH_URL
    assert json.loads(seen[0].content) == {
        "queries": [
            {
                "package": {"name": "django", "ecosystem": "PyPI"},
                "version": "4.2.0",
            },
            {
                "package": {"name": "httpx", "ecosystem": "PyPI"},
                "version": "0.27.0",
            },
        ]
    }


def test_scan_without_vulnerabilities_returns_empty_list(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"results": [{}]})

    fake_osv(monkeypatch, handler)

    response = client.post("/scan", json=ONE_PACKAGE_BODY)

    assert response.status_code == 200
    assert response.json() == []


def test_scan_returns_502_when_provider_fails(monkeypatch):
    def handler(request):
        return httpx.Response(500, json={"error": "boom"})

    fake_osv(monkeypatch, handler)

    response = client.post("/scan", json=ONE_PACKAGE_BODY)

    assert response.status_code == 502
    assert response.json() == {"detail": "Vulnerability data provider unavailable"}


def test_scan_returns_502_when_provider_is_unreachable(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("connection refused")

    fake_osv(monkeypatch, handler)

    response = client.post("/scan", json=ONE_PACKAGE_BODY)

    assert response.status_code == 502
    assert response.json() == {"detail": "Vulnerability data provider unavailable"}


def test_scan_returns_502_when_provider_sends_invalid_json(monkeypatch):
    def handler(request):
        return httpx.Response(200, content=b"this is not json")

    fake_osv(monkeypatch, handler)

    response = client.post("/scan", json=ONE_PACKAGE_BODY)

    assert response.status_code == 502
    assert response.json() == {"detail": "Vulnerability data provider unavailable"}


def test_scan_returns_502_when_result_count_does_not_match(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"results": [{}, {}]})

    fake_osv(monkeypatch, handler)

    response = client.post("/scan", json=ONE_PACKAGE_BODY)

    assert response.status_code == 502
    assert response.json() == {
        "detail": "Unexpected response from vulnerability provider"
    }
