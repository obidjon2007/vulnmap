import json

import httpx
from fastapi.testclient import TestClient

from vulnmap import main

client = TestClient(main.app)

# Keep a reference to the real class before any test replaces it.
RealAsyncClient = httpx.AsyncClient

CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {"component": {"type": "application", "name": "demo-app"}},
    "components": [
        {"name": "django", "version": "4.2.0", "purl": "pkg:pypi/django@4.2.0"},
        {
            "name": "core",
            "version": "7.0.0",
            "purl": "pkg:npm/%40babel/core@7.0.0",
            "components": [
                {
                    "name": "django",
                    "version": "4.2.0",
                    "purl": "pkg:pypi/django@4.2.0",
                }
            ],
        },
        {"name": "left-pad", "version": "1.3.0"},
    ],
}


def fake_osv(monkeypatch, handler):
    """Make /scan/sbom talk to a fake OSV server instead of the internet."""

    def factory(*args, **kwargs):
        return RealAsyncClient(
            *args,
            transport=httpx.MockTransport(handler),
            **kwargs,
        )

    monkeypatch.setattr(main.httpx, "AsyncClient", factory)


def vulnerable_django_handler(seen):
    """Report one critical issue for django and nothing for other packages."""

    def handler(request):
        body = json.loads(request.content)
        seen.append(body)
        results = []

        for query in body["queries"]:
            if query["package"]["name"] == "django":
                results.append(
                    {
                        "vulns": [
                            {
                                "id": "GHSA-xxxx-xxxx-xxxx",
                                "summary": "Example issue",
                                "severity": [
                                    {"type": "CVSS_V3", "score": CRITICAL_VECTOR}
                                ],
                                "references": [
                                    {
                                        "type": "ADVISORY",
                                        "url": "https://example.com/advisory",
                                    }
                                ],
                            }
                        ]
                    }
                )
            else:
                results.append({})

        return httpx.Response(200, json={"results": results})

    return handler


def test_scan_sbom_returns_findings(monkeypatch):
    seen = []
    fake_osv(monkeypatch, vulnerable_django_handler(seen))

    response = client.post("/scan/sbom", json=SBOM)

    assert response.status_code == 200
    assert response.json() == {
        "project": "demo-app",
        "scanned_packages": 2,
        "skipped": ["left-pad - no package URL (purl)"],
        "findings": [
            {
                "project": "demo-app",
                "ecosystem": "PyPI",
                "package": "django",
                "version": "4.2.0",
                "advisory_id": "GHSA-xxxx-xxxx-xxxx",
                "summary": "Example issue",
                "severity": "unknown",
                "priority": "critical",
                "references": ["https://example.com/advisory"],
            }
        ],
    }

    assert seen == [
        {
            "queries": [
                {
                    "package": {"name": "django", "ecosystem": "PyPI"},
                    "version": "4.2.0",
                },
                {
                    "package": {"name": "@babel/core", "ecosystem": "npm"},
                    "version": "7.0.0",
                },
            ]
        }
    ]


def test_scan_sbom_project_parameter_overrides_metadata(monkeypatch):
    fake_osv(monkeypatch, vulnerable_django_handler([]))

    response = client.post("/scan/sbom?project=my-project", json=SBOM)

    assert response.status_code == 200
    assert response.json()["project"] == "my-project"
    assert response.json()["findings"][0]["project"] == "my-project"


def test_scan_sbom_requires_a_project_name():
    document = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "django", "version": "4.2.0", "purl": "pkg:pypi/django@4.2.0"}
        ],
    }

    response = client.post("/scan/sbom", json=document)

    assert response.status_code == 422
    assert "Project name is missing" in response.json()["detail"]


def test_scan_sbom_rejects_other_formats():
    response = client.post("/scan/sbom?project=demo", json={"bomFormat": "SPDX"})

    assert response.status_code == 422
    assert "CycloneDX" in response.json()["detail"]


def test_scan_sbom_rejects_a_list_body():
    response = client.post("/scan/sbom?project=demo", json=[])

    assert response.status_code == 422


def test_scan_sbom_without_scannable_components_skips_osv(monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"results": []})

    fake_osv(monkeypatch, handler)
    document = {
        "bomFormat": "CycloneDX",
        "components": [{"name": "left-pad", "version": "1.3.0"}],
    }

    response = client.post("/scan/sbom?project=demo", json=document)

    assert response.status_code == 200
    assert response.json() == {
        "project": "demo",
        "scanned_packages": 0,
        "skipped": ["left-pad - no package URL (purl)"],
        "findings": [],
    }
    assert calls == []


def test_scan_sbom_returns_502_when_provider_fails(monkeypatch):
    def handler(request):
        return httpx.Response(500, json={"error": "boom"})

    fake_osv(monkeypatch, handler)

    response = client.post("/scan/sbom", json=SBOM)

    assert response.status_code == 502
    assert response.json() == {"detail": "Vulnerability data provider unavailable"}
