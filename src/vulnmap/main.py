
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(
    title="VulnMap API",
    description="Open-source vulnerability intelligence prototype",
    version="0.1.0",
)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


class Package(BaseModel):
    ecosystem: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=300)
    version: str = Field(min_length=1, max_length=200)


class ScanRequest(BaseModel):
    project: str = Field(min_length=1, max_length=300)
    packages: list[Package] = Field(min_length=1, max_length=100)


class Finding(BaseModel):
    project: str
    ecosystem: str
    package: str
    version: str
    advisory_id: str
    summary: str | None = None
    severity: str
    priority: Literal["critical", "high", "medium", "unknown"]
    references: list[str]


def classify_priority(vulnerability: dict) -> str:
    """Use numeric scores only; never guess from missing data."""
    for item in vulnerability.get("severity", []):
        score = item.get("score", "")

        if not isinstance(score, str):
            continue

        try:
            value = float(score)
        except ValueError:
            continue

        if value >= 9.0:
            return "critical"
        if value >= 7.0:
            return "high"
        if value >= 4.0:
            return "medium"

    return "unknown"


@app.get("/health")
async def health():
    return {"status": "ok", "service": "vulnmap"}


@app.post("/scan", response_model=list[Finding])
async def scan(request: ScanRequest):
    queries = [
        {
            "package": {
                "name": package.name,
                "ecosystem": package.ecosystem,
            },
            "version": package.version,
        }
        for package in request.packages
    ]

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(
                OSV_BATCH_URL,
                json={"queries": queries},
            )
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(
            status_code=502,
            detail="Vulnerability data provider unavailable",
        ) from None

    results = data.get("results", [])

    if len(results) != len(request.packages):
        raise HTTPException(
            status_code=502,
            detail="Unexpected response from vulnerability provider",
        )

    findings = []

    for package, result in zip(request.packages, results):
        for vulnerability in result.get("vulns", []):
            references = [
                item["url"]
                for item in vulnerability.get("references", [])
                if isinstance(item.get("url"), str)
            ]

            findings.append(
                Finding(
                    project=request.project,
                    ecosystem=package.ecosystem,
                    package=package.name,
                    version=package.version,
                    advisory_id=vulnerability.get("id", "UNKNOWN"),
                    summary=vulnerability.get("summary"),
                    severity="unknown",
                    priority=classify_priority(vulnerability),
                    references=references,
                )
            )

    return findings
