import math
from typing import Annotated, Literal

import httpx
from fastapi import Body, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from vulnmap.sbom import packages_from_cyclonedx, project_name_from_cyclonedx

app = FastAPI(
    title="VulnMap API",
    description="Open-source vulnerability intelligence prototype",
    version="0.1.0",
)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_SBOM_PACKAGES = 1000

# Metric weights from the public CVSS v3.1 specification (first.org/cvss).
CVSS3_ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
CVSS3_ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
CVSS3_USER_INTERACTION = {"N": 0.85, "R": 0.62}
CVSS3_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}
CVSS3_PRIVILEGES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
CVSS3_PRIVILEGES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


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


class SbomScanResponse(BaseModel):
    project: str
    scanned_packages: int
    skipped: list[str]
    findings: list[Finding]


def cvss3_roundup(value: float) -> float:
    """Round up to one decimal place, as defined by CVSS v3.1."""
    integer = round(value * 100000)

    if integer % 10000 == 0:
        return integer / 100000.0

    return (math.floor(integer / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Return the CVSS v3.x base score for a vector string.

    Returns None when the vector is not a valid CVSS v3 vector.
    """
    parts = vector.split("/")

    if not parts[0].startswith("CVSS:3"):
        return None

    metrics = {}

    for part in parts[1:]:
        key, separator, value = part.partition(":")

        if not separator:
            return None

        metrics[key] = value

    scope = metrics.get("S")

    if scope not in ("U", "C"):
        return None

    privileges = (
        CVSS3_PRIVILEGES_CHANGED if scope == "C" else CVSS3_PRIVILEGES_UNCHANGED
    )

    try:
        exploitability = (
            8.22
            * CVSS3_ATTACK_VECTOR[metrics["AV"]]
            * CVSS3_ATTACK_COMPLEXITY[metrics["AC"]]
            * privileges[metrics["PR"]]
            * CVSS3_USER_INTERACTION[metrics["UI"]]
        )
        isc_base = 1 - (
            (1 - CVSS3_IMPACT[metrics["C"]])
            * (1 - CVSS3_IMPACT[metrics["I"]])
            * (1 - CVSS3_IMPACT[metrics["A"]])
        )
    except KeyError:
        return None

    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

    if impact <= 0:
        return 0.0

    if scope == "U":
        return cvss3_roundup(min(impact + exploitability, 10))

    return cvss3_roundup(min(1.08 * (impact + exploitability), 10))


def severity_score(item: dict) -> float | None:
    """Read a numeric score from an OSV severity entry, if there is one."""
    score = item.get("score", "")

    if not isinstance(score, str):
        return None

    try:
        return float(score)
    except ValueError:
        return cvss3_base_score(score)


def classify_priority(vulnerability: dict) -> str:
    """Use numeric scores only; never guess from missing data."""
    for item in vulnerability.get("severity", []):
        value = severity_score(item)

        if value is None:
            continue

        if value >= 9.0:
            return "critical"
        if value >= 7.0:
            return "high"
        if value >= 4.0:
            return "medium"

    return "unknown"


async def find_vulnerabilities(
    project: str,
    packages: list[Package],
) -> list[Finding]:
    """Ask OSV about the given packages and turn the answer into findings."""
    queries = [
        {
            "package": {
                "name": package.name,
                "ecosystem": package.ecosystem,
            },
            "version": package.version,
        }
        for package in packages
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

    if len(results) != len(packages):
        raise HTTPException(
            status_code=502,
            detail="Unexpected response from vulnerability provider",
        )

    findings = []

    for package, result in zip(packages, results):
        for vulnerability in result.get("vulns", []):
            references = [
                item["url"]
                for item in vulnerability.get("references", [])
                if isinstance(item.get("url"), str)
            ]

            findings.append(
                Finding(
                    project=project,
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


@app.get("/health")
async def health():
    return {"status": "ok", "service": "vulnmap"}


@app.post("/scan", response_model=list[Finding])
async def scan(request: ScanRequest):
    return await find_vulnerabilities(request.project, request.packages)


@app.post("/scan/sbom", response_model=SbomScanResponse)
async def scan_sbom(
    document: Annotated[dict, Body()],
    project: Annotated[str | None, Query(min_length=1, max_length=300)] = None,
):
    """Scan the components listed in a CycloneDX JSON SBOM."""
    try:
        found, skipped = packages_from_cyclonedx(document)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None

    project_name = project or project_name_from_cyclonedx(document)

    if not project_name:
        raise HTTPException(
            status_code=422,
            detail=(
                "Project name is missing: add the ?project= query parameter "
                "or metadata.component.name to the SBOM"
            ),
        )

    if len(found) > MAX_SBOM_PACKAGES:
        raise HTTPException(
            status_code=422,
            detail=f"Too many components (maximum is {MAX_SBOM_PACKAGES})",
        )

    findings = []

    if found:
        packages = [Package(**item) for item in found]
        findings = await find_vulnerabilities(project_name, packages)

    return SbomScanResponse(
        project=project_name,
        scanned_packages=len(found),
        skipped=skipped,
        findings=findings,
    )