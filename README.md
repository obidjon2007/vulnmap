# VulnMap

**Open-source vulnerability intelligence and remediation coordination.**

VulnMap is an open-source project designed to connect vulnerability
intelligence, software dependencies, affected projects, and remediation
status in one transparent system.

## Goals

- Collect known vulnerability data from trusted public sources.
- Map software components and affected version ranges.
- Track remediation status with evidence and timestamps.
- Help maintainers prioritize security fixes.
- Build an open, auditable global dependency risk graph.

## Current status

Early prototype. Not production-ready.

The current API queries the OSV vulnerability database for package versions
you supply, either as a plain list or as a CycloneDX SBOM. Findings are
ranked by CVSS v3 scores. CVSS v4 scores are not read yet and stay
`unknown`. VulnMap does not scan public servers, prove exploitability, or
guarantee that a project is secure.

## Technology

- Python 3.11+
- FastAPI
- HTTPX
- Pydantic
- OSV API
- pytest
- Ruff

## Run locally

Create a virtual environment and install the project:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn vulnmap.main:app --reload
```

Open http://127.0.0.1:8000/docs to try the API.

On Windows, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

Run the tests and the linter:

```bash
pytest -v
ruff check src tests
```

## API

- `GET /health` - service health.
- `POST /scan` - query known vulnerability data for a list of packages.
- `POST /scan/sbom` - query known vulnerability data for the components of a
  CycloneDX JSON SBOM.

### Scan an SBOM

With the server running, send the example file from this repository:

```bash
curl -X POST "http://127.0.0.1:8000/scan/sbom" \
  -H "Content-Type: application/json" \
  --data @examples/sample-sbom.json
```

The project name is taken from `metadata.component.name` in the SBOM. To set
it yourself, add `?project=my-project` to the URL.

The answer lists how many packages were checked, which components were
skipped and why, and the findings:

```json
{
  "project": "sample-app",
  "scanned_packages": 3,
  "skipped": ["internal-tool - no package URL (purl)"],
  "findings": [
    {
      "project": "sample-app",
      "ecosystem": "npm",
      "package": "lodash",
      "version": "4.17.15",
      "advisory_id": "GHSA-xxxx-xxxx-xxxx",
      "summary": "Short description of the issue",
      "severity": "unknown",
      "priority": "high",
      "references": ["https://example.com/advisory"]
    }
  ]
}
```

The values in `findings` above are illustrative.

Components are read from their package URL (purl). Supported package types:
PyPI, npm, Maven, Cargo, RubyGems, NuGet, Composer, Hex and Pub.

## Safety

VulnMap is intended for defensive security work. It queries vulnerability
metadata and does not exploit systems or scan third-party servers.

Do not submit secrets or private source code to this public service.

## Roadmap

- [x] Read CVSS v3 scores to rank findings.
- [x] Import CycloneDX SBOM documents (JSON).
- [ ] Read CVSS v4 scores.
- [ ] Import SPDX SBOM documents.
- [ ] Normalize affected version ranges.
- [ ] Store projects, dependencies, and observations.
- [ ] Build a dependency and remediation graph.
- [ ] Add a transparent remediation workflow.
- [ ] Build a public dashboard.

## Contributing

Contributions, tests, documentation, and security reviews are welcome.
See CONTRIBUTING.md.

## License

MIT. See LICENSE.