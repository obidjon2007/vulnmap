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

The current API queries the OSV vulnerability database for supplied
package versions. It does not scan public servers, prove exploitability,
or guarantee that a project is secure.

## Technology

- Python 3.11+
- FastAPI
- HTTPX
- Pydantic
- OSV API
- pytest

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

## API

- `GET /health` — service health.
- `POST /scan` — query known vulnerability data for supplied packages.

## Safety

VulnMap is intended for defensive security work. It queries vulnerability
metadata and does not exploit systems or scan third-party servers.

Do not submit secrets or private source code to this public service.

## Roadmap

- [ ] Normalize vulnerability severity and affected ranges.
- [ ] Import CycloneDX and SPDX SBOM documents.
- [ ] Store projects, dependencies, and observations.
- [ ] Build a dependency and remediation graph.
- [ ] Add a transparent remediation workflow.
- [ ] Build a public dashboard.

## Contributing

Contributions, tests, documentation, and security reviews are welcome.
See CONTRIBUTING.md.

## License

MIT. See LICENSE.
