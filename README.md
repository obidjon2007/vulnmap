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
.venv
