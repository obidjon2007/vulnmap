
"""Read package lists from CycloneDX SBOM documents.

This module only reads data. It never contacts any server.
"""

from urllib.parse import unquote

PURL_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
    "golang": "Go",
}

MAX_NAME_LENGTH = 300
MAX_VERSION_LENGTH = 200
MAX_COMPONENTS = 100_000


def parse_purl(purl: str) -> tuple[str, str, str | None] | None:
    """Return (type, name, version), or None for unusable PURLs."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None

    rest = purl[4:].split("#", 1)[0].split("?", 1)[0]

    version = None
    at = rest.rfind("@")
    if at > rest.rfind("/"):
        rest, raw_version = rest[:at], rest[at + 1:]
        version = unquote(raw_version) or None

    purl_type, separator, path = rest.partition("/")
    if not separator or not path:
        return None

    purl_type = purl_type.lower()
    if purl_type not in PURL_ECOSYSTEMS:
        return None

    segments = [unquote(part) for part in path.split("/")]
    if any(not part or part in {".", ".."} for part in segments):
        return None

    name = segments[-1]
    namespace = "/".join(segments[:-1])

    if namespace:
        joiner = ":" if purl_type == "maven" else "/"
        name = f"{namespace}{joiner}{name}"

    if not name or len(name) > MAX_NAME_LENGTH:
        return None
    if version is not None and len(version) > MAX_VERSION_LENGTH:
        return None

    return purl_type, name, version


def iter_components(document: dict):
    """Yield components, including nested ones, in document order."""
    top_level = document.get("components")
    if not isinstance(top_level, list):
        return

    stack = list(reversed(top_level))
    count = 0

    while stack:
        component = stack.pop()
        if not isinstance(component, dict):
            continue

        count += 1
        if count > MAX_COMPONENTS:
            raise ValueError("SBOM contains too many components")

        yield component

        children = component.get("components")
        if isinstance(children, list):
            stack.extend(reversed(children))


def packages_from_cyclonedx(
    document: dict,
) -> tuple[list[dict], list[str]]:
    """Return (packages, skipped) from a CycloneDX document."""
    if not isinstance(document, dict):
        raise ValueError("SBOM must be a JSON object")

    if document.get("bomFormat") != "CycloneDX":
        raise ValueError(
            "Not a CycloneDX document (bomFormat must be CycloneDX)"
        )

    packages = []
    skipped = []
    seen = set()

    for component in iter_components(document):
        purl = component.get("purl")
        label = str(component.get("name") or "unnamed component")

        if not isinstance(purl, str):
            skipped.append(f"{label}: missing package URL")
            continue

        parsed = parse_purl(purl)
        if parsed is None:
            skipped.append(f"{label}: unsupported or invalid package URL")
            continue

        purl_type, name, version = parsed
        ecosystem = PURL_ECOSYSTEMS[purl_type]

        if not version:
            version = component.get("version")
        if not isinstance(version, str) or not version:
            skipped.append(f"{label}: missing package version")
            continue
        if len(version) > MAX_VERSION_LENGTH:
            skipped.append(f"{label}: package version is too long")
            continue

        key = (ecosystem, name, version)
        if key in seen:
            continue

        seen.add(key)
        packages.append({
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
        })

    return packages, skipped
