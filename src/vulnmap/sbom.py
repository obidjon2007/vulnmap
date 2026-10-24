"""Read package lists out of CycloneDX SBOM documents.

This module only reads data. It never contacts any server.
"""

from urllib.parse import unquote

# Maps the "type" part of a package URL (purl) to the OSV ecosystem name.
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
}

MAX_NAME_LENGTH = 300
MAX_VERSION_LENGTH = 200


def parse_purl(purl: str) -> tuple[str, str, str | None] | None:
    """Split a package URL into (type, name, version).

    The namespace is folded into the name the way OSV expects it:
    "group:artifact" for Maven and "scope/name" for everything else.
    Returns None when the text is not a usable purl.
    """
    if not purl.startswith("pkg:"):
        return None

    rest = purl[4:].lstrip("/")
    rest = rest.split("#", 1)[0].split("?", 1)[0]

    # The version separator is the last "@" that comes after the last "/",
    # so an unencoded npm scope such as "@babel/core" is not mistaken for it.
    version = None
    at = rest.rfind("@")

    if at > rest.rfind("/"):
        rest, version = rest[:at], unquote(rest[at + 1 :]) or None

    purl_type, separator, path = rest.partition("/")

    if not separator:
        return None

    segments = [unquote(segment) for segment in path.split("/")]
    name = segments[-1]
    namespace = "/".join(segment for segment in segments[:-1] if segment)

    if not name:
        return None

    purl_type = purl_type.lower()

    if namespace:
        joiner = ":" if purl_type == "maven" else "/"
        name = f"{namespace}{joiner}{name}"

    return purl_type, name, version


def iter_components(document: dict):
    """Yield every component, including nested ones, in document order."""
    top_level = document.get("components")

    if not isinstance(top_level, list):
        return

    stack = list(reversed(top_level))

    while stack:
        component = stack.pop()

        if not isinstance(component, dict):
            continue

        yield component

        children = component.get("components")

        if isinstance(children, list):
            stack.extend(reversed(children))


def packages_from_cyclonedx(document: dict) -> tuple[list[dict], list[str]]:
    """Return (packages, skipped) found in a CycloneDX document.

    Each package is a dict with "ecosystem", "name" and "version".
    "skipped" explains every component that could not be checked.
    Raises ValueError when the document is not CycloneDX.
    """
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("Not a CycloneDX document (bomFormat must be CycloneDX)")

    packages = []
    skipped = []
    seen = set()

    for component in iter_components(document):
        purl = component.get("purl")
        label = component.get("name")

        if not isinstance(label, str) or not label:
            label = purl if isinstance(purl, str) and purl else "unnamed component"

        if not isinstance(purl, str) or not purl:
            skipped.append(f"{label} - no package URL (purl)")
            continue

        parsed = parse_purl(purl)

        if parsed is None:
            skipped.append(f"{label} - invalid package URL (purl)")
            continue

        purl_type, name, purl_version = parsed
        ecosystem = PURL_ECOSYSTEMS.get(purl_type)

        if ecosystem is None:
            skipped.append(f"{label} - unsupported package type '{purl_type}'")
            continue

        version = component.get("version")

        if not isinstance(version, str) or not version.strip():
            version = purl_version

        if not version or not version.strip():
            skipped.append(f"{label} - no version")
            continue

        version = version.strip()

        if len(name) > MAX_NAME_LENGTH or len(version) > MAX_VERSION_LENGTH:
            skipped.append(f"{label} - name or version too long")
            continue

        key = (ecosystem, name, version)

        if key in seen:
            continue

        seen.add(key)
        packages.append({"ecosystem": ecosystem, "name": name, "version": version})

    return packages, skipped


def project_name_from_cyclonedx(document: dict) -> str | None:
    """Return the project name stored in the SBOM metadata, if any."""
    metadata = document.get("metadata")

    if not isinstance(metadata, dict):
        return None

    component = metadata.get("component")

    if not isinstance(component, dict):
        return None

    name = component.get("name")

    if isinstance(name, str) and name.strip():
        return name.strip()

    return None