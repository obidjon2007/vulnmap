"""Helpers that read OSV vulnerability records.

These are pure functions: they never contact any server.
"""

import re

# Severity labels used by advisory databases, mapped to VulnMap priorities.
LABEL_PRIORITIES = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}

# Only these range types hold package versions. GIT ranges hold commit hashes.
VERSION_RANGE_TYPES = ("ECOSYSTEM", "SEMVER")

MAX_SUMMARY_LENGTH = 200


def vulnerabilities_of(result) -> list[dict]:
    """Return the vulnerability entries of one OSV batch result."""
    if not isinstance(result, dict):
        return []

    vulnerabilities = result.get("vulns")

    if not isinstance(vulnerabilities, list):
        return []

    return [item for item in vulnerabilities if isinstance(item, dict)]


def advisory_ids(results: list) -> list[str]:
    """Return every advisory id once, in the order it first appears."""
    ids = []

    for result in results:
        for vulnerability in vulnerabilities_of(result):
            advisory_id = vulnerability.get("id")

            if isinstance(advisory_id, str) and advisory_id not in ids:
                ids.append(advisory_id)

    return ids


def severity_label(vulnerability: dict) -> str | None:
    """Return the severity label given by the advisory database, if any."""
    database = vulnerability.get("database_specific")

    if not isinstance(database, dict):
        return None

    label = database.get("severity")

    if not isinstance(label, str):
        return None

    label = label.strip().upper()

    if label in LABEL_PRIORITIES:
        return label

    return None


def priority_from_label(label: str | None) -> str | None:
    """Translate a severity label into a VulnMap priority."""
    if label is None:
        return None

    return LABEL_PRIORITIES.get(label)


def summary_of(vulnerability: dict) -> str | None:
    """Return the summary, or the first line of the details when it is missing."""
    summary = vulnerability.get("summary")

    if isinstance(summary, str) and summary.strip():
        return summary.strip()

    details = vulnerability.get("details")

    if not isinstance(details, str):
        return None

    for line in details.splitlines():
        line = line.lstrip("#").strip()

        if not line:
            continue

        if len(line) > MAX_SUMMARY_LENGTH:
            return line[: MAX_SUMMARY_LENGTH - 3] + "..."

        return line

    return None


def reference_urls(vulnerability: dict) -> list[str]:
    """Return the web addresses listed in the references."""
    references = vulnerability.get("references")

    if not isinstance(references, list):
        return []

    return [
        item["url"]
        for item in references
        if isinstance(item, dict) and isinstance(item.get("url"), str)
    ]


def normalize_name(ecosystem: str, name: str) -> str:
    """Normalize a package name so that different spellings compare equal."""
    name = name.strip().lower()

    if ecosystem.lower() == "pypi":
        name = re.sub(r"[-_.]+", "-", name)

    return name


def fixed_versions(vulnerability: dict, ecosystem: str, name: str) -> list[str]:
    """Return the versions in which the advisory is fixed for this package.

    An advisory can be fixed in several versions, one per affected branch.
    All of them are returned, in the order the advisory lists them.
    """
    wanted = normalize_name(ecosystem, name)
    affected = vulnerability.get("affected")
    found = []

    if not isinstance(affected, list):
        return found

    for entry in affected:
        if not isinstance(entry, dict):
            continue

        package = entry.get("package")

        if not isinstance(package, dict):
            continue

        package_ecosystem = package.get("ecosystem")
        package_name = package.get("name")

        if not isinstance(package_ecosystem, str) or not isinstance(package_name, str):
            continue

        if package_ecosystem.lower() != ecosystem.lower():
            continue

        if normalize_name(ecosystem, package_name) != wanted:
            continue

        ranges = entry.get("ranges")

        if not isinstance(ranges, list):
            continue

        for version_range in ranges:
            if not isinstance(version_range, dict):
                continue

            if version_range.get("type") not in VERSION_RANGE_TYPES:
                continue

            events = version_range.get("events")

            if not isinstance(events, list):
                continue

            for event in events:
                if not isinstance(event, dict):
                    continue

                fixed = event.get("fixed")

                if isinstance(fixed, str) and fixed and fixed not in found:
                    found.append(fixed)

    return found
