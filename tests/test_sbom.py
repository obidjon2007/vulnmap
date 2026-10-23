
import pytest

from vulnmap.sbom import packages_from_cyclonedx, parse_purl


def test_parse_pypi_purl():
    assert parse_purl("pkg:pypi/requests@2.32.0") == (
        "pypi", "requests", "2.32.0"
    )


def test_parse_npm_scoped_package():
    assert parse_purl("pkg:npm/@babel/core@7.24.0") == (
        "npm", "@babel/core", "7.24.0"
    )


def test_parse_maven_package():
    assert parse_purl("pkg:maven/org.example/library@1.2.3") == (
        "maven", "org.example:library", "1.2.3"
    )


@pytest.mark.parametrize("value", [
    "",
    "https://example.com/package",
    "pkg:unknown/package@1.0",
    "pkg:pypi/",
])
def test_invalid_purl(value):
    assert parse_purl(value) is None


def test_cyclonedx_extracts_packages():
    document = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "name": "requests",
                "purl": "pkg:pypi/requests@2.32.0",
            },
            {
                "name": "root",
                "components": [
                    {
                        "name": "flask",
                        "purl": "pkg:pypi/flask@3.0.0",
                    }
                ],
            },
        ],
    }

    packages, skipped = packages_from_cyclonedx(document)

    assert len(packages) == 2
    assert packages[0] == {
        "ecosystem": "PyPI",
        "name": "requests",
        "version": "2.32.0",
    }
    assert packages[1]["name"] == "flask"
    assert skipped == []


def test_duplicate_packages_are_removed():
    document = {
        "bomFormat": "CycloneDX",
        "components": [
            {"purl": "pkg:pypi/requests@2.32.0"},
            {"purl": "pkg:pypi/requests@2.32.0"},
        ],
    }

    packages, skipped = packages_from_cyclonedx(document)

    assert len(packages) == 1
    assert skipped == []


def test_missing_version_is_skipped():
    document = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "requests", "purl": "pkg:pypi/requests"},
        ],
    }

    packages, skipped = packages_from_cyclonedx(document)

    assert packages == []
    assert len(skipped) == 1


def test_invalid_document_format():
    with pytest.raises(ValueError):
        packages_from_cyclonedx({"bomFormat": "SPDX"})


def test_component_version_fallback():
    document = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "name": "requests",
                "purl": "pkg:pypi/requests",
                "version": "2.32.0",
            }
        ],
    }

    packages, skipped = packages_from_cyclonedx(document)

    assert packages[0]["version"] == "2.32.0"
    assert skipped == []
