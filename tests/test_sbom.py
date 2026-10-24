import pytest

from vulnmap.sbom import (
    packages_from_cyclonedx,
    parse_purl,
    project_name_from_cyclonedx,
)

DOCUMENT = {
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
        {"name": "curl", "version": "7.0", "purl": "pkg:deb/debian/curl@7.0"},
        {"name": "no-version", "purl": "pkg:pypi/no-version"},
        {"name": "broken", "version": "1", "purl": "nonsense"},
        "not a component",
    ],
}


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:pypi/django@4.2.0", ("pypi", "django", "4.2.0")),
        ("pkg:PyPI/Django@4.2.0", ("pypi", "Django", "4.2.0")),
        ("pkg:npm/%40babel/core@7.0.0", ("npm", "@babel/core", "7.0.0")),
        ("pkg:npm/@babel/core@7.0.0", ("npm", "@babel/core", "7.0.0")),
        ("pkg:npm/@babel/core", ("npm", "@babel/core", None)),
        (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            ("maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
        ),
        (
            "pkg:composer/symfony/symfony@5.0.0",
            ("composer", "symfony/symfony", "5.0.0"),
        ),
        ("pkg:cargo/serde@1.0.0?arch=x86#sub/path", ("cargo", "serde", "1.0.0")),
    ],
)
def test_parse_purl(purl, expected):
    assert parse_purl(purl) == expected


@pytest.mark.parametrize(
    "purl",
    ["", "garbage", "pkg:", "pkg:pypi", "pkg:pypi/", "pkg:pypi/@1.0"],
)
def test_parse_purl_rejects_unusable_text(purl):
    assert parse_purl(purl) is None


def test_packages_from_cyclonedx_reads_nested_components_once():
    packages, skipped = packages_from_cyclonedx(DOCUMENT)

    assert packages == [
        {"ecosystem": "PyPI", "name": "django", "version": "4.2.0"},
        {"ecosystem": "npm", "name": "@babel/core", "version": "7.0.0"},
    ]
    assert skipped == [
        "left-pad - no package URL (purl)",
        "curl - unsupported package type 'deb'",
        "no-version - no version",
        "broken - invalid package URL (purl)",
    ]


def test_packages_from_cyclonedx_falls_back_to_purl_version():
    document = {
        "bomFormat": "CycloneDX",
        "components": [{"name": "x", "purl": "pkg:pypi/x@2.0"}],
    }

    packages, skipped = packages_from_cyclonedx(document)

    assert packages == [{"ecosystem": "PyPI", "name": "x", "version": "2.0"}]
    assert skipped == []


def test_packages_from_cyclonedx_handles_missing_component_list():
    document = {"bomFormat": "CycloneDX", "components": "oops"}

    assert packages_from_cyclonedx(document) == ([], [])


def test_packages_from_cyclonedx_rejects_other_formats():
    with pytest.raises(ValueError, match="CycloneDX"):
        packages_from_cyclonedx({"bomFormat": "SPDX"})


def test_project_name_from_cyclonedx():
    assert project_name_from_cyclonedx(DOCUMENT) == "demo-app"


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"metadata": "oops"},
        {"metadata": {"component": "oops"}},
        {"metadata": {"component": {"name": "   "}}},
    ],
)
def test_project_name_from_cyclonedx_without_a_name(document):
    assert project_name_from_cyclonedx(document) is None