import pytest

from vulnmap.osv import (
    advisory_ids,
    fixed_versions,
    normalize_name,
    priority_from_label,
    reference_urls,
    severity_label,
    summary_of,
    vulnerabilities_of,
)

PYSEC_RECORD = {
    "id": "PYSEC-2018-28",
    "details": "\n## Requests leaks credentials on redirect\n\nMore text.",
    "affected": [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "GIT",
                    "events": [{"introduced": "0"}, {"fixed": "c45d7c49ea75"}],
                },
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.20.0"}],
                },
            ],
        }
    ],
}


def test_vulnerabilities_of_keeps_only_dict_entries():
    result = {"vulns": [{"id": "A"}, "oops", 5, {"id": "B"}]}

    assert vulnerabilities_of(result) == [{"id": "A"}, {"id": "B"}]


@pytest.mark.parametrize("result", [None, "oops", [], {}, {"vulns": "oops"}])
def test_vulnerabilities_of_handles_unusable_results(result):
    assert vulnerabilities_of(result) == []


def test_advisory_ids_are_unique_and_keep_order():
    results = [
        {"vulns": [{"id": "B"}, {"id": "A"}]},
        {},
        {"vulns": [{"id": "A"}, {"id": "C"}, {"modified": "x"}, {"id": 7}]},
    ]

    assert advisory_ids(results) == ["B", "A", "C"]


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ({"database_specific": {"severity": "MODERATE"}}, "MODERATE"),
        ({"database_specific": {"severity": " high "}}, "HIGH"),
        ({"database_specific": {"severity": "unheard-of"}}, None),
        ({"database_specific": {"severity": 5}}, None),
        ({"database_specific": "oops"}, None),
        ({}, None),
    ],
)
def test_severity_label(record, expected):
    assert severity_label(record) == expected


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("CRITICAL", "critical"),
        ("HIGH", "high"),
        ("MODERATE", "medium"),
        ("MEDIUM", "medium"),
        ("LOW", "low"),
        (None, None),
    ],
)
def test_priority_from_label(label, expected):
    assert priority_from_label(label) == expected


def test_summary_of_prefers_the_summary():
    record = {"summary": "  Short text  ", "details": "Long text"}

    assert summary_of(record) == "Short text"


def test_summary_of_uses_first_line_of_details():
    assert summary_of(PYSEC_RECORD) == "Requests leaks credentials on redirect"


def test_summary_of_shortens_a_very_long_line():
    summary = summary_of({"details": "x" * 500})

    assert len(summary) == 200
    assert summary.endswith("...")


@pytest.mark.parametrize(
    "record",
    [{}, {"summary": "  "}, {"details": "   \n  "}, {"details": 5}],
)
def test_summary_of_without_text(record):
    assert summary_of(record) is None


def test_reference_urls_skips_entries_without_an_address():
    record = {
        "references": [
            {"type": "ADVISORY", "url": "https://example.com/a"},
            {"type": "WEB"},
            "oops",
            {"url": 5},
        ]
    }

    assert reference_urls(record) == ["https://example.com/a"]


@pytest.mark.parametrize("record", [{}, {"references": "oops"}])
def test_reference_urls_without_a_list(record):
    assert reference_urls(record) == []


@pytest.mark.parametrize(
    ("ecosystem", "name", "expected"),
    [
        ("PyPI", "Zope_Interface", "zope-interface"),
        ("PyPI", "zope.interface", "zope-interface"),
        ("npm", "@Babel/Core", "@babel/core"),
        ("Maven", "org.example:Lib", "org.example:lib"),
    ],
)
def test_normalize_name(ecosystem, name, expected):
    assert normalize_name(ecosystem, name) == expected


def test_fixed_versions_ignores_git_ranges_and_matches_spelling():
    assert fixed_versions(PYSEC_RECORD, "PyPI", "Requests") == ["2.20.0"]


def test_fixed_versions_collects_every_branch_once():
    record = {
        "affected": [
            {
                "package": {"name": "django", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "3.0"},
                            {"fixed": "3.2.5"},
                            {"introduced": "4.0"},
                            {"fixed": "4.2.1"},
                        ],
                    }
                ],
            },
            {
                "package": {"name": "django", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"fixed": "4.2.1"}]},
                ],
            },
        ]
    }

    assert fixed_versions(record, "PyPI", "django") == ["3.2.5", "4.2.1"]


def test_fixed_versions_ignores_other_packages_and_ecosystems():
    assert fixed_versions(PYSEC_RECORD, "PyPI", "urllib3") == []
    assert fixed_versions(PYSEC_RECORD, "npm", "requests") == []


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"affected": "oops"},
        {"affected": ["oops"]},
        {"affected": [{"package": "oops"}]},
        {"affected": [{"package": {"name": 1, "ecosystem": "PyPI"}}]},
        {"affected": [{"package": {"name": "x", "ecosystem": "PyPI"}}]},
        {
            "affected": [
                {
                    "package": {"name": "x", "ecosystem": "PyPI"},
                    "ranges": ["oops", {"type": "ECOSYSTEM", "events": "oops"}],
                }
            ]
        },
    ],
)
def test_fixed_versions_survives_unexpected_shapes(record):
    assert fixed_versions(record, "PyPI", "x") == []
