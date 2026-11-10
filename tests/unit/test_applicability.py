from copy import deepcopy

import pytest

from app.services.applicability import encoded, evaluate, evidence_for, specific_cpe
from tests.cve_support import CPE, RECORD, response_page


def simple():
    return response_page(simple=True)["vulnerabilities"][0]["cve"]


def match(record):
    return record["configurations"][0]["nodes"][0]["cpeMatch"][0]


def test_positive_literal_or_is_only_potential():
    result, codes = evaluate(CPE, "1.0.0.33", simple())
    assert result == "potential" and codes == ["POSITIVE_OR_LITERAL_MATCH"]


def test_verified_and_firmware_hardware_is_undetermined():
    result, codes = evaluate(CPE, "1.0.0.33", RECORD)
    assert result == "undetermined" and "COMPLEX_CONFIGURATION" in codes


@pytest.mark.parametrize(
    "criterion",
    [
        CPE.replace("cisco", "other_vendor"),
        CPE.replace("rv340", "rv345"),
        CPE.replace("1.0.0.33", "1.0.0.30"),
        CPE.replace(":*:*:*:*:*:*:*", ":enterprise:*:*:*:*:*:*"),
    ],
)
def test_incompatible_or_variant_does_not_prove_absence(criterion):
    record = simple()
    match(record)["criteria"] = criterion
    assert evaluate(CPE, "1.0.0.33", record)[0] == "undetermined"


@pytest.mark.parametrize("observed", [None, ""])
def test_unknown_version(observed):
    assert evaluate(CPE, observed, simple())[0] == "undetermined"


@pytest.mark.parametrize(
    "bound,value",
    [
        ("versionStartIncluding", "1.0.0.1"),
        ("versionEndIncluding", "1.0.0.33"),
        ("versionEndExcluding", "1.0.0.33"),
        ("versionStartExcluding", "1.0.0.40"),
        ("versionStartIncluding", "1.0.0.33-release"),
        ("versionEndIncluding", "1.0.0.5"),
    ],
)
def test_ranges_inside_outside_inclusive_exclusive_remain_explicitly_unsupported(bound, value):
    record = simple()
    match(record)["criteria"] = CPE.replace("1.0.0.33", "*")
    match(record)[bound] = value
    result, codes = evaluate(CPE, "1.0.0.33", record)
    assert result == "undetermined" and "VERSION_RANGE_OR_UNSUPPORTED_CRITERION" in codes


def test_suffix_equality_requires_no_ordering():
    cpe = CPE.replace("1.0.0.33", "1.0.0.33-release")
    record = simple()
    match(record)["criteria"] = cpe
    assert evaluate(cpe, "1.0.0.33-release", record)[0] == "potential"
    assert specific_cpe(cpe, "1.0.0.33-release")


@pytest.mark.parametrize(
    "change", ["and", "negate", "environment", "missing", "unknown_attribute", "pattern", "child"]
)
def test_complex_and_missing_data(change):
    record = simple()
    config = record["configurations"][0]
    if change == "and":
        config["operator"] = "AND"
    elif change == "negate":
        config["nodes"][0]["negate"] = True
    elif change == "environment":
        match(record)["vulnerable"] = False
    elif change == "missing":
        record.pop("configurations")
    elif change == "unknown_attribute":
        match(record)["criteria"] = CPE.replace(":*:*:*:*:*:*:*", ":platform:*:*:*:*:*:*")
    elif change == "pattern":
        match(record)["criteria"] = CPE.replace("rv340", "rv34*")
    else:
        config["nodes"][0]["children"] = [{"operator": "OR"}]
    assert evaluate(CPE, "1.0.0.33", record)[0] == "undetermined"


def test_or_alternative_can_match_without_discarding_unknown_and():
    record = deepcopy(RECORD)
    record["configurations"].extend(simple()["configurations"])
    assert evaluate(CPE, "1.0.0.33", record)[0] == "potential"
    assert record["configurations"][0]["operator"] == "AND"


def test_evidence_preserves_original_and_never_mutates_record():
    record = deepcopy(RECORD)
    result, evidence = evidence_for(CPE, "1.0.0.33", record)
    assert record == RECORD and result == "undetermined"
    assert evidence["configurations"] == RECORD["configurations"]
    assert evidence["lastModified"] == RECORD["lastModified"]
    assert evidence["initial_applicability"] == result and not evidence["truncated"]
    assert len(encoded(evidence)) < 24000


def test_budget_never_evaluates_a_truncated_expression_as_potential():
    record = simple()
    record["descriptions"] = [{"lang": "en", "value": "x" * 70000}]
    result, evidence = evidence_for(CPE, "1.0.0.33", record)
    assert result == "undetermined" and evidence["truncated"]
    assert evidence["rule_codes"] == ["EVIDENCE_BUDGET_REACHED"]
    assert len(evidence["source_record_sha256"]) == 64


def test_rejected_never_potential_and_hardware_is_not_firmware():
    record = simple() | {"vulnStatus": "Rejected"}
    assert evaluate(CPE, "1.0.0.33", record)[0] == "undetermined"
    assert not specific_cpe(CPE.replace(":o:", ":h:"), "1.0.0.33")
    assert not specific_cpe(CPE, None)


def test_observed_version_cannot_disagree_with_selected_cpe():
    result, codes = evaluate(CPE, "2.0", simple())
    assert result == "undetermined" and codes == ["OBSERVED_VERSION_MISMATCH"]
