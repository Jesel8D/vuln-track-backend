"""Deliberately partial CPE evaluator, version 1. Never confirms a vulnerability.

Supports positive, unnested OR-only configurations and literal component equality
with ANY criteria. No ordering is inferred for vendor versions. AND, negation,
embedded wildcards, ranges, unknown target attributes and other products need review.
Automatic exclusion is not published: not_applicable is a human decision in this MVP.
"""

import hashlib
import json
import re

from app.schemas.cpe import parse_cpe, unbind_component

RULE_VERSION = "cpe-conservative-1"


def literal(value):
    return not re.search(r"(?<!\\)[*?]", value) and value != "-"


def specific_cpe(name, observed):
    parts = parse_cpe(name)
    return (
        observed is not None
        and parts[0] in {"o", "a"}
        and all(literal(p) for p in parts[1:4])
        and unbind_component(parts[3]).casefold() == observed.casefold()
    )


def evaluate(cpe, observed, record):
    """Return applicability and reproducible rule codes; missing != disproven."""
    if record.get("vulnStatus") == "Rejected":
        return "undetermined", ["CVE_REJECTED"]
    try:
        target = parse_cpe(cpe)
    except ValueError:
        return "undetermined", ["UNSUPPORTED_CPE"]
    if not observed or not literal(target[3]):
        return "undetermined", ["VERSION_UNKNOWN"]
    if unbind_component(target[3]).casefold() != observed.casefold():
        return "undetermined", ["OBSERVED_VERSION_MISMATCH"]
    configurations = record.get("configurations")
    if not isinstance(configurations, list) or not configurations:
        return "undetermined", ["CONFIGURATIONS_MISSING"]
    supported_match = False
    warnings = set()
    # Every configuration is preserved; do not discard unknown predicates to make a match.
    for config in configurations:
        if not isinstance(config, dict) or set(config) - {"operator", "negate", "nodes"}:
            warnings.add("UNSUPPORTED_EXPRESSION")
            continue
        if config.get("negate", False) or config.get("operator", "OR") != "OR":
            warnings.add("COMPLEX_CONFIGURATION")
            continue
        nodes = config.get("nodes")
        if not isinstance(nodes, list) or not nodes:
            warnings.add("CONFIGURATIONS_MISSING")
            continue
        if len(nodes) > 1 and "operator" not in config:
            warnings.add("COMPLEX_CONFIGURATION")
            continue
        for node in nodes:
            if (
                not isinstance(node, dict)
                or node.get("operator") != "OR"
                or node.get("negate", False)
                or set(node) - {"operator", "negate", "cpeMatch"}
            ):
                warnings.add("COMPLEX_CONFIGURATION")
                continue
            matches = node.get("cpeMatch")
            if not isinstance(matches, list) or not matches:
                warnings.add("CONFIGURATIONS_MISSING")
                continue
            for match in matches:
                if not isinstance(match, dict) or match.get("vulnerable") is not True:
                    warnings.add("ENVIRONMENT_CONDITION")
                    continue
                if set(match) - {"vulnerable", "criteria", "matchCriteriaId"}:
                    warnings.add("VERSION_RANGE_OR_UNSUPPORTED_CRITERION")
                    continue
                try:
                    criterion = parse_cpe(match["criteria"])
                except (KeyError, ValueError):
                    warnings.add("UNSUPPORTED_CPE")
                    continue
                compatible = True
                for expected, actual in zip(criterion, target, strict=True):
                    if expected == "*":
                        continue
                    if actual == "*" or (expected != "-" and not literal(expected)):
                        compatible = False
                        warnings.add("ATTRIBUTE_UNKNOWN_OR_PATTERN")
                        break
                    if unbind_component(expected).casefold() != unbind_component(actual).casefold():
                        compatible = False
                        warnings.add("CRITERION_MISMATCH")
                        break
                supported_match |= compatible
    if supported_match:
        return "potential", ["POSITIVE_OR_LITERAL_MATCH"]
    return "undetermined", sorted(warnings or {"INSUFFICIENT_EVIDENCE"})[:15]


def encoded(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def evidence_for(cpe, observed, record):
    applicability, rules = evaluate(cpe, observed, record)
    evidence = {
        "initial_applicability": applicability,
        "evaluator": RULE_VERSION,
        "rule_codes": rules,
        "selected_cpe": cpe,
        "observed_version": observed,
        "source": "NVD",
        "cve_id": record["id"],
        "vulnStatus": record["vulnStatus"],
        "published": record["published"],
        "lastModified": record["lastModified"],
        "descriptions": record.get("descriptions", []),
        "references": record.get("references", []),
        "configurations": record.get("configurations", []),
        "source_record_sha256": hashlib.sha256(encoded(record)).hexdigest(),
        "truncated": False,
    }
    # Leave generous room for JSONB whitespace/escaping; never trim expressions and
    # then evaluate the trimmed expression as though it were the original.
    if len(encoded(evidence)) > 24000:
        evidence = {
            k: v
            for k, v in evidence.items()
            if k not in {"descriptions", "references", "configurations"}
        }
        evidence.update(
            initial_applicability="undetermined",
            truncated=True,
            rule_codes=["EVIDENCE_BUDGET_REACHED"],
        )
        applicability = "undetermined"
    return applicability, evidence
