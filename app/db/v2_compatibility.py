"""Exact additive V2 catalog verification; never ignore unknown schema objects."""

import json
from importlib.resources import files

from sqlalchemy import text

POLICIES = """
    SELECT tablename,policyname,permissive,roles,cmd,qual,with_check
    FROM pg_policies WHERE schemaname='vulntrack' ORDER BY tablename,policyname
"""
FIELDS = {
    "columns": "table_name",
    "constraints": "table_name",
    "indexes": "tablename",
    "triggers": "table_name",
    "tables": "name",
    "functions": "name",
}


def without_verified_v2(connection, actual):
    if not any(row["name"] == "workspaces" for row in actual["tables"]):
        return actual
    reference = json.loads(files("app.db").joinpath("v2_additions_catalog.json").read_text())
    tables = {row["name"] for row in reference["tables"]}
    functions = {row["name"] for row in reference["functions"]}
    core = {}
    for category, field in FIELDS.items():
        names = functions if category == "functions" else tables
        extension = [row for row in actual[category] if row[field] in names]
        if extension != reference[category]:
            raise RuntimeError("Catálogo V2 incompatible: " + category)
        core[category] = [row for row in actual[category] if row[field] not in names]
    policies = [dict(row) for row in connection.execute(text(POLICIES)).mappings()]
    if policies != reference["policies"]:
        raise RuntimeError("Políticas RLS V2 incompatibles")
    return core
