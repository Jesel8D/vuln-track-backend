"""Serialize cooperating migration/adoption tools; never substitutes a maintenance window."""

from sqlalchemy import text


def lock_schema_operation(connection):
    connection.execute(text("SELECT pg_advisory_xact_lock(hashtext('vulntrack:schema'))"))
