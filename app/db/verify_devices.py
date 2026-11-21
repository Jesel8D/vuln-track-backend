"""Refuse to serve RC2 on an incomplete devices schema."""

from sqlalchemy import text

TABLES = {"devices", "identifications", "runs", "findings", "recommendations"}


def verify_devices_schema(connection):
    rows = connection.execute(
        text("""
        SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
               has_table_privilege('vulntrack_app', c.oid, 'SELECT'),
               has_table_privilege('vulntrack_app', c.oid, 'INSERT'),
               has_table_privilege('vulntrack_app', c.oid, 'DELETE,TRUNCATE,TRIGGER')
        FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid
        WHERE n.nspname='vulntrack_devices' AND c.relkind='r'
    """)
    ).all()
    if {row[0] for row in rows} != TABLES or any(
        tuple(row[1:]) != (True, True, True, True, False) for row in rows
    ):
        raise RuntimeError("RC2 devices schema or privileges are incomplete")
    policies = connection.execute(
        text("""
        SELECT tablename, policyname, cmd FROM pg_policies WHERE schemaname='vulntrack_devices'
    """)
    ).all()
    expected = {
        (table, name, cmd)
        for table in TABLES
        for name, cmd in (("scoped_read", "SELECT"), ("scoped_insert", "INSERT"))
    }
    expected.update((table, "scoped_update", "UPDATE") for table in {"devices", "runs", "findings"})
    if set(policies) != expected:
        raise RuntimeError("RC2 devices policies do not match")
