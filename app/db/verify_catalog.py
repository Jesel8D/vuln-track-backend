"""Validate the privileges and schema needed for the RC2.2 catalog."""

from sqlalchemy import text


def verify_catalog_schema(connection):
    ready = connection.scalar(
        text("""
        SELECT has_table_privilege('vulntrack_app','vulntrack_catalog.products','SELECT')
           AND NOT has_table_privilege('vulntrack_app','vulntrack_catalog.products',
                                       'INSERT,UPDATE,DELETE,TRUNCATE')
           AND NOT has_table_privilege('vulntrack_app','vulntrack_catalog.sync_runs',
                                       'INSERT,UPDATE,DELETE')
           AND to_regclass('vulntrack_catalog.sync_pages') IS NOT NULL
           AND to_regclass('vulntrack_catalog.catalog_search_idx') IS NOT NULL
           AND (SELECT relforcerowsecurity FROM pg_class
                WHERE oid='vulntrack_catalog_private.device_registrations'::regclass)
        """)
    )
    if not ready:
        raise RuntimeError("RC2.2 catalog schema or privileges are incomplete")
