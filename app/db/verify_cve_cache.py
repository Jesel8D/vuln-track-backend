"""Read-only exact cache catalog/ACL verification, including both private run links."""

import json
from importlib.resources import files

from sqlalchemy import text

from app.db.verify_schema import QUERIES


def cache_catalog(connection):
    result = {}
    for category, query in QUERIES.items():
        query = query.replace("'vulntrack'", "'vulntrack_cve_cache'")
        result[category] = [dict(row) for row in connection.execute(text(query)).mappings()]
    result["policies"] = [
        dict(row)
        for row in connection.execute(
            text("""SELECT tablename,
        policyname,permissive,roles,cmd,qual,with_check FROM pg_policies
        WHERE schemaname='vulntrack_cve_cache' ORDER BY tablename,policyname""")
        ).mappings()
    ]
    return result


def verify_cve_cache_schema(connection):
    expected = json.loads(files("app.db").joinpath("cve_cache_catalog.json").read_text())
    if cache_catalog(connection) != expected:
        raise RuntimeError("CVE cache exact catalog differs")
    if not connection.scalar(
        text("""SELECT
        (SELECT count(*)=4 FROM information_schema.columns
          WHERE (table_schema,table_name) IN
            (('vulntrack','application_analysis_runs'),('vulntrack_devices','runs'))
          AND column_name IN ('cache_response_id','cache_usage'))
        AND (SELECT count(*)=2 FROM pg_trigger WHERE tgname='cache_run_guard'
          AND tgenabled='O' AND NOT tgisinternal)
        AND has_table_privilege('vulntrack_app','vulntrack_cve_cache.responses','SELECT')
        AND has_table_privilege('vulntrack_app','vulntrack_cve_cache.responses','INSERT')
        AND NOT has_table_privilege('vulntrack_app',
          'vulntrack_cve_cache.responses','UPDATE,DELETE,TRUNCATE')
        AND NOT has_table_privilege('vulntrack_app','vulntrack_cve_cache.slots','DELETE,TRUNCATE')
        AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='vulntrack_cve_cache' AND
            (p.prosecdef OR EXISTS(SELECT 1 FROM aclexplode(p.proacl) WHERE grantee=0)))
    """)
    ):
        raise RuntimeError("CVE cache private references/privileges differ")
    return True
