"""Read-only validation of the additive V2 reliability boundary."""

from sqlalchemy import text


def verify_cve_reliability_schema(connection):
    if not connection.scalar(
        text("""SELECT
        (SELECT count(*)=6 FROM information_schema.columns
          WHERE (table_schema,table_name) IN
            (('vulntrack','application_analysis_runs'),('vulntrack_devices','runs'))
          AND column_name IN ('run_context','lease_expires_at','response_received_at'))
        AND (SELECT count(*)=2 FROM pg_trigger WHERE tgname='cve_reliability_guard'
          AND tgenabled='O' AND NOT tgisinternal)
        AND EXISTS(SELECT 1 FROM pg_proc WHERE oid='vulntrack.recover_cve_runs()'::regprocedure
          AND prosecdef AND proconfig=ARRAY['search_path=pg_catalog']
          AND NOT EXISTS (SELECT 1 FROM aclexplode(proacl) WHERE grantee=0))
        AND has_function_privilege('vulntrack_app','vulntrack.recover_cve_runs()','EXECUTE')
    """)
    ):
        raise RuntimeError("CVE reliability schema/privileges are incomplete")
    return True
