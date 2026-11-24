"""Read-only checks for the additive confirmation history extension."""

from sqlalchemy import text


def verify_technology_cpe_schema(connection):
    if not connection.scalar(
        text("""SELECT
        c.relrowsecurity AND c.relforcerowsecurity
        AND pg_get_userbyid(c.relowner)<>'vulntrack_app'
        AND has_table_privilege('vulntrack_app',c.oid,'SELECT')
        AND has_table_privilege('vulntrack_app',c.oid,'INSERT')
        AND NOT has_table_privilege('vulntrack_app',c.oid,'UPDATE,DELETE,TRUNCATE')
        AND (SELECT count(*)=2 FROM pg_policies
            WHERE schemaname='vulntrack_technology_cpe' AND tablename='confirmations')
        AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=c.oid
            AND tgname='confirmation_guard' AND tgenabled='O')
        FROM pg_class c WHERE c.oid=to_regclass('vulntrack_technology_cpe.confirmations')
    """)
    ):
        raise RuntimeError("Technology CPE history schema/privileges are incomplete")
    return True
