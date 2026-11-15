"""Exact SQL008 catalog and role/grant verification, separate from V1/V2 baseline."""

import json
from importlib.resources import files

from sqlalchemy import inspect, text
from sqlalchemy.dialects import postgresql

SCHEMA = "vulntrack_verification"
QUERIES = {
    "columns": """SELECT c.relname AS table_name,a.attname AS column_name,
        format_type(a.atttypid,a.atttypmod) AS type,a.attnotnull AS not_null,
        pg_get_expr(d.adbin,d.adrelid) AS default FROM pg_attribute a
        JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
        WHERE n.nspname='vulntrack_verification' AND c.relkind='r' AND a.attnum>0
        AND NOT a.attisdropped ORDER BY c.relname,a.attname""",
    "constraints": """SELECT c.relname AS table_name,co.conname AS name,co.contype AS type,
        pg_get_constraintdef(co.oid) AS definition FROM pg_constraint co
        JOIN pg_class c ON c.oid=co.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='vulntrack_verification' ORDER BY c.relname,co.conname""",
    "tables": """SELECT c.relname AS name,c.relrowsecurity AS rls,
        c.relforcerowsecurity AS force_rls,
        pg_get_userbyid(c.relowner) AS owner FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='vulntrack_verification'
        AND c.relkind='r' ORDER BY c.relname""",
    "policies": """SELECT tablename,policyname,permissive,roles,cmd,qual,with_check
        FROM pg_policies WHERE schemaname='vulntrack_verification' ORDER BY tablename,policyname""",
    "functions": """SELECT p.proname AS name,pg_get_functiondef(p.oid) AS definition,
        pg_get_userbyid(p.proowner) AS owner,p.prosecdef AS security_definer,
        p.proconfig AS config,p.proacl::text AS acl FROM pg_proc p JOIN pg_namespace n
        ON n.oid=p.pronamespace WHERE n.nspname='vulntrack_verification'
        ORDER BY p.proname""",
    "indexes": """SELECT tablename,indexname,indexdef FROM pg_indexes
        WHERE schemaname='vulntrack_verification' ORDER BY tablename,indexname""",
    "triggers": """SELECT c.relname AS table_name,t.tgname AS name,
        pg_get_triggerdef(t.oid) AS definition,t.tgenabled::text AS enabled
        FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n
        ON n.oid=c.relnamespace WHERE n.nspname='vulntrack_verification' AND NOT t.tgisinternal
        ORDER BY c.relname,t.tgname""",
    "column_grants": """SELECT table_name,column_name,grantee,privilege_type
        FROM information_schema.column_privileges WHERE table_schema='vulntrack_verification'
        ORDER BY table_name,column_name,grantee,privilege_type""",
    "table_grants": """SELECT table_name,grantee,privilege_type
        FROM information_schema.table_privileges WHERE table_schema='vulntrack_verification'
        ORDER BY table_name,grantee,privilege_type""",
    "roles": """SELECT rolname,rolsuper,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,
        rolbypassrls FROM pg_roles WHERE rolname IN
        ('vulntrack_verification_owner','vulntrack_verification_lab') ORDER BY rolname""",
    "memberships": """SELECT r.rolname AS role,m.rolname AS member FROM pg_auth_members a
        JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member
        WHERE r.rolname='vulntrack_verification_owner'
        OR (r.rolname='vulntrack_verification_lab' AND (m.rolname='vulntrack_registration'
            OR pg_has_role(m.rolname,'vulntrack_app','MEMBER'))) ORDER BY role,member""",
    "schema_acl": """SELECT nspname,pg_get_userbyid(nspowner) AS owner,nspacl::text AS acl
        FROM pg_namespace WHERE nspname='vulntrack_verification'""",
    "default_acl": """SELECT d.defaclobjtype AS type,d.defaclacl::text AS acl
        FROM pg_default_acl d JOIN pg_namespace n ON n.oid=d.defaclnamespace
        WHERE n.nspname='vulntrack_verification' ORDER BY d.defaclobjtype""",
}


def catalog(connection):
    return {
        key: [dict(row) for row in connection.execute(text(query)).mappings()]
        for key, query in QUERIES.items()
    }


def verify_verification_schema(connection):
    expected = json.loads(files("app.db").joinpath("verification_catalog.json").read_text())
    actual = catalog(connection)
    differences = [key for key in expected if expected[key] != actual[key]]
    if differences:
        raise RuntimeError("SQL008 verification drift: " + ", ".join(differences))
    from app.models.verification import VerificationBase

    inspector = inspect(connection)
    for table in VerificationBase.metadata.sorted_tables:
        columns = {
            column["name"]: column for column in inspector.get_columns(table.name, schema=SCHEMA)
        }
        if set(columns) != set(table.columns.keys()):
            raise RuntimeError("SQL008 ORM column drift")
        for column in table.columns:
            actual_column = columns[column.name]
            if (
                str(column.type.compile(dialect=postgresql.dialect()))
                != str(actual_column["type"].compile(dialect=postgresql.dialect()))
                or column.nullable != actual_column["nullable"]
            ):
                raise RuntimeError("SQL008 ORM type/nullability drift")
    return True
