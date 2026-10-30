"""Read-only compatibility check. Catalog snapshot derives from the upstream SQL, not ORM."""

import argparse
import json
from importlib.resources import files

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import CheckConstraint, inspect, text
from sqlalchemy.dialects import postgresql

from app.db.base import Base
from app.models import database_v1  # noqa: F401

V1_REVISION = "0001_database_v1"
OWNERSHIP_REVISION = "0002_asset_owner"

QUERIES = {
    "columns": """
        SELECT c.relname AS table_name, a.attname AS column_name,
               format_type(a.atttypid,a.atttypmod) AS type, a.attnotnull AS not_null,
               pg_get_expr(d.adbin,d.adrelid) AS default
        FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
        WHERE n.nspname='vulntrack' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
        ORDER BY c.relname,a.attname
    """,
    "constraints": """
        SELECT c.relname AS table_name, co.conname AS name, co.contype AS type,
               pg_get_constraintdef(co.oid) AS definition
        FROM pg_constraint co JOIN pg_class c ON c.oid=co.conrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='vulntrack'
        ORDER BY c.relname,co.conname
    """,
    "indexes": """
        SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname='vulntrack'
        ORDER BY tablename,indexname
    """,
    "triggers": """
        SELECT c.relname AS table_name,t.tgname AS name,pg_get_triggerdef(t.oid) AS definition
        FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='vulntrack' AND NOT t.tgisinternal ORDER BY c.relname,t.tgname
    """,
    "functions": """
        SELECT p.proname AS name,pg_get_functiondef(p.oid) AS definition
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='vulntrack' ORDER BY p.proname
    """,
    "tables": """
        SELECT c.relname AS name,c.relrowsecurity AS row_security,
               c.relforcerowsecurity AS force_row_security
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='vulntrack' AND c.relkind='r' ORDER BY c.relname
    """,
}


def catalog(connection):
    return {
        key: [dict(row) for row in connection.execute(text(query)).mappings()]
        for key, query in QUERIES.items()
    }


def expected_catalog(revision):
    expected = json.loads(files("app.db").joinpath("database_v1_catalog.json").read_text())
    if revision == OWNERSHIP_REVISION:
        expected["columns"].append(
            {
                "table_name": "assets",
                "column_name": "created_by",
                "type": "uuid",
                "not_null": False,
                "default": None,
            }
        )
        expected["columns"].sort(key=lambda row: (row["table_name"], row["column_name"]))
        expected["constraints"].append(
            {
                "table_name": "assets",
                "name": "assets_created_by_fkey",
                "type": "f",
                "definition": (
                    "FOREIGN KEY (created_by) REFERENCES vulntrack.users(id) ON DELETE RESTRICT"
                ),
            }
        )
        expected["constraints"].sort(key=lambda row: (row["table_name"], row["name"]))
        expected["indexes"].append(
            {
                "tablename": "assets",
                "indexname": "assets_owner_created_id_idx",
                "indexdef": "CREATE INDEX assets_owner_created_id_idx ON vulntrack.assets "
                "USING btree (created_by, created_at, id)",
            }
        )
        expected["indexes"].sort(key=lambda row: (row["tablename"], row["indexname"]))
    elif revision != V1_REVISION:
        raise RuntimeError("Revisión de esquema desconocida; operación bloqueada")
    return expected


def installed_revision(connection):
    heads = MigrationContext.configure(connection).get_current_heads()
    if len(heads) > 1 or (heads and heads[0] not in {V1_REVISION, OWNERSHIP_REVISION}):
        raise RuntimeError("Revisión Alembic desconocida o múltiple; operación bloqueada")
    return heads[0] if heads else None


def verify_schema(connection, revision=OWNERSHIP_REVISION):
    expected = expected_catalog(revision)
    actual = catalog(connection)
    differences = [key for key in expected if actual[key] != expected[key]]
    if differences:
        raise RuntimeError("Baseline bloqueado: difiere catálogo " + ", ".join(differences))
    if revision == V1_REVISION:
        # The immutable upstream catalog validates legacy V1 independently of head ORM.
        return True
    inspector = inspect(connection)
    for table in Base.metadata.sorted_tables:
        columns = {c["name"]: c for c in inspector.get_columns(table.name, schema="vulntrack")}
        if set(columns) != set(table.columns.keys()):
            raise RuntimeError(f"Columnas ORM incompatibles: {table.name}")
        for col in table.columns:
            reflected = columns[col.name]
            if (
                str(col.type.compile(dialect=postgresql.dialect()))
                != str(reflected["type"].compile(dialect=postgresql.dialect()))
                or col.nullable != reflected["nullable"]
            ):
                raise RuntimeError(f"Tipo/nulabilidad ORM incompatible: {table.name}.{col.name}")
        pk = inspector.get_pk_constraint(table.name, schema="vulntrack")
        if list(table.primary_key.columns.keys()) != pk["constrained_columns"]:
            raise RuntimeError(f"PK ORM incompatible: {table.name}")
        foreign_keys = {
            (
                tuple(fk["constrained_columns"]),
                fk["referred_schema"],
                fk["referred_table"],
                tuple(fk["referred_columns"]),
                fk["options"].get("ondelete"),
            )
            for fk in inspector.get_foreign_keys(table.name, schema="vulntrack")
        }
        mapped_keys = {
            (
                tuple(fk.column_keys),
                next(iter(fk.elements)).column.table.schema,
                next(iter(fk.elements)).column.table.name,
                tuple(e.column.name for e in fk.elements),
                fk.ondelete,
            )
            for fk in table.foreign_key_constraints
        }
        if foreign_keys != mapped_keys:
            raise RuntimeError(f"FK ORM incompatible: {table.name}")
        checks = {
            c["name"]: c["sqltext"]
            for c in inspector.get_check_constraints(table.name, schema="vulntrack")
        }
        mapped_checks = {
            c.name: str(c.sqltext) for c in table.constraints if isinstance(c, CheckConstraint)
        }
        if checks.keys() != mapped_checks.keys():
            raise RuntimeError(f"CHECK ORM faltante: {table.name}")
        for name, expression in mapped_checks.items():
            if expression_plan(connection, table.name, expression) != expression_plan(
                connection, table.name, checks[name]
            ):
                raise RuntimeError(f"CHECK ORM incompatible: {table.name}.{name}")
    comparison = MigrationContext.configure(
        connection,
        opts={
            "include_schemas": True,
            "compare_type": True,
            "compare_server_default": True,
            "include_name": lambda name, type_, parent: (
                name == "vulntrack" if type_ == "schema" else True
            ),
        },
    )
    if compare_metadata(comparison, Base.metadata):
        raise RuntimeError(
            "Baseline bloqueado: diferencias ORM en índices/UNIQUE/defaults/estructura"
        )
    return True


def expression_plan(connection, table, expression):
    # Only SQL from the trusted ORM/catalog, never user input. No ANALYZE, no writes.
    return connection.execute(
        text(
            f"EXPLAIN (VERBOSE, FORMAT JSON, COSTS OFF) SELECT ({expression}) "
            f"FROM vulntrack.{table}"
        )
    ).scalar_one()[0]["Plan"]["Output"]


if __name__ == "__main__":
    from app.core.config import get_settings
    from app.db.session import build_engine

    parser = argparse.ArgumentParser(description="Verificación de esquema solo lectura")
    parser.add_argument(
        "--revision", choices=[V1_REVISION, OWNERSHIP_REVISION], default=OWNERSHIP_REVISION
    )
    args = parser.parse_args()
    engine = build_engine(get_settings())
    try:
        with engine.connect() as connection:
            verify_schema(connection, args.revision)
        print(f"Esquema {args.revision}: compatible (solo lectura).")
    finally:
        engine.dispose()
