"""Route bounded official reads to an optional least-privilege PostgreSQL source."""

from contextlib import contextmanager

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

from app.core.errors import APIError

# Test the grants using the login itself. Ignore PostgreSQL's system metadata schemas.
ACCESS = """
SELECT current_setting('transaction_read_only') = 'on'
 AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
 AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member=r.oid)
 AND NOT has_database_privilege(current_user,current_database(),'CREATE')
 AND has_schema_privilege(current_user,'vulntrack_catalog','USAGE')
 AND has_table_privilege(current_user,'vulntrack_catalog.products','SELECT')
 AND has_table_privilege(current_user,'vulntrack_catalog.summary','SELECT')
 AND has_table_privilege(current_user,'vulntrack_catalog.sync_runs','SELECT')
 AND has_table_privilege(current_user,'vulntrack_catalog.feed_imports','SELECT')
 AND NOT EXISTS (
    SELECT 1 FROM pg_namespace n
    WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
    AND (has_schema_privilege(current_user,n.oid,'CREATE') OR
      (n.nspname LIKE 'vulntrack%' AND n.nspname <> 'vulntrack_catalog'
       AND has_schema_privilege(current_user,n.oid,'USAGE')))
 )
 AND NOT EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
      AND c.relkind IN ('r','p','v','m','f')
      AND has_schema_privilege(current_user,n.oid,'USAGE')
      AND (
        has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
        OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')
        OR (has_any_column_privilege(current_user,c.oid,'SELECT')
           AND NOT (n.nspname='vulntrack_catalog'
                    AND c.relname IN ('products','summary','sync_runs','feed_imports')))
      )
 )
FROM pg_roles r WHERE r.rolname=current_user
"""


class InvalidCatalogRole(RuntimeError):
    pass


def readonly_engine(secret):
    try:
        url = make_url(secret.get_secret_value())
        if (
            url.drivername != "postgresql+psycopg"
            or url.host not in {"127.0.0.1", "::1"}
            or not (url.port and url.database and url.username and url.password)
            or url.query
        ):
            raise ValueError
    except (SQLAlchemyError, ValueError):
        raise ValueError("External catalog requires a dedicated PostgreSQL loopback URL") from None
    engine = create_engine(
        url,
        hide_parameters=True,
        pool_size=3,
        max_overflow=0,
        pool_timeout=1,
        pool_recycle=60,
        pool_pre_ping=True,
        connect_args={
            "connect_timeout": 2,
            "options": "-c default_transaction_read_only=on -c statement_timeout=2000"
            " -c lock_timeout=500",
        },
    )

    @event.listens_for(engine, "connect")
    def verify_role(dbapi, _):
        try:
            with dbapi.cursor() as cursor:
                cursor.execute(ACCESS)
                if cursor.fetchone() != (True,):
                    raise InvalidCatalogRole
        finally:
            dbapi.rollback()

    return engine


class CatalogReader:
    def __init__(self, local, external_url=None):
        self.local = local
        self.external = readonly_engine(external_url) if external_url else None

    def is_external(self, mode):
        return mode == "live" and self.external is not None

    @contextmanager
    def connect(self, mode):
        external = self.is_external(mode)
        engine = self.external if external else self.local
        try:
            with engine.connect() as connection:
                if external:
                    connection.execute(text("SET TRANSACTION READ ONLY"))
                connection.execute(text("SET LOCAL statement_timeout=2000"))
                yield connection
        except (SQLAlchemyError, InvalidCatalogRole):
            raise APIError(
                503,
                "CATALOG_SOURCE_UNAVAILABLE",
                "No se pudo consultar esta fuente del catálogo. Reintenta.",
            ) from None

    def close(self):
        if self.external is not None:
            self.external.dispose()
