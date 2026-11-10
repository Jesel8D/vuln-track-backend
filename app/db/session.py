import psycopg
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.core.config import Settings


def build_engine(settings: Settings):
    engine = create_engine(
        settings.database_url.get_secret_value(),
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout,
        pool_recycle=settings.db_pool_recycle,
        pool_pre_ping=settings.db_pool_pre_ping,
        hide_parameters=True,
        connect_args={
            "connect_timeout": settings.db_connect_timeout,
            "options": (
                f"-c statement_timeout={settings.db_statement_timeout_ms} "
                f"-c lock_timeout={settings.db_lock_timeout_ms} "
                "-c idle_in_transaction_session_timeout=15000 -c timezone=UTC"
            ),
        },
    )

    @event.listens_for(engine, "connect")
    def reject_administrative_role(dbapi_connection, connection_record):
        with dbapi_connection.cursor() as cursor:
            cursor.execute(
                "SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls "
                "OR pg_has_role(current_user, nspowner, 'USAGE') "
                "FROM pg_roles JOIN pg_namespace ON nspname='vulntrack' "
                "WHERE rolname=current_user"
            )
            row = cursor.fetchone()
            if not row or row[0]:
                dbapi_connection.close()
                raise psycopg.OperationalError("Unsafe application role")
        dbapi_connection.rollback()

    return engine


def build_session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
