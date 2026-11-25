import pytest
from pydantic import SecretStr

from app.services.catalog_reader import readonly_engine


def test_private_catalog_requires_verified_tls():
    engine = readonly_engine(
        SecretStr(
            "postgresql+psycopg://reader:synthetic@catalog:5432/vulntrack?sslmode=verify-full&sslrootcert=/run/tls/ca.crt"
        )
    )
    assert engine.url.host == "catalog"
    assert engine.url.query["sslmode"] == "verify-full"
    engine.dispose()


@pytest.mark.parametrize(
    "authority,query",
    [
        ("catalog:5432", ""),
        ("catalog:5432", "?sslmode=require&sslrootcert=/run/tls/ca.crt"),
        ("catalog:5432", "?sslmode=verify-full&sslrootcert=/tmp/untrusted.crt"),
        ("catalog:5433", "?sslmode=verify-full&sslrootcert=/run/tls/ca.crt"),
        ("remote.example:5432", "?sslmode=verify-full&sslrootcert=/run/tls/ca.crt"),
        ("127.0.0.1:5432", "?sslmode=disable"),
    ],
)
def test_catalog_cannot_expand_to_arbitrary_or_unverified_hosts(authority, query):
    with pytest.raises(ValueError):
        readonly_engine(
            SecretStr(f"postgresql+psycopg://reader:synthetic@{authority}/vulntrack{query}")
        )


def test_original_loopback_reader_remains_valid():
    engine = readonly_engine(
        SecretStr("postgresql+psycopg://reader:synthetic@127.0.0.1:55454/vulntrack")
    )
    assert engine.url.host == "127.0.0.1"
    engine.dispose()
