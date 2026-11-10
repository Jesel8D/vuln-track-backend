import hmac
import time
from contextlib import contextmanager
from hashlib import sha256
from uuid import UUID

import pytest
from pydantic import SecretStr

from app.core.errors import APIError
from app.db.workspace_context import list_user_workspaces, workspace_session


class CaptureSession:
    def execute(self, statement, parameters):
        self.statement = str(statement)
        self.parameters = parameters

        class Result:
            @staticmethod
            def mappings():
                class Mappings:
                    @staticmethod
                    def all():
                        return [{"workspace_id": "sample", "role": "owner"}]

                return Mappings()

        return Result()


class CaptureFactory:
    def __init__(self):
        self.session = CaptureSession()

    @contextmanager
    def begin(self):
        yield self.session


def test_workspace_context_signs_only_canonical_ids_and_short_expiry():
    factory = CaptureFactory()
    settings = type("Settings", (), {"workspace_hmac_key": SecretStr("ab" * 32)})()
    user = UUID("00000000-0000-4000-8000-000000000001")
    workspace = UUID("50000000-0000-4000-8000-000000000001")

    with workspace_session(factory, settings, user, workspace):
        params = factory.session.parameters
        assert params["user_id"] == user
        assert params["workspace_id"] == workspace
        assert 1 <= params["expires"] - time.time() <= 31
        payload = f"v1|{user}|{workspace}|{params['expires']}|{params['nonce']}".encode()
        expected = hmac.new(bytes.fromhex("ab" * 32), payload, sha256).hexdigest()
        assert hmac.compare_digest(params["signature"], expected)
        assert "establish_context" in factory.session.statement
        assert "ab" * 32 not in factory.session.statement


def test_workspace_context_fails_closed_without_key():
    factory = CaptureFactory()
    settings = type("Settings", (), {"workspace_hmac_key": None})()
    with pytest.raises(APIError) as error:
        with workspace_session(factory, settings, UUID(int=1), UUID(int=2)):
            pytest.fail("no debe abrir contexto sin secreto")
    assert error.value.code == "WORKSPACE_CONTEXT_UNAVAILABLE"


def test_workspace_directory_uses_a_separate_signed_domain():
    factory = CaptureFactory()
    settings = type("Settings", (), {"workspace_hmac_key": SecretStr("cd" * 32)})()
    user = UUID("00000000-0000-4000-8000-000000000001")
    rows = list_user_workspaces(factory, settings, user)
    params = factory.session.parameters
    payload = f"v1-directory|{user}|{params['expires']}|{params['nonce']}".encode()
    expected = hmac.new(bytes.fromhex("cd" * 32), payload, sha256).hexdigest()
    assert rows == [{"workspace_id": "sample", "role": "owner"}]
    assert hmac.compare_digest(params["signature"], expected)
    assert "list_user_workspaces" in factory.session.statement
