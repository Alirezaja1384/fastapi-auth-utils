import uuid
from http import HTTPStatus

import jwt
from pydantic import BaseModel
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.authentication import AuthenticationMiddleware

from auth_utils.utils import BaseUser, auth_required
from auth_utils.backends import JWTAuthBackend


JWT_ALGORITHM = "HS256"
JWT_KEY = str(uuid.uuid4())

RANDOM_ROLE = str(uuid.uuid4())
RANDOM_PERMISSION = str(uuid.uuid4())


class User(BaseUser, BaseModel):
    """A test user class which has sub and permissions"""

    sub: str
    roles: list[str]
    permissions: list[str]

    def has_perm(self, perm: str):
        return perm in self.permissions

    def has_role(self, role: str):
        return role in self.roles


app = FastAPI()
app.add_middleware(
    AuthenticationMiddleware,
    backend=JWTAuthBackend(
        key=JWT_KEY, decode_algorithms=[JWT_ALGORITHM], user_class=User
    ),
)


def get_headers(
    *,
    sub: str,
    roles: list[str] | None = None,
    permissions: list[str] | None = None,
) -> dict:
    token = jwt.encode(
        {"sub": sub, "roles": roles or [], "permissions": permissions or []},
        JWT_KEY,
        JWT_ALGORITHM,
    )

    return {"Authorization": f"Bearer {token}"}


@app.get("/auth_no_perm", dependencies=[Depends(auth_required())])
def auth_no_perm():
    """Only requires user to be authenticated"""
    return {"msg": "Well done!"}


@app.get(
    "/auth_with_perm",
    dependencies=[Depends(auth_required(permissions=[RANDOM_PERMISSION]))],
)
def auth_with_perm():
    """Requires the user to have `RANDOM_PERMISSION` permission as well."""
    return {"msg": "Well done!"}


@app.get(
    "/auth_with_role",
    dependencies=[Depends(auth_required(roles=[RANDOM_ROLE]))],
)
def auth_with_role():
    """Requires the user to have `RANDOM_ROLE` permission as well."""
    return {"msg": "Well done!"}


client = TestClient(app=app)


def test_auth_no_perm_unauthenticated():
    response = client.get("/auth_no_perm")
    assert response.status_code == HTTPStatus.UNAUTHORIZED  # 401


def test_auth_no_perm_authenticated():
    response = client.get(
        "/auth_no_perm", headers=get_headers(sub="test", permissions=[])
    )

    assert response.status_code == HTTPStatus.OK  # 200


def test_auth_with_perm_unauthenticated():
    response = client.get("/auth_with_perm")
    assert response.status_code == HTTPStatus.UNAUTHORIZED  # 401


def test_auth_with_perm_authenticated_without_perm():
    response = client.get(
        "/auth_with_perm", headers=get_headers(sub="test", permissions=[])
    )

    assert response.status_code == HTTPStatus.FORBIDDEN  # 403


def test_auth_with_perm_authenticated_with_perm():
    response = client.get(
        "/auth_with_perm",
        headers=get_headers(sub="test", permissions=[RANDOM_PERMISSION]),
    )

    assert response.status_code == HTTPStatus.OK  # 200


def test_auth_with_role_authenticated_without_role():
    response = client.get(
        "/auth_with_role", headers=get_headers(sub="test", roles=[])
    )

    assert response.status_code == HTTPStatus.FORBIDDEN  # 403


def test_auth_with_role_authenticated_with_role():
    response = client.get(
        "/auth_with_role", headers=get_headers(sub="test", roles=[RANDOM_ROLE])
    )

    assert response.status_code == HTTPStatus.OK  # 200
