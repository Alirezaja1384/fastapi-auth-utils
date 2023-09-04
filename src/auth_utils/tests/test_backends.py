import uuid
import logging
from datetime import datetime, timedelta

import jwt
from pydantic import BaseModel
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.authentication import AuthenticationMiddleware

from auth_utils.utils import BaseUser
from auth_utils.backends import JWTAuthBackend


JWT_KEY = str(uuid.uuid4())
JWT_ALGORITHM = "HS256"
JWT_ISSUER = str(uuid.uuid4())
JWT_AUDIENCE = str(uuid.uuid4())


class User(BaseUser, BaseModel):
    """A test user class which has sub and permissions"""

    sub: str
    permissions: list[str]


app = FastAPI()
app.add_middleware(
    AuthenticationMiddleware,
    backend=JWTAuthBackend(
        key=JWT_KEY,
        decode_algorithms=[JWT_ALGORITHM],
        user_class=User,
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
    ),
)


@app.get("/me")
def me(request: Request):
    return {
        "user": request.user,
        "is_authenticated": request.user.is_authenticated,
    }


client = TestClient(app=app)


def generate_token(
    *, exclude_none_values: bool = True, **kwargs
) -> tuple[dict, str]:
    payload = {
        "sub": str(uuid.uuid4()),
        "aud": JWT_AUDIENCE,
        "iss": JWT_ISSUER,
        **kwargs,
    }

    if exclude_none_values:
        payload = {key: val for key, val in payload.items() if val is not None}

    return payload, jwt.encode(payload, JWT_KEY, JWT_ALGORITHM)


def test_jwt_unauthenticated():
    response = client.get("/me")

    assert response.status_code == 200
    assert response.json()["is_authenticated"] is False


def test_jwt_authenticated():
    payload, token = generate_token(
        sub=str(uuid.uuid4()),
        permissions=[str(uuid.uuid4())],
        an_invalid_field=str(uuid.uuid4()),
    )

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200

    json_response = response.json()
    assert json_response["is_authenticated"] is True
    assert json_response["user"]["sub"] == payload["sub"]
    assert json_response["user"]["permissions"] == payload["permissions"]
    assert "an_invalid_field" not in json_response


def test_jwt_invalid_bearer():
    response = client.get("/me", headers={"Authorization": "Bearer invalid"})

    assert response.status_code == 200
    assert response.json()["is_authenticated"] is False


def test_jwt_expired_token():
    _, token = generate_token(
        exp=datetime.timestamp(datetime.now() - timedelta(hours=1))
    )

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.json()["is_authenticated"] is False


def test_jwt_invalid_audience():
    _, token = generate_token(aud=str(uuid.uuid4()))

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.json()["is_authenticated"] is False


def test_jwt_no_audience():
    payload, token = generate_token(aud=None, exclude_none_values=True)
    assert "aud" not in payload

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.json()["is_authenticated"] is False


def test_jwt_invalid_issuer():
    _, token = generate_token(iss=str(uuid.uuid4()))

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.json()["is_authenticated"] is False


def test_jwt_no_issuer():
    payload, token = generate_token(iss=None, exclude_none_values=True)
    assert "iss" not in payload

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.json()["is_authenticated"] is False


def test_jwt_logging_expired_token(caplog):
    _, token = generate_token(
        exp=datetime.timestamp(datetime.now() - timedelta(hours=1))
    )

    with caplog.at_level(logging.DEBUG):
        client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert "ExpiredSignatureError" in caplog.text


def test_jwt_logging_invalid(caplog):
    with caplog.at_level(logging.WARNING):
        client.get("/me", headers={"Authorization": "Bearer invalid_token"})
        assert "DecodeError" in caplog.text
