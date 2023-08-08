import uuid
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


class User(BaseUser, BaseModel):
    """A test user class which has sub and permissions"""

    sub: str
    permissions: list[str]


app = FastAPI()
app.add_middleware(
    AuthenticationMiddleware,
    backend=JWTAuthBackend(
        key=JWT_KEY, decode_algorithms=[JWT_ALGORITHM], user_class=User
    ),
)


@app.get("/me")
def me(request: Request):
    return {
        "user": request.user,
        "is_authenticated": request.user.is_authenticated,
    }


client = TestClient(app=app)


def test_request_user_unauthenticated():
    response = client.get("/me")

    assert response.status_code == 200
    assert response.json()["is_authenticated"] is False


def test_request_user_authenticated():
    payload = {
        "sub": "test-user",
        "permissions": ["test"],
        "an_invalid_field": "test",
    }

    token = jwt.encode(payload, JWT_KEY, JWT_ALGORITHM)
    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200

    json_response = response.json()
    assert json_response["is_authenticated"] is True
    assert json_response["user"]["sub"] == payload["sub"]
    assert json_response["user"]["permissions"] == payload["permissions"]
    assert "an_invalid_field" not in json_response


def test_request_user_invalid_token():
    response = client.get("/me", headers={"Authorization": "Bearer invalid"})

    assert response.status_code == 200
    assert response.json()["is_authenticated"] is False


def test_request_user_expired_token():
    payload = {
        "sub": "test-user",
        "permissions": ["test"],
        "exp": datetime.timestamp(datetime.now() - timedelta(hours=1)),
    }

    token = jwt.encode(payload, JWT_KEY, JWT_ALGORITHM)
    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["is_authenticated"] is False
