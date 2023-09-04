import uuid

import jwt
from pydantic import BaseModel
from fastapi import Depends, FastAPI, Request
from starlette.middleware.authentication import AuthenticationMiddleware

from auth_utils.utils import BaseUser, auth_required
from auth_utils.backends import JWTAuthBackend

JWT_KEY = str(uuid.uuid4())
JWT_ALGORITHM = "HS256"


class Permission(BaseModel):
    claims: list[str] | None = None
    roles: list[str] | None = None


class User(BaseUser, BaseModel):
    """A test user class which has sub and permissions"""

    sub: str
    name: str = ""
    claims: list[str]
    roles: list[str] = []

    def has_perm(self, perm: Permission):
        def has_roles(roles: list[str]):
            return all(map(lambda role: role in self.roles, roles))

        def has_claims(claims: list[str]):
            return all(map(lambda claim: claim in self.claims, claims))

        return has_roles(perm.roles or []) and has_claims(perm.claims or [])

    @property
    def identity(self) -> str:
        return self.sub

    @property
    def display_name(self) -> str:
        return self.name


app = FastAPI(docs_url="/docs")
app.add_middleware(
    AuthenticationMiddleware,
    backend=JWTAuthBackend(
        key=JWT_KEY, decode_algorithms=[JWT_ALGORITHM], user_class=User
    ),
)


@app.on_event("startup")
def startup():
    payload = User(
        sub="user-0", name="test", roles=["user"], claims=["home"]
    ).model_dump()

    print("JWT signing algorithm: ", JWT_ALGORITHM)
    print("JWT signing key: ", JWT_KEY)
    print("JWT payload: ", payload)
    print(
        "Example JWT token: ",
        jwt.encode(payload, JWT_KEY, JWT_ALGORITHM),
    )


@app.get(
    "/",
    dependencies=[
        Depends(
            auth_required(
                permissions=[Permission(claims=["home"], roles=["user"])]
            )
        )
    ],
)
def me(request: Request):
    return {"user": request.user}
