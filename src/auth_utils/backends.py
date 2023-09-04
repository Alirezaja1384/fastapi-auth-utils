"""Authentication backend for starlette's AuthenticationMiddleware."""

import logging
from typing import Type

import jwt
from starlette.authentication import AuthenticationBackend, AuthCredentials

from auth_utils.utils import BaseUser


class JWTAuthBackend(AuthenticationBackend):
    """
    An authentication backend for starlette's `AuthenticationMiddleware` which
        relies on JWT bearer tokens.
    """

    key: str
    decode_algorithms: list[str]
    user_class: Type[BaseUser]
    audience: str | None
    issuer: str | None

    def __init__(
        self,
        key: str,
        decode_algorithms: list[str],
        user_class: Type[BaseUser],
        audience: str | None = None,
        issuer: str | None = None,
    ) -> None:
        self.key = key
        self.decode_algorithms = decode_algorithms
        self.user_class = user_class
        self.audience = audience
        self.issuer = issuer

        self.logger = logging.getLogger("jwt-auth-backend")

    def get_payload(
        self, token: str, fail_silently: bool, log_errors: bool = True
    ) -> dict | None:
        """Returns the payload of VALID token.

        Args:
            token (str): JWT token.
            fail_silently (bool): Returns `None` on errors instead of raising.
            log_errors (bool, optional): Logs PyJWT exceptions if True.

        Returns:
            dict | None: Decoded payload for valid tokens and
                None for invalid ones.
        """
        try:
            return jwt.decode(
                token,
                key=self.key,
                algorithms=self.decode_algorithms,
                audience=self.audience,
                issuer=self.issuer,
            )

        except jwt.PyJWTError as exc:
            if log_errors:
                self.logger.log(
                    level=(
                        logging.DEBUG
                        if isinstance(exc, jwt.ExpiredSignatureError)
                        else logging.WARNING
                    ),
                    msg=repr(exc),
                    exc_info=False,
                )

            if fail_silently:
                return None

            raise

    async def authenticate(self, conn):
        """Authenticates the users who have a valid JWT token.

        Args:
            conn (HTTPConnection): The http request.

        Returns:
            tuple["AuthCredentials", "BaseUser"] | None: Auth credentials
                and user object for authenticated users and None for
                unauthenticated ones.
        """
        auth_header = conn.headers.get("Authorization", " ")

        try:
            if not auth_header.lower().startswith("bearer "):
                return

            token = auth_header.split(" ")[1]

            # Authenticate the user if token is valid
            if payload := self.get_payload(
                token=token, fail_silently=True, log_errors=True
            ):
                return AuthCredentials(["authenticated"]), self.user_class(
                    **payload
                )

        # If parsing payload data fail
        except (ValueError, TypeError) as err:
            self.logger.log(logging.ERROR, err, exc_info=True)
            return
