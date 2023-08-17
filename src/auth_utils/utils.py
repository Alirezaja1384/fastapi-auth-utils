from http import HTTPStatus
from typing import Annotated, Any, Sequence

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPBearer
from starlette.authentication import (
    BaseUser as StarletteBaseUser,
    UnauthenticatedUser,
)


class BaseUser(StarletteBaseUser):
    """Base user class

    Raises:
        NotImplementedError: has_perm must be implemented by user
            in order to use permission checks.
    """

    @property
    def is_authenticated(self):
        return True

    def has_perm(self, perm: str):
        """Checks if user has a specific permission or not.

        Args:
            perm (str): The permission

        Raises:
            NotImplementedError: This method must be implemented by user.
        """
        raise NotImplementedError()

    def has_role(self, role: str):
        """Checks if user has a specific role or not.

        Args:
            perm (str): The role

        Raises:
            NotImplementedError: This method must be implemented by user.
        """
        raise NotImplementedError()

    def has_perms(self, perms: Sequence[str]):
        """Checks if user has all given permissions or not.
        Calls has_perm() for each permission by default.

        Args:
            perm (Sequence[str]): The permissions sequence.
        """
        return all(map(self.has_perm, perms))

    def has_roles(self, roles: Sequence[str]):
        """Checks if user has all given roles or not.
        Calls has_role() for each permission by default.

        Args:
            perm (Sequence[str]): The permissions sequence.
        """
        return all(map(self.has_role, roles))


def get_user(request: Request) -> BaseUser | UnauthenticatedUser:
    """Returns the current user

    NOTE: This function DOES NOT authenticate the user by itself.
        An UnauthenticatedUser will be returned when user is not authenticated.
        You have to check `is_authenticated` yourself or use auth_required().

    Args:
        request (Request): User's http request.

    Returns:
        BaseUser | UnauthenticatedUser: Current user.
    """
    return request.user


def auth_required(
    *,
    permissions: list[Any] | None = None,
    roles: list[Any] | None = None,
):
    """Enforces authentication and authorization for current user.

    Args:
        permissions (list[str] | None, optional): The permissions user
            MUST have. Defaults to none.

        roles (list[str] | None, optional): The roles user MUST have.
            Defaults to none.
    """

    def auth_checker(
        _: Annotated[
            str,
            Security(
                HTTPBearer(auto_error=False)  # Errors are manually handled
            ),
        ],  # Enables authorize options in swagger
        user: Annotated[BaseUser, Depends(get_user)],
    ):
        # If user is not authenticated
        if not user.is_authenticated:
            raise HTTPException(HTTPStatus.UNAUTHORIZED)

        # If user is not authorized (insufficient roles)
        if not user.has_roles(roles or []):
            raise HTTPException(HTTPStatus.FORBIDDEN)

        # If user is not authorized (insufficient permissions)
        if not user.has_perms(permissions or []):
            raise HTTPException(HTTPStatus.FORBIDDEN)

    return auth_checker
