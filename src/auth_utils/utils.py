from http import HTTPStatus
from typing import Annotated, Any, Sequence, Type

from fastapi import Depends, HTTPException, Request
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

    def has_perm(self, perm: Any) -> bool:
        """Checks if user has a specific permission or not.

        Args:
            perm (Any): The permission

        Raises:
            NotImplementedError: This method must be implemented by user.
        """
        raise NotImplementedError()

    def has_perms(self, perms: Sequence[Any]) -> bool:
        """Checks if user has all given permissions or not.
        Calls has_perm() for each permission by default.

        Args:
            perm (Sequence[str]): The permissions sequence.
        """
        return all(map(self.has_perm, perms))


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
    permissions: list[Any] | None = None, user_class: Type[BaseUser] = BaseUser
):
    """Enforces authentication and authorization for current user.

    Args:
        permissions (list[Any] | None, optional): The permissions user
            MUST have. Defaults to none.
    """

    def auth_checker(
        user: Annotated[user_class, Depends(get_user)],
    ):
        # If user is not authenticated or its authentication type is invalid
        if not user.is_authenticated or not isinstance(user, user_class):
            raise HTTPException(HTTPStatus.UNAUTHORIZED)

        # If user is not authorized
        if not user.has_perms(permissions or []):
            raise HTTPException(HTTPStatus.FORBIDDEN)

    return auth_checker
