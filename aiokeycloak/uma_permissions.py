from typing import Any, Set

from aiokeycloak.exceptions import KeycloakPermissionFormatError, PermissionDefinitionError


class UMAPermission:
    """A class to conveniently assembly permissions.
    The class itself is callable, and will return the assembled permission.

    Usage example:

    >>> r = Resource("Users")
    >>> s = Scope("delete")
    >>> permission = r(s)
    >>> print(permission)
        'Users#delete'

    """

    def __init__(self, permission=None, resource="", scope=""):
        self.resource = resource
        self.scope = scope

        if permission:
            if not isinstance(permission, UMAPermission):
                raise PermissionDefinitionError(
                    "can't determine if '{}' is a resource or scope".format(permission)
                )
            if permission.resource:
                self.resource = str(permission.resource)
            if permission.scope:
                self.scope = str(permission.scope)

    def __str__(self):
        scope = self.scope
        if scope:
            scope = "#" + scope
        return "{}{}".format(self.resource, scope)

    def __eq__(self, __o: object) -> bool:
        return str(self) == str(__o)

    def __repr__(self) -> str:
        return self.__str__()

    def __hash__(self) -> int:
        return hash(str(self))

    def __call__(self, permission=None, resource="", scope="") -> object:
        result_resource = self.resource
        result_scope = self.scope

        if resource:
            result_resource = str(resource)
        if scope:
            result_scope = str(scope)

        if permission:
            if not isinstance(permission, UMAPermission):
                raise PermissionDefinitionError(
                    "can't determine if '{}' is a resource or scope".format(permission)
                )
            if permission.resource:
                result_resource = str(permission.resource)
            if permission.scope:
                result_scope = str(permission.scope)

        return UMAPermission(resource=result_resource, scope=result_scope)


class Resource(UMAPermission):
    """An UMAPermission Resource class to conveniently assembly permissions.
    The class itself is callable, and will return the assembled permission.
    """

    def __init__(self, resource):
        super().__init__(resource=resource)


class Scope(UMAPermission):
    """An UMAPermission Scope class to conveniently assembly permissions.
    The class itself is callable, and will return the assembled permission.
    """

    def __init__(self, scope):
        super().__init__(scope=scope)


class AuthStatus:
    """A class that represents the authorization/login status of a user associated with a token.
    This has to evaluate to True if and only if the user is properly authorized
    for the requested resource."""

    def __init__(self, is_logged_in, is_authorized, missing_permissions):
        self.is_logged_in = is_logged_in
        self.is_authorized = is_authorized
        self.missing_permissions = missing_permissions

    def __bool__(self):
        return self.is_authorized

    def __repr__(self):
        return (
            f"AuthStatus("
            f"is_authorized={self.is_authorized}, "
            f"is_logged_in={self.is_logged_in}, "
            f"missing_permissions={self.missing_permissions})"
        )


def build_permission_param(permissions: Any) -> Set[str]:
    """
    Transform permissions to a set, so they are usable for requests

    :param permissions: either str (resource#scope),
        iterable[str] (resource#scope),
        dict[str,str] (resource: scope),
        dict[str,iterable[str]] (resource: scopes)
    :return: result bool
    """
    if permissions is None or permissions == "":
        return set()
    if isinstance(permissions, str):
        return {permissions}
    if isinstance(permissions, UMAPermission):
        return {str(permissions)}

    try:  # treat as dictionary of permissions
        result = set()
        for resource, scopes in permissions.items():
            print(f"resource={resource}scopes={scopes}")
            if scopes is None:
                result.add(resource)
            elif isinstance(scopes, str):
                result.add("{}#{}".format(resource, scopes))
            else:
                try:
                    for scope in scopes:
                        if not isinstance(scope, str):
                            raise KeycloakPermissionFormatError(
                                "misbuilt permission {}".format(permissions)
                            )
                        result.add("{}#{}".format(resource, scope))
                except TypeError:
                    raise KeycloakPermissionFormatError(
                        "misbuilt permission {}".format(permissions)
                    )
        return result
    except AttributeError:
        pass

    try:  # treat as any other iterable of permissions
        result = set()
        for permission in permissions:
            if not isinstance(permission, (str, UMAPermission)):
                raise KeycloakPermissionFormatError("misbuilt permission {}".format(permissions))
            result.add(str(permission))
        return result
    except TypeError:
        pass
    raise KeycloakPermissionFormatError("misbuilt permission {}".format(permissions))
