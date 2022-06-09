from dataclasses import dataclass


@dataclass(frozen=True, eq=True)
class Role:
    """
    Roles identify a type or category of user. Admin, user,
    manager, and employee are all typical roles that may exist in an organization.

    https://keycloak.gitbooks.io/documentation/server_admin/topics/roles.html

    """

    name: str
    is_required: bool = False
