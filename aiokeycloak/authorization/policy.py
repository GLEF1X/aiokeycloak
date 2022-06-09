from dataclasses import dataclass, field
from typing import List

from aiokeycloak.authorization.permission import Permission
from aiokeycloak.authorization.role import Role


@dataclass
class Policy:
    """
    A policy defines the conditions that must be satisfied to grant access to an object.
    Unlike permissions, you do not specify the object being protected but rather the conditions
    that must be satisfied for access to a given object (for example, resource, scope, or both).
    Policies are strongly related to the different access control mechanisms (ACMs) that you can
    use to protect your resources. With policies, you can implement strategies for attribute-based
    access control (ABAC), role-based access control (RBAC), context-based access control, or any
    combination of these.

    https://keycloak.gitbooks.io/documentation/authorization_services/topics/policy/overview.html

    """

    name: str
    type: str
    logic: str
    decision_strategy: str
    permissions: List[Permission] = field(default_factory=list)
    roles: List[Role] = field(default_factory=list)
