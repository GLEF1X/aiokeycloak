from dataclasses import dataclass, field
from typing import List


@dataclass
class Permission:
    """
    Consider this simple and very common permission:

    A permission associates the object being protected with the policies that must be evaluated to
    determine whether access is granted.

    X CAN DO Y ON RESOURCE Z

    where

    - X represents one or more users, roles, or groups, or a combination of them. You can
        also use claims and context here.

    - Y represents an action to be performed, for example, write, view, and so on.

    - Z represents a protected resource, for example, "/accounts".

    https://keycloak.gitbooks.io/documentation/authorization_services/topics/permission/overview.html

    """

    name: str
    type: str
    logic: str
    decision_strategy: str
    scopes: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)

    def __repr__(self):
        return "<Permission: %s (%s)>" % (self.name, self.type)

    def __str__(self):
        return "Permission: %s (%s)" % (self.name, self.type)
