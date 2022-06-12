from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, SecretStr, validator

from .exceptions import KeycloakError


class KeycloakUser(BaseModel):
    id: str
    createdTimestamp: int
    username: str
    enabled: bool
    totp: bool
    emailVerified: bool
    firstName: Optional[str]
    lastName: Optional[str]
    email: Optional[str]
    disableableCredentialTypes: List[str]
    requiredActions: List[str]
    realmRoles: Optional[List[str]]
    notBefore: int
    access: dict
    attributes: Optional[dict]


class UsernamePassword(BaseModel):
    username: str
    password: SecretStr


class OIDCUser(BaseModel):
    sub: str
    iat: int
    exp: int
    scope: Optional[str] = None
    email_verified: bool
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    email: Optional[str] = None
    preferred_username: Optional[str] = None
    realm_access: Optional[Dict[Any, Any]] = None
    resource_access: Optional[Dict[Any, Any]] = None

    @property
    def roles(self) -> List[str]:
        try:
            return self.realm_access["roles"]
        except KeyError as e:
            raise KeycloakError(
                status_code=404,
                reason="The 'realm_access' section of the provided access token did not contain any 'roles'",
            ) from e


class KeycloakIdentityProvider(BaseModel):
    alias: str
    internalId: str
    providerId: str
    enabled: bool
    updateProfileFirstLoginMode: str
    trustEmail: bool
    storeToken: bool
    addReadTokenRoleOnCreate: bool
    authenticateByDefault: bool
    linkOnly: bool
    firstBrokerLoginFlowAlias: str
    config: dict


class KeycloakRole(BaseModel):
    id: str
    name: str
    composite: bool
    clientRole: bool
    containerId: str


class KeycloakToken(BaseModel):
    access_token: str
    token_type: str
    session_state: Optional[str] = None
    scope: List[str]

    @validator("scope", pre=True)
    def split_scopes(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            return v.split()

        return v


class KeycloakGroup(BaseModel):
    id: str
    name: str
    path: Optional[str]
    realmRoles: Optional[List[str]]
    subGroups: Optional[List["KeycloakGroup"]]
