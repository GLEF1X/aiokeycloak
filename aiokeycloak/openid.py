from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from jose import jwt
from typing_extensions import Self

from aiokeycloak.authorization import Authorization
from aiokeycloak.exceptions import (
    KeycloakAuthenticationError,
    KeycloakAuthorizationConfigError,
    KeycloakInvalidTokenError,
    KeycloakPostError,
    KeycloakRPTNotFound,
)
from aiokeycloak.session import AiohttpSession
from aiokeycloak.types import KeycloakToken
from aiokeycloak.uma_permissions import AuthStatus, build_permission_param
from aiokeycloak.url_patterns import (
    URL_AUTH,
    URL_CERTS,
    URL_ENTITLEMENT,
    URL_INTROSPECT,
    URL_LOGOUT,
    URL_REALM,
    URL_TOKEN,
    URL_USERINFO,
    URL_WELL_KNOWN,
)


class AioKeycloakOpenIDClient:
    def __init__(
        self,
        server_url: str,
        client_id: str,
        client_secret: str,
        realm_name: str,
    ):
        self._server_url = server_url
        self._realm_name = realm_name
        self._client_id = client_id
        self._client_secret = client_secret
        self._session = AiohttpSession(server_url)
        self._authorization = Authorization()

    async def get_well_known_configuration(self) -> Dict[Any, Any]:
        """
        The most important endpoint to understand is the well-known configuration
               endpoint. It lists endpoints and other configuration options relevant to
               the OpenID Connect implementation in Keycloak.

        :return It lists endpoints and other configuration options relevant.
        """
        params_path = {"realm-name": self._realm_name}
        return await self._session.send_request("GET", URL_WELL_KNOWN.format(**params_path))

    async def build_auth_url(self, redirect_uri: str) -> str:
        """
        http://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

        :return:
        """
        well_known = await self.get_well_known_configuration()
        params_path = {
            "authorization-endpoint": well_known["authorization_endpoint"],
            "client-id": self._client_id,
            "redirect-uri": redirect_uri,
        }
        return URL_AUTH.format(**params_path)

    async def get_token(
        self,
        username: str = "",
        password: str = "",
        grant_type: Optional[Iterable[str]] = None,
        code: str = "",
        redirect_uri: str = "",
        totp=None,
        session_state: Optional[str] = None,
        **extra: Any,
    ) -> KeycloakToken:
        """
        The token endpoint is used to obtain tokens. Tokens can either be obtained by
        exchanging an authorization code or by supplying credentials directly depending on
        what flow is used. The token endpoint is also used to obtain new access tokens
        when they expire.
        http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

        :param username:
        :param password:
        :param grant_type:
        :param code:
        :param redirect_uri:
        :param totp:
        :param session_state:
        :return:
        """
        if grant_type is None:
            grant_type = ["password"]

        params_path = {"realm-name": self._realm_name}
        payload = {
            "username": username,
            "password": password,
            "client_id": self._client_id,
            "grant_type": grant_type,
            "code": code,
            "redirect_uri": redirect_uri,
            "session_state": session_state,
        }
        if extra:
            payload.update(extra)

        if totp:
            payload["totp"] = totp

        payload = self._add_secret_key(payload)
        json_response = await self._session.send_request(
            "POST", URL_TOKEN.format(**params_path), data=payload
        )

        return KeycloakToken.parse_obj(json_response)

    async def refresh_token(self, refresh_token: str, grant_type: Optional[Iterable[str]] = None):
        """
        The token endpoint is used to obtain tokens. Tokens can either be obtained by
        exchanging an authorization code or by supplying credentials directly depending on
        what flow is used. The token endpoint is also used to obtain new access tokens
        when they expire.

        http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

        :param refresh_token:
        :param grant_type:
        :return:
        """
        if grant_type is None:
            grant_type = ["refresh_token"]

        params_path = {"realm-name": self._realm_name}
        payload = {
            "client_id": self._client_id,
            "grant_type": grant_type,
            "refresh_token": refresh_token,
        }
        payload = self._add_secret_key(payload)
        return await self._session.send_request(
            "POST", URL_TOKEN.format(**params_path), data=payload
        )

    async def exchange_token(
        self, token: str, client_id: str, audience: str, subject: str
    ) -> Dict[Any, Any]:
        """
        Use a token to obtain an entirely different token. See
        https://www.keycloak.org/docs/latest/securing_apps/index.html#_token-exchange

        :param token:
        :param client_id:
        :param audience:
        :param subject:
        :return:
        """
        params_path = {"realm-name": self._realm_name}
        payload = {
            "grant_type": ["urn:ietf:params:oauth:grant-type:token-exchange"],
            "client_id": client_id,
            "subject_token": token,
            "requested_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
            "audience": audience,
            "requested_subject": subject,
        }
        payload = self._add_secret_key(payload)
        return await self._session.send_request(
            "POST", URL_TOKEN.format(**params_path), data=payload
        )

    async def get_userinfo(self, access_token: str) -> Dict[Any, Any]:
        """
        The userinfo endpoint returns standard claims about the authenticated user,
        and is protected by a bearer token.
        http://openid.net/specs/openid-connect-core-1_0.html#UserInfo

        :param access_token:
        :return:
        """
        params_path = {"realm-name": self._realm_name}
        headers = {"Authorization": f"Bearer {access_token}"}

        return await self._session.send_request(
            "GET", URL_USERINFO.format(**params_path), headers=headers
        )

    async def logout(self, refresh_token: str) -> Dict[Any, Any]:
        """
        The logout endpoint logs out the authenticated user.

        :param refresh_token:
        :return:
        """
        params_path = {"realm-name": self._realm_name}
        payload = {"client_id": self._client_id, "refresh_token": refresh_token}

        payload = self._add_secret_key(payload)
        return await self._session.send_request(
            "POST", URL_LOGOUT.format(**params_path), data=payload
        )

    async def get_certs(self) -> Dict[Any, Any]:
        """
        The certificate endpoint returns the public keys enabled by the realm, encoded as a
        JSON Web Key (JWK). Depending on the realm settings there can be one or more keys enabled
        for verifying tokens.

        https://tools.ietf.org/html/rfc7517

        :return:
        """
        params_path = {"realm-name": self._realm_name}
        return await self._session.send_request("GET", URL_CERTS.format(**params_path))

    async def get_public_key(self) -> str:
        """
        The public key is exposed by the realm page directly.

        :return:
        """
        params_path = {"realm-name": self._realm_name}
        raw_json = await self._session.send_request("GET", URL_REALM.format(**params_path))
        return raw_json["public_key"]

    async def entitlement(self, token: str, resource_server_id: str):
        """
        Client applications can use a specific endpoint to obtain a special security token
        called a requesting party token (RPT). This token consists of all the entitlements
        (or permissions) for a user as a result of the evaluation of the permissions and
        authorization policies associated with the resources being requested. With an RPT,
        client applications can gain access to protected resources at the resource server.

        :return:
        """
        headers = {"Authorization": f"Bearer {token}"}
        params_path = {"realm-name": self._realm_name, "resource-server-id": resource_server_id}
        return await self._session.send_request(
            "GET", URL_ENTITLEMENT.format(**params_path), headers=headers
        )

    async def introspect(
        self, access_token: str, rpt: Optional[str] = None, token_type_hint: Optional[str] = None
    ):
        """
        The introspection endpoint is used to retrieve the active state of a token.
        It is can only be invoked by confidential clients.

        https://tools.ietf.org/html/rfc7662

        :param access_token:
        :param rpt:
        :param token_type_hint:
        :return:
        """
        params_path = {"realm-name": self._realm_name}

        payload = {"client_id": self._client_id, "token": access_token}
        headers = {}

        if token_type_hint == "requesting_party_token":
            if rpt:
                payload.update({"token": rpt, "token_type_hint": token_type_hint})
                headers["Authorization"] = f"Bearer {access_token}"
            else:
                raise KeycloakRPTNotFound("Can't found RPT.")

        payload = self._add_secret_key(payload)

        return await self._session.send_request(
            "POST", URL_INTROSPECT.format(**params_path), data=payload, headers=headers
        )

    async def get_policies(
        self, access_token: str, method_token_info: str = "introspect", **kwargs: Any
    ):
        """
        Get policies by user token

        :param access_token: user token
        :param method_token_info:
        :return: policies list
        """
        if not self._authorization.policies:
            raise KeycloakAuthorizationConfigError(
                "Keycloak settings not found. Load Authorization Keycloak settings."
            )

        token_info = await self._get_token_info(access_token, method_token_info, **kwargs)

        if method_token_info == "introspect" and not token_info["active"]:
            raise KeycloakInvalidTokenError("Token expired or invalid.")

        user_resources = token_info["resource_access"].get(self._client_id)

        if not user_resources:
            return None

        policies = []

        for policy_name, policy in self._authorization.policies.items():
            for role in user_resources["roles"]:
                if self._build_name_role(role) in policy.roles:
                    policies.append(policy)

        return list(set(policies))

    async def get_permissions(self, access_token: str, method_token_info="introspect", **kwargs):
        """
        Get permission by user token

        :param access_token: user token
        :param method_token_info: Decode token method
        :param kwargs: parameters for decode
        :return: permissions list
        """
        if not self._authorization.policies:
            raise KeycloakAuthorizationConfigError(
                "Keycloak settings not found. Load Authorization Keycloak settings."
            )

        token_info = await self._get_token_info(access_token, method_token_info, **kwargs)

        if method_token_info == "introspect" and not token_info["active"]:
            raise KeycloakInvalidTokenError("Token expired or invalid.")

        user_resources = token_info["resource_access"].get(self._client_id)

        if not user_resources:
            return None

        permissions = []

        for policy_name, policy in self._authorization.policies.items():
            for role in user_resources["roles"]:
                if self._build_name_role(role) in policy.roles:
                    permissions += policy.permissions

        return list(set(permissions))

    async def uma_permissions(self, token: str, permissions: Any):
        """
        Get UMA permissions by user token with requested permissions
        The token endpoint is used to retrieve UMA permissions from Keycloak. It can only be
        invoked by confidential clients.

        http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

        :param token: user token
        :param permissions: list of uma permissions list(resource:scope) requested by the user
        :return: permissions list
        """

        permission = build_permission_param(permissions)

        params_path = {"realm-name": self._realm_name}
        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "permission": permission,
            "response_mode": "permissions",
            "audience": self._client_id,
        }

        headers = {"Authorization": f"Bearer {token}"}
        return await self._session.send_request(
            "POST", URL_TOKEN.format(**params_path), data=payload, headers=headers
        )

    async def get_auth_status(self, access_token: str, permissions: Iterable[str]) -> AuthStatus:
        """
        Determine whether user has uma permissions with specified user token

        :param access_token: user token
        :param permissions: list of uma permissions (resource:scope)
        :return: auth status
        """
        needed = build_permission_param(permissions)
        try:
            granted = await self.uma_permissions(access_token, permissions)
        except (KeycloakPostError, KeycloakAuthenticationError) as e:
            if e.response_code == 403:
                return AuthStatus(
                    is_logged_in=True, is_authorized=False, missing_permissions=needed
                )
            elif e.response_code == 401:
                return AuthStatus(
                    is_logged_in=False, is_authorized=False, missing_permissions=needed
                )
            raise

        for resource_struct in granted:
            resource = resource_struct["rsname"]
            scopes = resource_struct.get("scopes", None)
            if not scopes:
                needed.discard(resource)
                continue
            for scope in scopes:
                needed.discard("{}#{}".format(resource, scope))

        return AuthStatus(
            is_logged_in=True, is_authorized=len(needed) == 0, missing_permissions=needed
        )

    async def _get_token_info(self, token: str, method_token_info: str, **kwargs: Any):
        """
        :param token:
        :param method_token_info:
        :param kwargs:
        :return:
        """
        if method_token_info == "introspect":
            return await self.introspect(token)
        return jwt.decode(token, **kwargs)

    def _add_secret_key(self, payload: Dict[Any, Any]):
        """
        Add secret key if exist.
        :param payload:
        :return:
        """
        if self._client_secret:
            payload.update({"client_secret": self._client_secret})

        return payload

    def _build_name_role(self, role: str) -> str:
        """
        :param role:
        :return:
        """
        return self._client_id + "/" + role

    async def close(self) -> None:
        await self._session.close()

    async def __aenter__(self) -> Self:
        await self._session._create_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._session.close()
