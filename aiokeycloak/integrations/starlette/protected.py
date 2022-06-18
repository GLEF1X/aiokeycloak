from typing import Iterable, Optional

from jose import jwt
from starlette.requests import Request

from aiokeycloak import AioKeycloakOpenIDClient
from aiokeycloak.integrations.starlette.store.base import AccessTokenStore


class Protected:
    def __init__(self, permissions: Optional[Iterable[str]] = None):
        self._permissions = permissions

    def __call__(self, request: Request):
        store: AccessTokenStore = request.app.state["s"]
        keycloak: AioKeycloakOpenIDClient = request.app.state["kk"]
        token = store.get_token()

        await keycloak.get_userinfo()


kk = AioKeycloakOpenIDClient()

jwt.decode()
