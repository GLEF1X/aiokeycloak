import logging
from typing import Any, AsyncGenerator

import uvicorn
from fastapi import Depends, FastAPI, Query
from starlette.responses import RedirectResponse

from aiokeycloak import AioKeycloakOpenIDClient
from aiokeycloak.types import KeycloakToken

app = FastAPI()
logger = logging.getLogger(__name__)


async def get_keycloak_client() -> AsyncGenerator[AioKeycloakOpenIDClient, Any]:
    client = AioKeycloakOpenIDClient(
        server_url="http://localhost:8080/",
        client_id="coursehunter-backend",
        realm_name="coursehunter",
        client_secret="kcOUlwK1XLsAdaGgCRZON0Y11EL4HjPR",
    )
    try:
        yield client
    finally:
        await client.close()


@app.get("/login", include_in_schema=False)
async def login_redirect(keycloak_openid: AioKeycloakOpenIDClient = Depends(get_keycloak_client)):
    return RedirectResponse(
        await keycloak_openid.build_auth_url("http://localhost:8081/oauth/callback")
    )


@app.get("/oauth/callback", response_model=KeycloakToken)
async def handle_oauth2_keycloak_callback(
    session_state: str = Query(...),
    code: str = Query(...),
    keycloak_openid: AioKeycloakOpenIDClient = Depends(get_keycloak_client),
):
    return await keycloak_openid.get_token(
        session_state=session_state,
        code=code,
        redirect_uri="http://localhost:8081/oauth/callback",
        grant_type=["authorization_code"],
    )


@app.get("/users/me")
async def get_information_about_me(
    keycloak_openid: AioKeycloakOpenIDClient = Depends(get_keycloak_client),
):
    pass


if __name__ == "__main__":
    uvicorn.run("fast-api:app", port=8081, workers=1)
