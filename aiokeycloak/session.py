import asyncio
import json
from typing import Any, Dict, Optional

import aiohttp
from starlette.status import HTTP_226_IM_USED
from typing_extensions import Self

from aiokeycloak.exceptions import KeycloakError


class AiohttpSession:
    def __init__(self, base_url: str) -> None:
        self._session: Optional[aiohttp.ClientSession] = None
        self._base_url = base_url

    async def close(self) -> None:
        if self._session is None or self._session.closed:
            return None

        await self._session.close()

    async def __aenter__(self) -> Self:
        await self._create_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def send_request(self, method: str, url: Any, **kwargs: Any) -> Dict[Any, Any]:
        session = await self._create_session()
        try:
            async with session.request(method, url, **kwargs) as response:
                if response.status > HTTP_226_IM_USED:
                    try:
                        message = (await response.json())["message"]
                    except (KeyError, ValueError):
                        message = await response.read()

                    raise KeycloakError(
                        error_message=message,
                        response_code=response.status,
                        response_body=await response.read(),
                    )
                try:
                    return await response.json(encoding="utf-8")
                except json.JSONDecodeError:
                    raise KeycloakError(
                        response_code=response.status, response_body=await response.read()
                    )

        except asyncio.TimeoutError:
            raise KeycloakError("Request timeout error")
        except aiohttp.ClientError as e:
            raise KeycloakError(f"{type(e).__name__}: {e}")

    async def _create_session(self) -> aiohttp.ClientSession:
        self._session = aiohttp.ClientSession(base_url=self._base_url)
        return self._session
