import os
from dataclasses import dataclass

import pytest
from testcontainers.keycloak import KeycloakContainer
from typing_extensions import Self


class EnvCredentialsMissingError(Exception):
    pass


@dataclass
class KeycloakCredentials:
    username: str
    password: str
    connection_url: str

    @classmethod
    def from_env(cls) -> Self:
        try:
            return KeycloakCredentials(
                username=os.environ["KEYCLOAK_USERNAME"],
                password=os.environ["KEYCLOAK_PASSWORD"],
                connection_url=os.environ.get("KEYCLOAK_CONNECTION_URL", "localhost"),
            )
        except KeyError:
            raise EnvCredentialsMissingError()


@pytest.fixture(scope="session")
def keycloak_image_name() -> str:
    return os.environ.get("KEYCLOAK_IMAGE_NAME", "quay.io/keycloak/keycloak:latest")


@pytest.fixture(name="keycloak_credentials", scope="session", autouse=True)
def start_keycloak(keycloak_image_name: str) -> KeycloakCredentials:
    try:
        yield KeycloakCredentials.from_env()
    except EnvCredentialsMissingError:
        with KeycloakContainer(keycloak_image_name) as container:
            yield KeycloakCredentials(
                connection_url=container.get_url(),
                username=container.KEYCLOAK_USER,
                password=container.KEYCLOAK_PASSWORD,
            )
