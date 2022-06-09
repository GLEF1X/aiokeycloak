from typing import Any, Optional


class KeycloakError(Exception):
    def __init__(
        self,
        error_message: str = "",
        response_code: Optional[int] = None,
        response_body: Optional[Any] = None,
    ) -> None:
        super().__init__(self, error_message)

        self.response_code = response_code
        self.response_body = response_body
        self.error_message = error_message

    def __str__(self) -> str:
        if self.response_code is not None:
            return "{0}: {1}".format(self.response_code, self.error_message)

        return "{0}".format(self.error_message)


class KeycloakAuthenticationError(KeycloakError):
    pass


class KeycloakConnectionError(KeycloakError):
    pass


class KeycloakOperationError(KeycloakError):
    pass


class KeycloakDeprecationError(KeycloakError):
    pass


class KeycloakGetError(KeycloakOperationError):
    pass


class KeycloakPostError(KeycloakOperationError):
    pass


class KeycloakPutError(KeycloakOperationError):
    pass


class KeycloakDeleteError(KeycloakOperationError):
    pass


class KeycloakSecretNotFound(KeycloakOperationError):
    pass


class KeycloakRPTNotFound(KeycloakOperationError):
    pass


class KeycloakAuthorizationConfigError(KeycloakOperationError):
    pass


class KeycloakInvalidTokenError(KeycloakOperationError):
    pass


class KeycloakPermissionFormatError(KeycloakOperationError):
    pass


class PermissionDefinitionError(Exception):
    pass
