import abc

from starlette.requests import Request


class AccessTokenStore(abc.ABC):
    @abc.abstractmethod
    def store(self, request: Request) -> None:
        pass

    @abc.abstractmethod
    def discard(self, request: Request) -> None:
        pass
