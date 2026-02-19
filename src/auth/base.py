from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class AuthResult:
    success: bool
    paths: list[str]
    download_limits: dict
    session_id: str
    error: Optional[str] = None
    extra_data: Optional[dict] = None


class BaseAuth(ABC):
    @abstractmethod
    def authenticate(self, username: str, password: str, client_ip: str) -> AuthResult:
        pass
