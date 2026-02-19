from abc import ABC, abstractmethod
from typing import BinaryIO, Optional
from dataclasses import dataclass


@dataclass
class SFTPAttr:
    filename: str
    longname: str
    size: int
    uid: int = 1000
    gid: int = 1000
    atime: int = 0
    mtime: int = 0
    perm: int = 0o644
    is_dir: bool = False


class StorageBackend(ABC):
    @abstractmethod
    def list(self, path: str) -> list[SFTPAttr]:
        pass

    @abstractmethod
    def open(self, path: str, mode: str) -> BinaryIO:
        pass

    @abstractmethod
    def stat(self, path: str) -> SFTPAttr:
        pass

    @abstractmethod
    def exists(self, path: str) -> bool:
        pass

    @abstractmethod
    def is_dir(self, path: str) -> bool:
        pass

    def normalize_path(self, path: str) -> str:
        path = path.replace('\\', '/')
        while '//' in path:
            path = path.replace('//', '/')
        if path != '/' and path.endswith('/'):
            path = path[:-1]
        return path

    def is_subpath(self, base: str, path: str) -> bool:
        base = self.normalize_path(base)
        path = self.normalize_path(path)
        if base == '/':
            return True
        return path.startswith(base + '/') or path == base
