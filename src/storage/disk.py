import os
import io
import stat
import time
from typing import BinaryIO, Optional
from src.storage.base import StorageBackend, SFTPAttr
from src.config import get_config


class DiskFileWrapper:
    """磁盘文件包装器，添加 content_length 属性"""
    
    def __init__(self, file_obj, size: int):
        self._file_obj = file_obj
        self.content_length = size
    
    def seek(self, offset: int):
        return self._file_obj.seek(offset)
    
    def read(self, size: int = -1):
        return self._file_obj.read(size)
    
    def close(self):
        return self._file_obj.close()
    
    @property
    def closed(self):
        return self._file_obj.closed
    
    def __getattr__(self, name):
        return getattr(self._file_obj, name)


class DiskStorage(StorageBackend):
    def __init__(self, root: Optional[str] = None, config: Optional[dict] = None):
        cfg = get_config()
        if config:
            self._root = root or config.get('disk', {}).get('root', './data')
        else:
            self._root = root or cfg.storage.get('disk', {}).get('root', './data')
        if not os.path.isabs(self._root):
            self._root = os.path.abspath(self._root)
        if not os.path.exists(self._root):
            os.makedirs(self._root, exist_ok=True)

    def _resolve_path(self, path: str) -> str:
        path = self.normalize_path(path)
        if path == '/':
            return self._root
        full_path = os.path.join(self._root, path.lstrip('/'))
        real_path = os.path.realpath(full_path)
        if not real_path.startswith(self._root):
            raise PermissionError("Path outside storage root")
        return real_path

    def list(self, path: str) -> list[SFTPAttr]:
        resolved_path = self._resolve_path(path)
        if not os.path.exists(resolved_path):
            raise FileNotFoundError(f"Path not found: {path}")
        if not os.path.isdir(resolved_path):
            raise NotADirectoryError(f"Not a directory: {path}")

        results = []
        try:
            entries = os.listdir(resolved_path)
        except PermissionError:
            raise PermissionError(f"Permission denied: {path}")

        for entry in entries:
            try:
                entry_path = os.path.join(resolved_path, entry)
                file_stat = os.stat(entry_path)
                is_dir = stat.S_ISDIR(file_stat.st_mode)

                attrs = self._build_attr(entry, file_stat, is_dir)
                results.append(attrs)
            except (OSError, PermissionError):
                continue

        return results

    def open(self, path: str, mode: str) -> BinaryIO:
        resolved_path = self._resolve_path(path)
        if 'w' in mode or 'a' in mode or '+' in mode:
            raise PermissionError("Write operations not allowed")
        try:
            file_obj = open(resolved_path, 'rb')
            size = os.path.getsize(resolved_path)
            return DiskFileWrapper(file_obj, size)
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {path}")
        except PermissionError:
            raise PermissionError(f"Permission denied: {path}")

    def stat(self, path: str) -> SFTPAttr:
        resolved_path = self._resolve_path(path)
        try:
            file_stat = os.stat(resolved_path)
        except FileNotFoundError:
            raise FileNotFoundError(f"Path not found: {path}")
        except PermissionError:
            raise PermissionError(f"Permission denied: {path}")

        is_dir = stat.S_ISDIR(file_stat.st_mode)
        return self._build_attr(os.path.basename(path), file_stat, is_dir)

    def exists(self, path: str) -> bool:
        try:
            resolved_path = self._resolve_path(path)
            return os.path.exists(resolved_path)
        except PermissionError:
            return False

    def is_dir(self, path: str) -> bool:
        try:
            resolved_path = self._resolve_path(path)
            return os.path.isdir(resolved_path)
        except PermissionError:
            return False

    def _build_attr(self, filename: str, file_stat, is_dir: bool) -> SFTPAttr:
        perms = stat.S_IMODE(file_stat.st_mode)
        if is_dir:
            perms |= stat.S_IFDIR
            long_perm = 'drwxr-xr-x'
        else:
            perms |= stat.S_IFREG
            long_perm = '-rw-r--r--'

        longname = f"{long_perm}  1 1000  1000  {file_stat.st_size:>8} {time.strftime('%b %d %H:%M', time.localtime(file_stat.st_mtime))} {filename}"

        return SFTPAttr(
            filename=filename,
            longname=longname,
            size=file_stat.st_size,
            uid=file_stat.st_uid,
            gid=file_stat.st_gid,
            atime=int(file_stat.st_atime),
            mtime=int(file_stat.st_mtime),
            perm=perms,
            is_dir=is_dir
        )
