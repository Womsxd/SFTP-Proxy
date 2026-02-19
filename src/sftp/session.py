import os
import time
from typing import Optional
from src.redis_client import RedisClient
from src.config import get_config


class Session:
    def __init__(self, session_id: str, allowed_paths: list, download_limits: dict,
                 token: str = None, redis_client: RedisClient = None):
        self.session_id = session_id
        self.allowed_paths = allowed_paths
        self.download_limits = download_limits
        self.token = token
        self._redis = redis_client
        self._last_activity = time.time()
        cfg = get_config()
        self._timeout = cfg.server.get('connection_timeout', 300)
        self._operation_timeout = cfg.server.get('operation_timeout', 60)

    def update_activity(self):
        """更新最后活动时间"""
        self._last_activity = time.time()

    def is_timeout(self) -> bool:
        """检查是否超时"""
        if self._timeout <= 0:
            return False
        return time.time() - self._last_activity > self._timeout

    def check_operation_timeout(self, start_time: float) -> bool:
        """检查操作是否超时"""
        if self._operation_timeout <= 0:
            return False
        return time.time() - start_time > self._operation_timeout

    def check_path(self, path: str) -> bool:
        if not self.allowed_paths:
            return False

        normalized_path = self._normalize_path(path)
        normalized_path = normalized_path.rstrip('/')

        for allowed in self.allowed_paths:
            allowed_normalized = self._normalize_path(allowed).rstrip('/')
            if allowed_normalized == '/':
                return True
            if normalized_path == allowed_normalized:
                return True
            if normalized_path.startswith(allowed_normalized + '/'):
                return True

        return False

    def check_download_limit(self, path: str) -> tuple[bool, int, Optional[int]]:
        if not self.download_limits:
            return True, 0, None

        normalized_path = self._normalize_path(path)

        for allowed_path, limit in self.download_limits.items():
            allowed_normalized = self._normalize_path(allowed_path)
            if normalized_path == allowed_normalized:
                if self._redis and self.token:
                    from src.redis_client import TokenStore
                    store = TokenStore(self._redis)
                    return store.check_and_incr_download(self.token, normalized_path)
                return True, 0, limit

        return True, 0, None

    def _normalize_path(self, path: str) -> str:
        path = path.replace('\\', '/')
        while '//' in path:
            path = path.replace('//', '/')
        if path != '/' and path.endswith('/'):
            path = path[:-1]
        if not path.startswith('/'):
            path = '/' + path
        return path
