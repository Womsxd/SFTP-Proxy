import json
import time
import secrets
import sys
from typing import Optional, Any
import redis
from src.config import get_config


class RedisClient:
    _instance: Optional['RedisClient'] = None
    _connection_failed = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        cfg = get_config()
        self._prefix = cfg.redis.get('key_prefix', 'sftp')
        self._client = None
        
        # 检查是否需要 Redis
        self._redis_required = self._is_redis_required()
        
        # 尝试连接 Redis（带重试）
        self._connect_with_retry(
            host=cfg.redis.get('host', 'localhost'),
            port=cfg.redis.get('port', 6379),
            db=cfg.redis.get('db', 0),
            password=cfg.redis.get('password')
        )

    def _is_redis_required(self) -> bool:
        """检查当前配置是否需要 Redis"""
        cfg = get_config()
        auth_type = cfg.auth.get('type', 'token')
        
        # Token 模式必须使用 Redis
        if auth_type == 'token':
            return True
        
        # JWT 模式如果启用了 Redis 也需要
        if auth_type == 'jwt':
            return cfg.auth.get('jwt', {}).get('redis_enabled', False)
        
        return False

    def _connect_with_retry(self, host: str, port: int, db: int, password: Optional[str], max_retries: int = 3):
        """尝试连接 Redis，带重试机制"""
        last_error = None
        
        for attempt in range(1, max_retries + 1):
            try:
                self._client = redis.Redis(
                    host=host,
                    port=port,
                    db=db,
                    password=password,
                    decode_responses=True,
                    socket_connect_timeout=5
                )
                # 测试连接
                self._client.ping()
                print(f"[Redis] Connected successfully to {host}:{port}")
                return
            except Exception as e:
                last_error = e
                print(f"[Redis] Connection attempt {attempt}/{max_retries} failed: {e}")
                if attempt < max_retries:
                    time.sleep(2 ** attempt)  # 指数退避
        
        # 所有重试都失败了
        RedisClient._connection_failed = True
        
        if self._redis_required:
            # Redis 是必需的，拒绝服务
            error_msg = f"[Redis] CRITICAL: Redis connection failed after {max_retries} attempts. "
            error_msg += f"Redis is required for current auth type. Error: {last_error}"
            print(error_msg, file=sys.stderr)
            sys.exit(1)
        else:
            # Redis 不是必需的，发出警告但继续运行
            print(f"[Redis] WARNING: Redis connection failed, but it's not required for current auth type", file=sys.stderr)
            self._client = None

    def _key(self, *parts) -> str:
        return f"{self._prefix}:{':'.join(parts)}"

    def _check_connection(self):
        """检查 Redis 连接是否可用"""
        if self._client is None:
            raise RuntimeError("Redis connection is not available")

    def get(self, key: str) -> Optional[str]:
        self._check_connection()
        return self._client.get(key)

    def set(self, key: str, value: str, expire: Optional[int] = None):
        self._check_connection()
        if expire:
            self._client.setex(key, expire, value)
        else:
            self._client.set(key, value)

    def delete(self, key: str):
        self._check_connection()
        self._client.delete(key)

    def exists(self, key: str) -> bool:
        self._check_connection()
        return bool(self._client.exists(key))

    def hget(self, key: str, field: str) -> Optional[str]:
        self._check_connection()
        return self._client.hget(key, field)

    def hset(self, key: str, field: str, value: str):
        self._check_connection()
        self._client.hset(key, field, value)

    def hgetall(self, key: str) -> dict:
        self._check_connection()
        return self._client.hgetall(key) or {}

    def hdel(self, key: str, *fields):
        self._check_connection()
        self._client.hdel(key, *fields)

    def incr(self, key: str) -> int:
        self._check_connection()
        return self._client.incr(key)

    def expire(self, key: str, seconds: int):
        self._check_connection()
        self._client.expire(key, seconds)

    def keys(self, pattern: str) -> list:
        self._check_connection()
        return self._client.keys(pattern)

    def ping(self) -> bool:
        if self._client is None:
            return False
        try:
            return self._client.ping()
        except Exception:
            return False


def get_redis() -> RedisClient:
    return RedisClient()


class TokenStore:
    def __init__(self, redis_client: Optional[RedisClient] = None):
        self._redis = redis_client or RedisClient()

    def create_token(self, token: str, paths: list, download_limits: Optional[dict] = None,
                     expire: Optional[int] = None) -> dict:
        cfg = get_config()
        if expire is None:
            expire = cfg.token.get('default_expire', 600)
        max_expire = cfg.token.get('max_expire', 86400)
        expire = min(expire, max_expire)

        now = time.time()
        expires_at = now + expire

        key = self._redis._key('token', token)
        data = {
            'paths': json.dumps(paths),
            'download_limits': json.dumps(download_limits or {}),
            'downloads': json.dumps({}),
            'created_at': str(now),
            'expires_at': str(expires_at)
        }
        for field, value in data.items():
            self._redis.hset(key, field, value)
        self._redis.expire(key, expire)

        return {
            'token': token,
            'paths': paths,
            'download_limits': download_limits,
            'expires_at': expires_at
        }

    def get_token(self, token: str) -> Optional[dict]:
        key = self._redis._key('token', token)
        data = self._redis.hgetall(key)
        if not data:
            return None

        if 'expires_at' in data:
            if time.time() > float(data['expires_at']):
                self._redis.delete(key)
                return None

        return {
            'paths': json.loads(data.get('paths', '[]')),
            'download_limits': json.loads(data.get('download_limits', '{}')),
            'downloads': json.loads(data.get('downloads', '{}')),
            'created_at': float(data.get('created_at', 0)),
            'expires_at': float(data.get('expires_at', 0))
        }

    def delete_token(self, token: str) -> bool:
        key = self._redis._key('token', token)
        downloads_key = self._redis._key('token', token, 'downloads')
        deleted = self._redis.delete(key)
        self._redis.delete(downloads_key)
        return bool(deleted)

    def check_and_incr_download(self, token: str, path: str) -> tuple[bool, int, Optional[int]]:
        token_data = self.get_token(token)
        if not token_data:
            return False, 0, None

        download_limits = token_data.get('download_limits', {})

        normalized_limits = {}
        for limit_path, limit in download_limits.items():
            normalized_path = limit_path if limit_path.startswith('/') else '/' + limit_path
            normalized_limits[normalized_path] = limit

        if path in normalized_limits:
            limit = normalized_limits[path]
            key = self._redis._key('token', token, 'downloads', path.replace('/', '_'))
            current = self._redis.incr(key)
            if current == 1:
                cfg = get_config()
                token_expire = int(cfg.token.get('default_expire', 600))
                self._redis.expire(key, token_expire)

            if current > limit:
                return False, current, limit
            return True, current, limit
        return True, 0, None

    def get_downloads(self, token: str) -> dict:
        token_data = self.get_token(token)
        if not token_data:
            return {}
        return token_data.get('downloads', {})


def generate_token() -> str:
    return secrets.token_urlsafe(16)
