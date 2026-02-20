import os
import yaml
import threading
from pathlib import Path
from typing import Any, Optional


class Config:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._config_file = "./config.yaml"
        self._lock = threading.RLock()

        self.server = {
            "host": "0.0.0.0",
            "sftp_port": 2222,
            "api_port": 8080,
            "host_key": "./ssh_host_key",
            "host_key_type": "rsa",
            "max_connections": 100,
            "thread_pool_size": 50,
            "backlog": 128
        }
        self.redis = {
            "host": "localhost",
            "port": 6379,
            "db": 0,
            "password": None,
            "key_prefix": "sftp"
        }
        self.token = {
            "default_expire": 600,
            "max_expire": 86400
        }
        self.auth = {
            "type": "token",
            # Token模式: 用户名直接传入token，无需密码
            # JWT模式: 固定用户名 + JWT token密码
            # S3模式: 固定用户名 + 带签名的URL（延迟鉴权）
            "jwt": {
                "username": "jwt",          # JWT模式固定用户名
                "secret": None,             # JWT密钥，必须配置
                "algorithm": "HS256",
                "issuer": "sftp-proxy",
                "redis_enabled": False
            },
            "s3": {
                "enabled": False,
                "username": "s3",             # S3模式固定用户名
                "access_key": None,
                "secret_key": None,
                "region": "us-east-1"
            }
        }
        self.storage = {
            "type": "disk",
            "disk": {"root": "./data"},
            "s3": {
                "bucket": "my-bucket",
                "endpoint": "https://s3.amazonaws.com",
                "access_key": None,
                "secret_key": None,
                "region": "us-east-1"
            }
        }
        self.log = {
            "level": "INFO",
            "dir": "./logs",
            "format": "%(asctime)s [%(levelname)s] [%(action)s] %(message)s",
            "date_format": "%Y-%m-%d %H:%M:%S"
        }
        self.api = {
            "admin_token": None  # 管理API的token，必须配置
        }

    def load(self, config_file: str = "./config.yaml") -> 'Config':
        with self._lock:
            self._config_file = config_file
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                if data:
                    self._apply_config(data)
            return self

    def reload(self) -> 'Config':
        return self.load(self._config_file)

    def validate(self) -> list[str]:
        """验证配置，返回错误列表（空列表表示验证通过）"""
        errors = []
        
        # 检查 admin_token
        admin_token = self.api.get('admin_token')
        if not admin_token:
            errors.append("api.admin_token is required but not configured")
        elif len(admin_token) < 16:
            errors.append("api.admin_token must be at least 16 characters long")
        
        # 检查 JWT 配置（如果使用 JWT 模式）
        auth_type = self.auth.get('type', 'token')
        if auth_type == 'jwt':
            jwt_secret = self.auth.get('jwt', {}).get('secret')
            if not jwt_secret:
                errors.append("auth.jwt.secret is required when using JWT authentication")
            elif len(jwt_secret) < 32:
                errors.append("auth.jwt.secret must be at least 32 characters long for security")
        
        return errors

    def _apply_config(self, data: dict):
        if 'server' in data:
            self.server.update(data['server'])
        if 'redis' in data:
            self.redis.update(data['redis'])
        if 'token' in data:
            self.token.update(data['token'])
        if 'auth' in data:
            if 'type' in data['auth']:
                self.auth['type'] = data['auth']['type']
            if 'jwt' in data['auth']:
                self.auth['jwt'].update(data['auth']['jwt'])
            if 's3' in data['auth']:
                self.auth['s3'].update(data['auth']['s3'])
        if 'storage' in data:
            if 'type' in data['storage']:
                self.storage['type'] = data['storage']['type']
            if 'disk' in data['storage']:
                self.storage['disk'].update(data['storage']['disk'])
            if 's3' in data['storage']:
                self.storage['s3'].update(data['storage']['s3'])
        if 'log' in data:
            self.log.update(data['log'])
        if 'api' in data:
            self.api.update(data['api'])

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split('.')
        value = self.__dict__
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value


_config: Optional[Config] = None
_config_lock = threading.Lock()


def get_config() -> Config:
    global _config
    if _config is None:
        with _config_lock:
            if _config is None:
                _config = Config()
    return _config


def load_config(config_file: str = "./config.yaml") -> Config:
    global _config
    with _config_lock:
        if _config is None:
            _config = Config()
        _config.load(config_file)
    return _config


def reload_config() -> Config:
    from src.logger import reinit_loggers
    cfg = get_config()
    result = cfg.reload()
    reinit_loggers()
    return result
