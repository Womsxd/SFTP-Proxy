import uuid
import time
import hashlib
import jwt
from typing import Optional
from src.auth.base import BaseAuth, AuthResult
from src.config import get_config
from src.redis_client import RedisClient
from src.logger import sftp_log


class JWTAuth(BaseAuth):
    """JWT认证模块 - 固定用户名 + token密码模式
    
    此模式下：
    1. 客户端使用固定用户名登录（可配置，默认"jwt"）
    2. 密码字段传入JWT token
    3. 服务器验证JWT签名
    """
    
    def __init__(self):
        cfg = get_config()
        self._jwt_config = cfg.auth.get('jwt', {})
        self._username = self._jwt_config.get('username', 'jwt')
        self._secret = self._jwt_config.get('secret')
        self._algorithm = self._jwt_config.get('algorithm', 'HS256')
        self._issuer = self._jwt_config.get('issuer', 'sftp-proxy')
        self._redis_enabled = self._jwt_config.get('redis_enabled', False)

        if not self._secret:
            raise ValueError("JWT secret is not configured. Please set auth.jwt.secret in config.yaml")

        if self._redis_enabled:
            self._redis = RedisClient()
            self._prefix = cfg.redis.get('key_prefix', 'sftp')

    def authenticate(self, username: str, password: str, client_ip: str) -> AuthResult:
        """认证入口 - 验证固定用户名和密码（JWT token）"""
        # 验证用户名
        if username != self._username:
            sftp_log("AUTH_FAILED", f"reason=invalid_username expected={self._username} got={username} ip={client_ip}", "ERROR")
            return AuthResult(
                success=False,
                paths=[],
                download_limits={},
                session_id="",
                error=f"Invalid username. Expected: {self._username}"
            )
        
        token = password

        if not token:
            sftp_log("AUTH_FAILED", f"reason=empty_token ip={client_ip}", "ERROR")
            return AuthResult(
                success=False,
                paths=[],
                download_limits={},
                session_id="",
                error="Empty token. JWT token should be provided as password."
            )

        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                issuer=self._issuer,
                options={"verify_exp": True}
            )
        except jwt.ExpiredSignatureError:
            sftp_log("AUTH_FAILED", f"reason=token_expired ip={client_ip}", "ERROR")
            return AuthResult(
                success=False,
                paths=[],
                download_limits={},
                session_id="",
                error="Token expired"
            )
        except jwt.InvalidTokenError as e:
            sftp_log("AUTH_FAILED", f"reason=invalid_token error={str(e)} ip={client_ip}", "ERROR")
            return AuthResult(
                success=False,
                paths=[],
                download_limits={},
                session_id="",
                error="Invalid token"
            )

        if self._redis_enabled:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            blacklist_key = f"{self._prefix}:jwt:blacklist:{token_hash}"
            if self._redis.exists(blacklist_key):
                sftp_log("AUTH_FAILED", f"reason=token_revoked ip={client_ip}", "ERROR")
                return AuthResult(
                    success=False,
                    paths=[],
                    download_limits={},
                    session_id="",
                    error="Token revoked"
                )

        paths = payload.get('paths', [])
        download_limits = payload.get('download_limits', {})
        rate_limit = payload.get('rate_limit')
        session_id = str(uuid.uuid4())

        sftp_log("AUTH_SUCCESS", f"mode=jwt username={username} token={token[:8]}... paths={paths} rate_limit={rate_limit} client={client_ip}")

        return AuthResult(
            success=True,
            paths=paths,
            download_limits=download_limits,
            session_id=session_id,
            rate_limit=rate_limit
        )

    def create_token(self, paths: list, download_limits: Optional[dict] = None,
                     expire: int = 600, rate_limit: Optional[int] = None) -> str:
        cfg = get_config()
        max_expire = cfg.token.get('max_expire', 86400)
        expire = min(expire, max_expire)

        now = time.time()
        payload = {
            'iss': self._issuer,
            'iat': now,
            'exp': now + expire,
            'paths': paths,
            'download_limits': download_limits or {},
            'rate_limit': rate_limit
        }

        return jwt.encode(payload, self._secret, algorithm=self._algorithm)

    def revoke_token(self, token: str) -> bool:
        if not self._redis_enabled:
            return False

        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                options={"verify_exp": False}
            )
            exp = payload.get('exp', 0)
            if exp > time.time():
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                blacklist_key = f"{self._prefix}:jwt:blacklist:{token_hash}"
                self._redis.set(blacklist_key, '1', expire=int(exp - time.time()) + 60)
                return True
        except Exception:
            pass
        return False
