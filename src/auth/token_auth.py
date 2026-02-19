import uuid
from src.auth.base import BaseAuth, AuthResult
from src.redis_client import RedisClient, TokenStore
from src.logger import sftp_log


class TokenAuth(BaseAuth):
    """Token认证模块 - 用户名即Token模式
    
    此模式下：
    1. 客户端使用token作为用户名登录（无需密码）
    2. 服务器验证token有效性
    3. 验证通过后，根据token对应的权限访问文件
    """
    
    def __init__(self):
        self._redis = RedisClient()
        self._token_store = TokenStore(self._redis)

    def authenticate(self, username: str, password: str, client_ip: str) -> AuthResult:
        """认证入口 - 用户名即token"""
        token = username

        if not token:
            sftp_log("AUTH_FAILED", f"reason=empty_token ip={client_ip}", "ERROR")
            return AuthResult(
                success=False,
                paths=[],
                download_limits={},
                session_id="",
                error="Empty token. Token should be provided as username."
            )

        token_data = self._token_store.get_token(token)

        if not token_data:
            sftp_log("AUTH_FAILED", f"reason=invalid_token ip={client_ip}", "ERROR")
            return AuthResult(
                success=False,
                paths=[],
                download_limits={},
                session_id="",
                error="Invalid or expired token"
            )

        session_id = str(uuid.uuid4())
        paths = token_data.get('paths', [])
        download_limits = token_data.get('download_limits', {})

        sftp_log("AUTH_SUCCESS", f"mode=token token={token[:8]}... paths={paths} client={client_ip}")

        return AuthResult(
            success=True,
            paths=paths,
            download_limits=download_limits,
            session_id=session_id
        )
