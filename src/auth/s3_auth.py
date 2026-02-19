import uuid
from typing import Optional
from src.auth.base import BaseAuth, AuthResult
from src.config import get_config
from src.logger import sftp_log


class S3Auth(BaseAuth):
    """S3签名验证认证模块
    
    此模式下：
    1. 客户端使用固定用户名登录（无需密码或任意密码）
    2. 通过 get 命令提供带签名的S3 URL
    3. 在handler中验证URL签名并使用配置的凭证访问S3
    """
    
    def __init__(self):
        cfg = get_config()
        self._s3_config = cfg.auth.get('s3', {})
        
        # 配置
        self._enabled = self._s3_config.get('enabled', False)
        self._username = self._s3_config.get('username', 's3')

    def authenticate(self, username: str, password: str, client_ip: str) -> AuthResult:
        """认证入口 - 只需验证用户名"""
        if not self._enabled:
            return AuthResult(
                success=False,
                paths=[],
                download_limits={},
                session_id="",
                error="S3 auth not enabled"
            )
        
        if username != self._username:
            return AuthResult(
                success=False,
                paths=[],
                download_limits={},
                session_id="",
                error=f"Invalid username. Expected: {self._username}"
            )
        
        # 用户名匹配即可，密码忽略
        session_id = str(uuid.uuid4())
        
        sftp_log("AUTH_SUCCESS", f"mode=s3 username={username} client={client_ip}")
        
        return AuthResult(
            success=True,
            paths=['/'],  # 允许访问所有路径，实际权限由URL签名控制
            download_limits={},
            session_id=session_id,
            error=None,
            extra_data={
                's3_mode': True
            }
        )
