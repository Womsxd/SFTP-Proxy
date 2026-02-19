import os
import socket
import threading
import paramiko
from paramiko.server import ServerInterface
from paramiko.transport import Transport
from paramiko.sftp_server import SFTPServer as BaseSFTPServer
from src.auth.base import BaseAuth, AuthResult
from src.auth.token_auth import TokenAuth
from src.auth.jwt_auth import JWTAuth
from src.auth.s3_auth import S3Auth
from src.sftp.session import Session
from src.sftp.handler import SFTPHandler
from src.storage.registry import get_storage
from src.config import get_config
from src.redis_client import RedisClient
from src.logger import sftp_log


SUPPORTED_KEY_TYPES = ['rsa', 'ecdsa', 'ed25519']


def _generate_key(key_type: str) -> paramiko.PKey:
    key_type = key_type.lower()
    if key_type == 'rsa':
        return paramiko.RSAKey.generate(2048)
    elif key_type == 'ecdsa':
        return paramiko.ECDSAKey.generate()
    elif key_type == 'ed25519':
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        from io import BytesIO
        private_key = Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return paramiko.Ed25519Key.from_private_key(BytesIO(pem))
    else:
        raise ValueError(f"Unsupported key type: {key_type}. Supported: {SUPPORTED_KEY_TYPES}")


def _get_key_class(key_type: str):
    key_type = key_type.lower()
    if key_type == 'rsa':
        return paramiko.RSAKey
    elif key_type == 'ecdsa':
        return paramiko.ECDSAKey
    elif key_type == 'ed25519':
        return paramiko.Ed25519Key
    else:
        raise ValueError(f"Unsupported key type: {key_type}. Supported: {SUPPORTED_KEY_TYPES}")


def generate_host_key(key_path: str, key_type: str = 'rsa') -> paramiko.PKey:
    key_type = key_type.lower()
    if key_type not in SUPPORTED_KEY_TYPES:
        raise ValueError(f"Unsupported key type: {key_type}. Supported: {SUPPORTED_KEY_TYPES}")
    
    sftp_log("KEY_GEN", f"Generating new {key_type.upper()} host key: {key_path}")
    
    key = _generate_key(key_type)
    key.write_private_key_file(key_path)
    
    return key


def load_or_generate_host_key(key_path: str, key_type: str = 'rsa') -> paramiko.PKey:
    key_type = key_type.lower()
    if key_type not in SUPPORTED_KEY_TYPES:
        raise ValueError(f"Unsupported key type: {key_type}. Supported: {SUPPORTED_KEY_TYPES}")
    
    if not os.path.exists(key_path):
        return generate_host_key(key_path, key_type)
    
    key_class = _get_key_class(key_type)
    return key_class.from_private_key_file(key_path)


def _create_handler_factory(sftp_si_class):
    """创建SFTPHandler工厂函数，用于从serverinterface获取自定义参数"""
    def handler_factory(server, *args, **kwargs):
        si = server
        session = getattr(si, 'session', None)
        storage = getattr(si, 'storage', None)
        token = getattr(si, 'token', '')
        s3_mode = getattr(si, 's3_mode', False)
        storage_type = getattr(si, 'storage_type', 'disk')
        return sftp_si_class(server, session, storage, token, s3_mode, storage_type)
    return handler_factory


class CustomSFTPServer(BaseSFTPServer):
    """自定义SFTPServer，支持从SFTPInterface动态获取参数"""
    
    def __init__(self, channel, name, server, sftp_si, session, storage, token, s3_mode, storage_type):
        handler_factory = _create_handler_factory(sftp_si)
        super().__init__(channel, name, server, sftp_si=handler_factory)


class SFTPInterface(ServerInterface):
    def __init__(self, client_address: tuple, host_key: str):
        self.client_address = client_address
        self.host_key = host_key
        self.session = None
        self.auth_result = None
        self.token = None
        self.storage = None
        self.s3_mode = False
        self.storage_type = 'disk'

    def check_channel_request(self, kind: str, chanid: int):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str):
        cfg = get_config()
        auth_type = cfg.auth.get('type', 'token')

        if auth_type == 'token':
            auth = TokenAuth()
        elif auth_type == 'jwt':
            auth = JWTAuth()
        elif auth_type == 's3':
            auth = S3Auth()
        else:
            sftp_log("AUTH_ERROR", f"unknown_auth_type={auth_type}", "ERROR")
            return paramiko.AUTH_FAILED

        client_ip = self.client_address[0]
        result = auth.authenticate(username, password, client_ip)

        if result.success:
            self.auth_result = result
            # Token模式：username就是token；JWT模式：password是JWT token
            if auth_type == 'token':
                self.token = username
            elif auth_type == 'jwt':
                self.token = password
            else:
                self.token = None
            redis_client = RedisClient()
            self.session = Session(
                session_id=result.session_id,
                allowed_paths=result.paths,
                download_limits=result.download_limits,
                token=self.token,
                redis_client=redis_client
            )
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key):
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_with_mic(self, username: str, gss_authenticated, cc_file):
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(self, username: str, gss_authenticated, cc_file):
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        return False

    def get_allowed_auths(self, username: str):
        return "password"

    def check_channel_shell_request(self, channel):
        return False

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return False

    def check_channel_exec_request(self, channel, command):
        return False

    def check_channel_subsystem_request(self, channel, name: str):
        if name == 'sftp' and self.auth_result:
            cfg = get_config()
            auth_type = cfg.auth.get('type', 'token')
            
            storage_type = cfg.storage.get('type', 'disk')
            s3_mode = False
            
            if auth_type == 's3' and self.auth_result.extra_data:
                s3_mode = self.auth_result.extra_data.get('s3_mode', False)
                if storage_type == 's3':
                    s3_config = {
                        'access_key': cfg.auth.get('s3', {}).get('access_key'),
                        'secret_key': cfg.auth.get('s3', {}).get('secret_key'),
                        'region': cfg.auth.get('s3', {}).get('region', 'us-east-1'),
                        'endpoint': cfg.storage.get('s3', {}).get('endpoint'),
                        'bucket': cfg.storage.get('s3', {}).get('bucket')
                    }
                    from src.storage.s3 import S3Storage
                    self.storage = S3Storage(config=s3_config)
                else:
                    self.storage = get_storage('disk')
            else:
                self.storage = get_storage()
            
            self.s3_mode = s3_mode
            self.storage_type = storage_type
            
            sftp = CustomSFTPServer(
                channel, 
                'sftp', 
                self, 
                sftp_si=SFTPHandler,
                session=self.session,
                storage=self.storage,
                token=self.token,
                s3_mode=self.s3_mode,
                storage_type=self.storage_type
            )
            return True
        return False


class ClientHandler(threading.Thread):
    """处理单个客户端连接的线程"""
    
    def __init__(self, client_socket, addr, host_key, host_key_type):
        super().__init__(daemon=True)
        self.client_socket = client_socket
        self.addr = addr
        self.host_key = host_key
        self.host_key_type = host_key_type
        self.transport = None
        
    def run(self):
        try:
            self.transport = Transport(self.client_socket)
            self.transport.add_server_key(self._load_host_key())
            # 注册 SFTP handler，让 check_channel_subsystem_request 处理子系统请求
            # 注意：这里使用 BaseSFTPServer 作为基础，实际的 SFTPHandler 在 check_channel_subsystem_request 中通过 CustomSFTPServer 创建
            self.transport.set_subsystem_handler('sftp', BaseSFTPServer)
            
            server = SFTPInterface(self.addr, self.host_key)
            self.transport.start_server(server=server)
            
            # 等待连接关闭
            while self.transport.is_active():
                self.transport.join(timeout=1.0)
                
        except Exception as e:
            sftp_log("CLIENT_ERROR", f"client={self.addr[0]}:{self.addr[1]} error={str(e)}", "ERROR")
        finally:
            if self.transport:
                self.transport.close()
            try:
                self.client_socket.close()
            except:
                pass
            sftp_log("DISCONNECT", f"client={self.addr[0]}:{self.addr[1]}")
    
    def _load_host_key(self) -> paramiko.PKey:
        return load_or_generate_host_key(self.host_key, self.host_key_type)


class SFTPServerThread(threading.Thread):
    def __init__(self, host: str, port: int, host_key: str, host_key_type: str = 'rsa'):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.host_key = host_key
        self.host_key_type = host_key_type
        self.socket = None
        self.running = False
        self.clients = []

    def run(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(100)
        self.running = True

        sftp_log("SERVER_START", f"SFTP server started on {self.host}:{self.port}")

        while self.running:
            try:
                self.socket.settimeout(1.0)
                try:
                    client, addr = self.socket.accept()
                except socket.timeout:
                    continue

                sftp_log("CONNECT", f"client={addr[0]}:{addr[1]}")
                
                # 为每个客户端创建独立线程
                client_handler = ClientHandler(client, addr, self.host_key, self.host_key_type)
                client_handler.start()
                self.clients.append(client_handler)
                
                # 清理已结束的客户端线程
                self.clients = [c for c in self.clients if c.is_alive()]

            except Exception as e:
                if self.running:
                    sftp_log("CONNECTION_ERROR", f"error={str(e)}", "ERROR")

    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
        # 等待所有客户端线程结束
        for client in self.clients:
            if client.is_alive():
                client.join(timeout=2.0)
        sftp_log("SERVER_STOP", "SFTP server stopped")

    def _load_host_key(self) -> paramiko.PKey:
        return load_or_generate_host_key(self.host_key, self.host_key_type)


def start_sftp_server(host: str = None, port: int = None, host_key: str = None, host_key_type: str = None) -> SFTPServerThread:
    cfg = get_config()
    host = host or cfg.server.get('host', '0.0.0.0')
    port = port or cfg.server.get('sftp_port', 2222)
    host_key = host_key or cfg.server.get('host_key', './ssh_host_key')
    host_key_type = host_key_type or cfg.server.get('host_key_type', 'rsa')

    server = SFTPServerThread(host, port, host_key, host_key_type)
    server.start()
    return server
