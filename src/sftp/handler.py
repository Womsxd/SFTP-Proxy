import os
import errno
import time
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote
from paramiko import SFTPServerInterface, SFTPHandle, SFTPAttributes
from paramiko.transport import Transport
from src.sftp.session import Session
from src.storage.base import StorageBackend
from src.config import get_config
from src.logger import sftp_log


class RateLimitedFileWrapper:
    """限速文件包装器"""
    
    def __init__(self, file_obj, rate_limit_kb: int):
        self.file_obj = file_obj
        self.rate_limit_kb = rate_limit_kb
        self.rate_limit_bytes = rate_limit_kb * 1024 if rate_limit_kb > 0 else 0
        self.last_read_time = time.time()
        self.bytes_read_in_window = 0
        self.window_start = time.time()
        
    def seek(self, offset: int):
        if self.file_obj:
            self.file_obj.seek(offset)
            
    def read(self, length: int) -> bytes:
        if self.file_obj is None:
            return b''
            
        if self.rate_limit_bytes <= 0:
            return self.file_obj.read(length)
        
        current_time = time.time()
        time_elapsed = current_time - self.window_start
        
        if time_elapsed >= 1.0:
            self.window_start = current_time
            self.bytes_read_in_window = 0
            time_elapsed = 0
        
        bytes_allowed = int(self.rate_limit_bytes * (1.0 - time_elapsed)) - self.bytes_read_in_window
        bytes_allowed = max(0, bytes_allowed)
        bytes_to_read = min(length, bytes_allowed)
        
        if bytes_to_read <= 0:
            sleep_time = 1.0 - time_elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.window_start = time.time()
            self.bytes_read_in_window = 0
            bytes_to_read = min(length, self.rate_limit_bytes)
        
        data = self.file_obj.read(bytes_to_read)
        self.bytes_read_in_window += len(data)
        return data
        
    def close(self):
        if self.file_obj:
            self.file_obj.close()
            self.file_obj = None
            
    def __getattr__(self, name):
        return getattr(self.file_obj, name)


class ReadOnlySFTPHandle(SFTPHandle):
    def __init__(self, file_obj, filename: str = "", rate_limit_kb: int = 0):
        super().__init__()
        self.filename = filename
        self._content_length = getattr(file_obj, 'content_length', 0)
        if rate_limit_kb > 0:
            self.file_obj = RateLimitedFileWrapper(file_obj, rate_limit_kb)
        else:
            self.file_obj = file_obj

    def read(self, offset: int, length: int):
        if self.file_obj is None:
            return b''
        self.file_obj.seek(offset)
        return self.file_obj.read(length)

    def stat(self):
        attr = SFTPAttributes()
        attr.filename = self.filename
        attr.st_size = self._content_length
        attr.st_uid = 1000
        attr.st_gid = 1000
        attr.st_mode = 0o644
        attr.st_atime = int(time.time())
        attr.st_mtime = int(time.time())
        return attr

    def chattr(self, attr):
        return 0

    def close(self):
        if self.file_obj:
            self.file_obj.close()
            self.file_obj = None


class S3URLValidator:
    """S3 URL签名验证器"""
    
    @staticmethod
    def is_s3_url(path: str) -> bool:
        """检查是否为S3 URL"""
        if not path.startswith('http'):
            return False
        return 'amazonaws.com' in path or 's3' in path
    
    @staticmethod
    def has_signature(path: str) -> bool:
        """检查URL是否包含签名参数"""
        return 'X-Amz-Signature=' in path or ('Signature=' in path and 'AWSAccessKeyId=' in path)
    
    @staticmethod
    def parse_s3_url(url: str) -> tuple[str, str, dict]:
        """解析S3 URL，返回(bucket, key, params)"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        path = unquote(parsed.path)
        
        bucket = ''
        key = ''
        
        # 格式1: bucket.s3.amazonaws.com/key
        if '.s3.' in parsed.netloc or '.s3-' in parsed.netloc:
            bucket = parsed.netloc.split('.s3')[0]
            key = path.lstrip('/')
        # 格式2: s3.amazonaws.com/bucket/key
        elif 's3.amazonaws.com' in parsed.netloc:
            path_parts = path.lstrip('/').split('/', 1)
            if len(path_parts) >= 2:
                bucket = path_parts[0]
                key = path_parts[1]
            else:
                bucket = path_parts[0] if path_parts else ''
        
        return bucket, key, params
    
    @staticmethod
    def verify_signature(url: str) -> tuple[bool, Optional[str]]:
        """验证S3 URL签名
        
        简化验证：检查必要的签名参数是否存在
        """
        bucket, key, params = S3URLValidator.parse_s3_url(url)
        
        if not bucket or not key:
            return False, "Invalid URL: cannot extract bucket or key"
        
        # 检查V4签名
        if 'X-Amz-Signature' in params:
            required = ['X-Amz-Algorithm', 'X-Amz-Credential', 'X-Amz-Date', 
                       'X-Amz-Expires', 'X-Amz-SignedHeaders']
            for param in required:
                if param not in params:
                    return False, f"Missing required parameter: {param}"
            
            algorithm = params.get('X-Amz-Algorithm', [''])[0]
            if algorithm != 'AWS4-HMAC-SHA256':
                return False, f"Unsupported algorithm: {algorithm}"
            
            return True, None
        
        # 检查V2签名
        elif 'Signature' in params and 'AWSAccessKeyId' in params:
            return True, None
        
        return False, "URL does not contain AWS signature parameters"


class SFTPHandler(SFTPServerInterface):
    def __init__(self, server: Transport, session: Session, storage: StorageBackend,
                 token: str = "", s3_mode: bool = False, storage_type: str = "disk"):
        self.server = server
        self.session = session
        self.storage = storage
        self.token = token
        self.root = '/'
        self.sftp_log = sftp_log
        self.s3_mode = s3_mode
        self.storage_type = storage_type  # disk 或 s3
        
        # 获取限速配置
        cfg = get_config()
        self.rate_limit_kb = cfg.server.get('rate_limit', 0)

    def _check_timeout(self) -> bool:
        if self.session.is_timeout():
            self.sftp_log("TIMEOUT", f"session={self.session.session_id[:8]}... reason=connection_timeout", "WARN")
            return True
        return False

    def _update_activity(self):
        self.session.update_activity()

    def open(self, path: str, flags: int, attr=None):
        """打开文件"""
        if self._check_timeout():
            raise OSError(errno.ETIMEDOUT, "Connection timeout")
        
        self._update_activity()
        self.sftp_log("OPEN", f"path={path} allowed_paths={self.session.allowed_paths}", "DEBUG")

        # S3签名验证模式：验证URL签名后根据后端类型访问文件
        if self.s3_mode:
            if not S3URLValidator.is_s3_url(path):
                raise OSError(errno.EINVAL, "S3 mode requires S3 URL (http://bucket.s3.amazonaws.com/key?signature)")
            
            if not S3URLValidator.has_signature(path):
                raise OSError(errno.EINVAL, "S3 URL must contain AWS signature parameters")
            
            # 验证签名（鉴权）
            is_valid, error = S3URLValidator.verify_signature(path)
            if not is_valid:
                self.sftp_log("ACCESS_DENIED", f"path={path[:80]}... reason={error}", "WARN")
                raise OSError(errno.EACCES, f"Invalid S3 signature: {error}")
            
            # 签名验证通过，解析URL获取文件路径
            bucket, key, params = S3URLValidator.parse_s3_url(path)
            
            # 根据后端类型决定文件路径
            if self.storage_type == "disk":
                # disk后端：直接使用key作为本地文件路径
                file_path = f"/{key}"
                self.sftp_log("S3_DISK_DOWNLOAD", f"path={file_path} url={path[:80]}...")
            else:
                # s3后端：使用 /bucket/key 格式
                file_path = f"/{bucket}/{key}"
                self.sftp_log("S3_S3_DOWNLOAD", f"bucket={bucket} key={key} url={path[:80]}...")
            
            # 添加路径检查：即使S3签名验证通过，也要检查是否在允许的路径范围内
            if not self.session.check_path(file_path):
                self.sftp_log("ACCESS_DENIED", f"path={file_path} reason=s3_path_not_in_allowed_paths", "WARN")
                raise OSError(errno.EACCES, f"Path not allowed: {file_path}")
            
            try:
                file_obj = self.storage.open(file_path, 'rb')
                size = getattr(file_obj, 'content_length', 0)
                filename = key.split('/')[-1] if '/' in key else key
                self.sftp_log("DOWNLOAD", f"path={file_path} size={size} rate_limit={self.rate_limit_kb}KB/s")
                return ReadOnlySFTPHandle(file_obj, filename=filename, rate_limit_kb=self.rate_limit_kb)
            except FileNotFoundError:
                raise OSError(errno.ENOENT, f"File not found: {key}")
            except PermissionError as e:
                self.sftp_log("PERMISSION_DENIED", f"path={file_path} reason={str(e)}", "ERROR")
                raise OSError(errno.EACCES, str(e))
            except Exception as e:
                self.sftp_log("OPEN_ERROR", f"path={file_path} error={str(e)}", "ERROR")
                raise OSError(errno.EIO, str(e))
        
        # 普通模式（Token/JWT）
        if not self.session.check_path(path):
            self.sftp_log("ACCESS_DENIED", f"path={path} reason=path_not_allowed", "WARN")
            raise OSError(errno.EACCES, "Path not allowed")

        allowed, current, limit = self.session.check_download_limit(path)
        if not allowed:
            self.sftp_log("DOWNLOAD_LIMIT", f"path={path} limit={limit} current={current}", "WARN")
            raise OSError(errno.EPERM, "Download limit exceeded")

        try:
            file_obj = self.storage.open(path, 'rb')
            size = getattr(file_obj, 'content_length', 0)
            self.sftp_log("DOWNLOAD", f"path={path} size={size} token={self.token[:8] if self.token else 'none'}... rate_limit={self.rate_limit_kb}KB/s")

            if limit is not None:
                self.sftp_log("DOWNLOAD", f"path={path} limit={limit} current={current+1}")

            return ReadOnlySFTPHandle(file_obj, filename=path, rate_limit_kb=self.rate_limit_kb)
        except FileNotFoundError:
            raise OSError(errno.ENOENT, f"File not found: {path}")
        except PermissionError as e:
            self.sftp_log("PERMISSION_DENIED", f"path={path} reason={str(e)}", "ERROR")
            raise OSError(errno.EACCES, str(e))
        except Exception as e:
            self.sftp_log("OPEN_ERROR", f"path={path} error={str(e)}", "ERROR")
            raise OSError(errno.EIO, str(e))

    def list_folder(self, path: str) -> list:
        """列出目录"""
        self.sftp_log("LIST_ENTRY", f"path={path} session={self.session is not None}", "DEBUG")
        
        if self._check_timeout():
            raise OSError(errno.ETIMEDOUT, "Connection timeout")
        
        self._update_activity()
        self.sftp_log("LIST", f"path={path} allowed_paths={self.session.allowed_paths}", "DEBUG")

        # S3签名验证模式下不允许列出目录
        if self.s3_mode:
            self.sftp_log("LIST_BLOCKED", f"path={path} reason=s3_mode_only_get_allowed", "WARN")
            raise OSError(errno.EACCES, "List operation not allowed in S3 signature mode. Only 'get' command with S3 URL is supported.")

        # 如果路径被允许，正常列出
        if self.session.check_path(path):
            self.sftp_log("LIST_ALLOWED", f"path={path}", "DEBUG")
            try:
                items = self.storage.list(path)
                results = []
                for item in items:
                    attr = SFTPAttributes()
                    attr.filename = item.filename
                    attr.longname = item.longname
                    attr.st_size = item.size
                    attr.st_uid = item.uid
                    attr.st_gid = item.gid
                    attr.st_atime = item.atime
                    attr.st_mtime = item.mtime
                    attr.st_mode = item.perm
                    results.append(attr)
                self.sftp_log("LIST", f"path={path} count={len(results)}")
                return results
            except FileNotFoundError:
                raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
            except PermissionError as e:
                self.sftp_log("PERMISSION_DENIED", f"path={path} reason={str(e)}", "ERROR")
                raise OSError(errno.EACCES, os.strerror(errno.EACCES))
        
        # 路径本身不被允许，检查是否有授权的文件在该目录下
        # 支持单文件访问场景：token 只配置了文件路径时，ls 显示该文件
        normalized_path = path.rstrip('/') if path != '/' else '/'
        files_in_dir = []
        for allowed_path in self.session.allowed_paths:
            allowed_dir = os.path.dirname(allowed_path)
            if allowed_dir == normalized_path or (normalized_path == '/' and allowed_dir in ('', '/')):
                try:
                    item = self.storage.stat(allowed_path)
                    attr = SFTPAttributes()
                    attr.filename = os.path.basename(allowed_path)
                    attr.longname = item.longname if hasattr(item, 'longname') else attr.filename
                    attr.st_size = item.size if hasattr(item, 'size') else 0
                    attr.st_uid = item.uid if hasattr(item, 'uid') else 1000
                    attr.st_gid = item.gid if hasattr(item, 'gid') else 1000
                    attr.st_atime = int(item.atime if hasattr(item, 'atime') else time.time())
                    attr.st_mtime = int(item.mtime if hasattr(item, 'mtime') else time.time())
                    attr.st_mode = item.perm if hasattr(item, 'perm') else 0o644
                    files_in_dir.append(attr)
                    self.sftp_log("LIST_FILE_ADDED", f"file={allowed_path}", "DEBUG")
                except Exception as e:
                    self.sftp_log("LIST_STAT_ERROR", f"path={allowed_path} error={str(e)}", "DEBUG")
        
        if files_in_dir:
            self.sftp_log("LIST", f"path={path} count={len(files_in_dir)} (filtered)")
            return files_in_dir
        
        self.sftp_log("ACCESS_DENIED", f"path={path} allowed={self.session.allowed_paths}", "WARN")
        raise OSError(errno.EACCES, f"Path not allowed: {path}")

    def stat(self, path: str) -> SFTPAttributes:
        """获取文件状态"""
        if self._check_timeout():
            raise OSError(errno.ETIMEDOUT, "Connection timeout")
        
        self._update_activity()
        self.sftp_log("STAT", f"path={path} allowed={self.session.allowed_paths}", "DEBUG")

        # S3签名验证模式下简化处理
        if self.s3_mode:
            filename = path.split('/')[-1].split('?')[0] if '?' in path else path.split('/')[-1]
            attr = SFTPAttributes()
            attr.filename = filename or path
            attr.st_size = 0
            attr.st_uid = 1000
            attr.st_gid = 1000
            attr.st_mode = 0o644
            return attr

        # 优先检查路径是否在 allowed_paths 中
        if self.session.check_path(path):
            try:
                item = self.storage.stat(path)
                attr = SFTPAttributes()
                attr.filename = item.filename
                attr.longname = item.longname
                attr.st_size = item.size
                attr.st_uid = item.uid
                attr.st_gid = item.gid
                attr.st_atime = item.atime
                attr.st_mtime = item.mtime
                attr.st_mode = item.perm
                return attr
            except FileNotFoundError:
                raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
            except PermissionError as e:
                self.sftp_log("PERMISSION_DENIED", f"path={path} reason={str(e)}", "ERROR")
                raise OSError(errno.EACCES, os.strerror(errno.EACCES))
        
        # 路径不在 allowed_paths 中，检查是否是授权文件本身
        if path in self.session.allowed_paths:
            try:
                item = self.storage.stat(path)
                attr = SFTPAttributes()
                attr.filename = os.path.basename(path)
                attr.longname = item.longname if hasattr(item, 'longname') else attr.filename
                attr.st_size = item.size if hasattr(item, 'size') else 0
                attr.st_uid = item.uid if hasattr(item, 'uid') else 1000
                attr.st_gid = item.gid if hasattr(item, 'gid') else 1000
                attr.st_atime = item.atime if hasattr(item, 'atime') else int(time.time())
                attr.st_mtime = item.mtime if hasattr(item, 'mtime') else int(time.time())
                attr.st_mode = item.perm if hasattr(item, 'perm') else 0o644
                return attr
            except Exception as e:
                self.sftp_log("STAT_ERROR", f"path={path} error={str(e)}", "ERROR")
        
        self.sftp_log("ACCESS_DENIED", f"path={path} reason=path_not_allowed", "WARN")
        raise OSError(errno.EACCES, os.strerror(errno.EACCES))

    def lstat(self, path: str) -> SFTPAttributes:
        return self.stat(path)

    def canonicalize(self, path: str) -> str:
        path = path.replace('\\', '/')
        while '//' in path:
            path = path.replace('//', '/')
        parts = path.split('/')
        result = []
        for part in parts:
            if part == '' or part == '.':
                continue
            elif part == '..':
                if result:
                    result.pop()
            else:
                result.append(part)
        path = '/' + '/'.join(result) if result else '/'
        return path

    def realpath(self, path: str) -> str:
        return self.canonicalize(path)

    def chattr(self, path: str, attr: SFTPAttributes) -> int:
        self.sftp_log("CHATTR_BLOCKED", f"path={path}", "WARN")
        raise OSError(errno.EPERM, "Write operations not allowed")

    def mkdir(self, path: str, attr: SFTPAttributes) -> int:
        self.sftp_log("MKDIR_BLOCKED", f"path={path}", "WARN")
        raise OSError(errno.EPERM, "Write operations not allowed")

    def rmdir(self, path: str) -> int:
        self.sftp_log("RMDIR_BLOCKED", f"path={path}", "WARN")
        raise OSError(errno.EPERM, "Write operations not allowed")

    def rm(self, path: str) -> int:
        self.sftp_log("REMOVE_BLOCKED", f"path={path}", "WARN")
        raise OSError(errno.EPERM, "Write operations not allowed")

    def rename(self, oldpath: str, newpath: str) -> int:
        self.sftp_log("RENAME_BLOCKED", f"oldpath={oldpath} newpath={newpath}", "WARN")
        raise OSError(errno.EPERM, "Write operations not allowed")

    def symlink(self, target_path: str, path: str) -> int:
        self.sftp_log("SYMLINK_BLOCKED", f"target={target_path} link={path}", "WARN")
        raise OSError(errno.EPERM, "Write operations not allowed")

    def readlink(self, path: str) -> str:
        raise OSError(errno.EINVAL, "Not supported")

    def posix_rename(self, oldpath: str, newpath: str) -> int:
        return self.rename(oldpath, newpath)
