import io
import time
import boto3
from botocore.exceptions import ClientError
from typing import BinaryIO, Optional, Any
from src.storage.base import StorageBackend, SFTPAttr
from src.config import get_config


class S3SeekableFileWrapper(io.BufferedIOBase):
    """支持 seek 的 S3 文件包装器，使用 Range 请求实现范围读取"""
    
    def __init__(self, client, bucket: str, key: str, size: int):
        self._client = client
        self._bucket = bucket
        self._key = key
        self._size = size
        self._offset = 0
        self._closed = False
        self._buffer: Optional[io.BytesIO] = io.BytesIO()
        self._buffer_start = 0
        self._chunk_size = 64 * 1024
        
    @property
    def content_length(self) -> int:
        return self._size
    
    def seek(self, offset: int, whence: int = 0) -> int:
        if self._closed:
            raise ValueError("I/O operation on closed file")
        
        if whence == 0:
            new_offset = offset
        elif whence == 1:
            new_offset = self._offset + offset
        elif whence == 2:
            new_offset = self._size + offset
        else:
            raise ValueError(f"Invalid whence value: {whence}")
        
        self._offset = max(0, min(new_offset, self._size))
        return self._offset
    
    def tell(self) -> int:
        return self._offset
    
    def read(self, size: Optional[int] = None) -> bytes:
        if self._closed:
            raise ValueError("I/O operation on closed file")
        
        if self._offset >= self._size:
            return b''
        
        if size is None or size < 0:
            size = self._size - self._offset
        else:
            size = min(size, self._size - self._offset)
        
        if size == 0:
            return b''
        
        buffer = self._buffer
        if buffer is None or self._offset < self._buffer_start or self._offset >= self._buffer_start + len(buffer.getvalue()):
            self._fetch_chunk(self._offset)
            buffer = self._buffer
        
        if buffer is None:
            return b''
        
        buffer_data = buffer.getvalue()
        buffer_offset = self._offset - self._buffer_start
        available = len(buffer_data) - buffer_offset
        
        if available >= size:
            result = buffer_data[buffer_offset:buffer_offset + size]
            self._offset += size
            return result
        
        result = buffer_data[buffer_offset:]
        remaining = size - len(result)
        self._offset += len(result)
        
        while remaining > 0 and self._offset < self._size:
            self._fetch_chunk(self._offset)
            buffer = self._buffer
            if buffer is None:
                break
            buffer_data = buffer.getvalue()
            chunk_read = min(remaining, len(buffer_data))
            result += buffer_data[:chunk_read]
            self._offset += chunk_read
            remaining -= chunk_read
        
        return result
    
    def _fetch_chunk(self, start: int):
        end = min(start + self._chunk_size, self._size - 1)
        range_header = f"bytes={start}-{end}"
        
        try:
            response = self._client.get_object(
                Bucket=self._bucket,
                Key=self._key,
                Range=range_header
            )
            self._buffer = io.BytesIO(response['Body'].read())
            self._buffer_start = start
        except ClientError as e:
            raise IOError(f"Failed to read from S3: {e}")
    
    def close(self):
        if not self._closed:
            self._closed = True
            self._buffer = None
    
    @property
    def closed(self) -> bool:
        return self._closed
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return None
    
    def readable(self) -> bool:
        return True
    
    def seekable(self) -> bool:
        return True


class S3Storage(StorageBackend):
    def __init__(self, config: Optional[dict] = None, session_creds: Optional[dict] = None):
        """
        S3存储后端
        
        Args:
            config: 存储配置
            session_creds: 透传模式的会话凭证（包含access_key, secret_key, bucket, region）
        """
        cfg = get_config()
        
        if session_creds:
            # 透传模式：使用会话凭证
            self._bucket = session_creds.get('bucket', 'my-bucket')
            self._endpoint = session_creds.get('endpoint') or cfg.storage.get('s3', {}).get('endpoint')
            self._region = session_creds.get('region', 'us-east-1')
            access_key = session_creds.get('access_key')
            secret_key = session_creds.get('secret_key')
        else:
            # 普通模式：使用配置
            s3_config = config or cfg.storage.get('s3', {})
            self._bucket = s3_config.get('bucket', 'my-bucket')
            self._endpoint = s3_config.get('endpoint', 'https://s3.amazonaws.com')
            self._region = s3_config.get('region', 'us-east-1')
            access_key = s3_config.get('access_key')
            secret_key = s3_config.get('secret_key')

        client_kwargs = {
            'service_name': 's3',
            'region_name': self._region,
        }

        if self._endpoint:
            client_kwargs['endpoint_url'] = self._endpoint

        if access_key and secret_key:
            client_kwargs['aws_access_key_id'] = access_key
            client_kwargs['aws_secret_access_key'] = secret_key

        self._client = boto3.client(**client_kwargs)
        
        resource_kwargs = {
            'service_name': 's3',
            'region_name': self._region,
        }
        if self._endpoint:
            resource_kwargs['endpoint_url'] = self._endpoint
        if access_key and secret_key:
            resource_kwargs['aws_access_key_id'] = access_key
            resource_kwargs['aws_secret_access_key'] = secret_key
            
        self._resource = boto3.resource(**resource_kwargs)

    def _normalize_key(self, path: str) -> str:
        path = self.normalize_path(path)
        if path == '/':
            return ''
        return path.lstrip('/')

    def list(self, path: str) -> list[SFTPAttr]:
        prefix = self._normalize_key(path)
        if prefix and not prefix.endswith('/'):
            prefix += '/'

        try:
            response = self._client.list_objects_v2(
                Bucket=self._bucket,
                Prefix=prefix,
                Delimiter='/'
            )
        except ClientError as e:
            raise FileNotFoundError(f"Failed to list: {e}")

        results = []

        if 'CommonPrefixes' in response:
            for obj in response['CommonPrefixes']:
                key = obj['Prefix'].rstrip('/')
                name = key.split('/')[-1]
                results.append(SFTPAttr(
                    filename=name,
                    longname=f"drwxr-xr-x  1  1000  1000        0 {time.strftime('%b %d %H:%M')} {name}",
                    size=0,
                    uid=1000,
                    gid=1000,
                    atime=0,
                    mtime=0,
                    perm=0o755,
                    is_dir=True
                ))

        if 'Contents' in response:
            for obj in response['Contents']:
                key = obj['Key']
                if key == prefix:
                    continue
                name = key.split('/')[-1]
                size = obj['Size']
                last_modified = obj['LastModified'].timestamp() if obj.get('LastModified') else 0

                results.append(SFTPAttr(
                    filename=name,
                    longname=f"-rw-r--r--  1  1000  1000  {size:>8} {time.strftime('%b %d %H:%M', time.localtime(last_modified))} {name}",
                    size=size,
                    uid=1000,
                    gid=1000,
                    atime=int(last_modified),
                    mtime=int(last_modified),
                    perm=0o644,
                    is_dir=False
                ))

        return results

    def open(self, path: str, mode: str) -> Any:
        if 'w' in mode or 'a' in mode or '+' in mode:
            raise PermissionError("Write operations not allowed")

        key = self._normalize_key(path)
        if not key:
            raise FileNotFoundError(f"Invalid path: {path}")

        try:
            head_response = self._client.head_object(Bucket=self._bucket, Key=key)
            size = head_response.get('ContentLength', 0)
            return S3SeekableFileWrapper(self._client, self._bucket, key, size)
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'NoSuchKey':
                raise FileNotFoundError(f"File not found: {path}")
            raise PermissionError(f"Failed to open: {e}")

    def stat(self, path: str) -> SFTPAttr:
        key = self._normalize_key(path)
        if not key:
            raise FileNotFoundError(f"Invalid path: {path}")

        try:
            response = self._client.head_object(Bucket=self._bucket, Key=key)
            size = response.get('ContentLength', 0)
            last_modified = response.get('LastModified')
            mtime = int(last_modified.timestamp()) if last_modified else 0

            return SFTPAttr(
                filename=path.split('/')[-1],
                longname=f"-rw-r--r--  1  1000  1000  {size:>8} {time.strftime('%b %d %H:%M', time.localtime(mtime))} {path.split('/')[-1]}",
                size=size,
                uid=1000,
                gid=1000,
                atime=mtime,
                mtime=mtime,
                perm=0o644,
                is_dir=False
            )
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ('404', 'NoSuchKey'):
                if self.is_dir(path):
                    return SFTPAttr(
                        filename=path.split('/')[-1],
                        longname=f"drwxr-xr-x  1  1000  1000        0 {time.strftime('%b %d %H:%M')} {path.split('/')[-1]}",
                        size=0,
                        uid=1000,
                        gid=1000,
                        atime=0,
                        mtime=0,
                        perm=0o755,
                        is_dir=True
                    )
                raise FileNotFoundError(f"Path not found: {path}")
            raise PermissionError(f"Failed to stat: {e}")

    def exists(self, path: str) -> bool:
        key = self._normalize_key(path)
        if not key:
            return True

        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
            return True
        except ClientError:
            return self.is_dir(path)

    def is_dir(self, path: str) -> bool:
        prefix = self._normalize_key(path)
        if prefix and not prefix.endswith('/'):
            prefix += '/'

        try:
            response = self._client.list_objects_v2(
                Bucket=self._bucket,
                Prefix=prefix,
                MaxKeys=1
            )
            return 'Contents' in response or 'CommonPrefixes' in response
        except ClientError:
            return False
