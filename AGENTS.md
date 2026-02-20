# SFTP Proxy 项目架构文档

## 项目概述

一个Python SFTP前置代理服务，支持多种认证方式（Token、JWT、S3签名验证），用户鉴权后只能读取对应文件，支持disk/s3作为文件后端。

**三种认证模式：**
- **Token模式**: 用户名即token，支持标准SFTP操作（ls/cd/get）
- **JWT模式**: 固定用户名 + JWT token密码，支持标准SFTP操作
- **S3签名验证模式**: 延迟鉴权，仅支持get命令，通过带签名的S3 URL访问文件

## 核心特性

- **多种认证方式**: Token (Redis)、JWT (Redis可选)、AWS S3签名
- **下载次数限制**: 支持限制单个文件下载次数
- **多存储后端**: Disk本地存储、S3对象存储
- **独立日志**: API日志与SFTP日志分离，按日期自动切割
- **配置热重载**: HTTP API和命令行支持配置重载
- **管理API**: HTTP接口管理token创建/撤销/查询

## 项目结构

```
sftp_proxy/
├── src/
│   ├── __init__.py
├── main.py                     # 入口：SFTP + HTTP服务（根目录）
├── src/sftp/server.py          # SFTP服务器启动
│   ├── config.py               # 配置加载与热重载
│   ├── logger.py               # 日志配置(按日期切割)
│   ├── redis_client.py         # Redis操作封装
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── base.py             # AuthResult, BaseAuth
│   │   ├── token_auth.py       # 简单Token认证
│   │   ├── jwt_auth.py         # JWT认证
│   │   └── s3_auth.py          # S3签名认证
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── base.py             # StorageBackend抽象类
│   │   ├── disk.py             # 本地磁盘存储
│   │   ├── s3.py               # S3存储后端
│   │   └── registry.py         # 存储后端注册(扩展预留)
│   ├── sftp/
│   │   ├── __init__.py
│   │   ├── handler.py          # SFTPServerInterface实现
│   │   └── session.py          # 会话管理与下载计数
│   └── api/
│       ├── __init__.py
│       ├── app.py              # FastAPI应用
│       ├── routes/
│       │   ├── __init__.py
│       │   ├── tokens.py       # Token CRUD
│       │   └── admin.py        # 配置重载等管理接口
│       ├── middleware.py       # Admin Token认证
│       └── dependencies.py     # 依赖注入
├── logs/
│   ├── api/
│   └── sftp/
├── data/                       # 本地存储默认目录
├── config.yaml
├── requirements.txt
└── README.md
```

## 配置文件 (config.yaml)

```yaml
server:
  host: 0.0.0.0
  sftp_port: 2222
  api_port: 8080
  host_key: ./ssh_host_key
  host_key_type: rsa              # rsa | ecdsa | ed25519（不存在时自动生成）
  connection_timeout: 300         # 连接超时（秒）
  operation_timeout: 60           # 操作超时（秒）
  rate_limit: 0                   # 下载限速（KB/s），0表示不限速

redis:
  host: localhost
  port: 6379
  db: 0
  password: null
  key_prefix: "sftp"

token:
  default_expire: 600           # 10分钟
  max_expire: 86400             # 24小时

auth:
  type: token                   # token | jwt | s3
  # Token模式: 用户名直接传入token，无需密码
  # JWT模式: 固定用户名 + JWT token密码
  # S3模式: 固定用户名 + 带签名的URL（延迟鉴权）
  jwt:
    username: "jwt"             # JWT模式固定用户名
    secret: your-jwt-secret
    algorithm: HS256
    issuer: sftp-proxy
    redis_enabled: false
  s3:
    # S3签名验证模式 - 客户端提供带签名的URL，服务器验证签名后访问文件
    enabled: false              # 是否启用S3签名验证模式
    username: "s3"              # S3模式固定用户名（默认s3）
    # 服务器使用的S3凭证（仅s3后端需要）
    access_key: null            # AWS Access Key ID
    secret_key: null            # AWS Secret Access Key  
    region: us-east-1           # AWS Region

storage:
  type: disk                    # disk | s3
  disk:
    root: ./data
  s3:
    bucket: my-bucket
    endpoint: https://s3.amazonaws.com
    access_key: your-ak
    secret_key: your-sk
    region: us-east-1

log:
  level: INFO
  dir: ./logs
  format: "%(asctime)s [%(levelname)s] [%(action)s] %(message)s"
  date_format: "%Y-%m-%d %H:%M:%S"

api:
  admin_token: your-admin-secret-token
```

## Redis数据结构

### 简单Token模式
```
sftp:token:{token_value}
  - paths: ["file1.txt", "dir1/"]
  - download_limits: {"file1.txt": 3}
  - rate_limit: 1024             # 下载限速（KB/s），null表示使用全局配置
  - created_at: timestamp
  - expires_at: timestamp

sftp:token:{token_value}:downloads
  - {path}: count
```

### JWT + Redis模式
```
sftp:jwt:blacklist:{token_hash}
  - revoked: true
  - expires_at: timestamp

sftp:jwt:{token_value}:downloads
  - {path}: count
```

## HTTP API 接口

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/tokens` | POST | 创建token |
| `/api/tokens/{token}` | GET | 查询token信息 |
| `/api/tokens/{token}` | DELETE | 撤销token |
| `/api/tokens/{token}/downloads` | GET | 查询下载统计 |
| `/api/admin/reload` | POST | 重载配置 |
| `/health` | GET | 健康检查 |

### 请求头
```
Authorization: Bearer <admin_token>
```

### 创建Token请求体
```json
{
  "paths": ["/file1.txt", "/dir1/"],
  "expire": 600,
  "download_limits": {"/file1.txt": 3},
  "rate_limit": 1024,
  "auth_type": "token"
}
```

**参数说明：**
- `paths`: 允许访问的路径列表（必填）
- `expire`: 过期时间（秒），默认使用配置中的default_expire
- `download_limits`: 下载次数限制，格式为 `{路径: 次数}`
- `rate_limit`: 下载限速（KB/s），null或不填则使用全局配置，优先级高于全局配置
- `auth_type`: 认证类型，`token` 或 `jwt`

## 日志格式

### API日志 (logs/api/api-YYYY-MM-DD.log)
```
2024-01-15 10:30:00 [INFO] [CREATE_TOKEN] token=abc123 paths=["file1.txt"] expire=600 ip=192.168.1.1
2024-01-15 10:35:00 [INFO] [REVOKE_TOKEN] token=abc123 ip=192.168.1.1
```

### SFTP日志 (logs/sftp/sftp-YYYY-MM-DD.log)
```
2024-01-15 10:31:00 [INFO] [CONNECT] client=192.168.1.100 user=anonymous
2024-01-15 10:31:05 [INFO] [AUTH_SUCCESS] token=abc123 paths=["file1.txt"]
2024-01-15 10:31:10 [INFO] [DOWNLOAD] token=abc123 path=file1.txt size=1024
2024-01-15 10:31:15 [WARN] [DOWNLOAD_LIMIT_EXCEEDED] token=abc123 path=file1.txt limit=3 current=4
2024-01-15 10:32:00 [ERROR] [AUTH_FAILED] reason=invalid_token ip=192.168.1.101
```

## 核心类设计

### auth/base.py
```python
@dataclass
class AuthResult:
    success: bool
    paths: list[str]
    download_limits: dict
    session_id: str
    rate_limit: Optional[int] = None
    error: Optional[str] = None
    extra_data: Optional[dict] = None

class BaseAuth(ABC):
    @abstractmethod
    def authenticate(self, username: str, password: str, client_ip: str) -> AuthResult:
        pass
```

### storage/base.py
```python
class StorageBackend(ABC):
    @abstractmethod
    def list(self, path: str) -> list[SFTPAttr]: pass
    
    @abstractmethod
    def open(self, path: str, mode: str) -> BinaryIO: pass
    
    @abstractmethod
    def stat(self, path: str) -> SFTPAttr: pass
    
    @abstractmethod
    def exists(self, path: str) -> bool: pass
    
    @abstractmethod
    def is_dir(self, path: str) -> bool: pass
    
    def normalize_path(self, path: str) -> str: pass
    
    def is_subpath(self, base: str, path: str) -> bool: pass
```

### sftp/session.py
```python
class Session:
    session_id: str
    allowed_paths: list[str]
    download_limits: dict
    
    def update_activity(self) -> None
    def is_timeout(self) -> bool
    def check_operation_timeout(self, start_time: float) -> bool
    def check_path(self, path: str) -> bool
    def check_download_limit(self, path: str) -> tuple[bool, int, Optional[int]]
```

### sftp/handler.py
```python
class SFTPHandler(SFTPServerInterface):
    session: Session
    storage: StorageBackend
    
    def open(self, path, flags):    # 检查权限+下载限制
    def listdir(self, path):         # 检查权限
    def stat(self, path):            # 检查权限
    # 禁止: mkdir, rmdir, remove, rename, write
```

### sftp/server.py
```python
# 支持的SSH密钥类型
SUPPORTED_KEY_TYPES = ['rsa', 'ecdsa', 'ed25519']

# 生成新的主机密钥
def generate_host_key(key_path: str, key_type: str = 'rsa') -> paramiko.PKey

# 加载或生成主机密钥（文件不存在时自动生成）
def load_or_generate_host_key(key_path: str, key_type: str = 'rsa') -> paramiko.PKey

# SFTP服务器线程
class SFTPServerThread(threading.Thread):
    def __init__(self, host: str, port: int, host_key: str, host_key_type: str = 'rsa')
    def _load_host_key(self) -> paramiko.PKey  # 使用 load_or_generate_host_key

# 启动SFTP服务器
def start_sftp_server(host: str = None, port: int = None, 
                      host_key: str = None, host_key_type: str = None) -> SFTPServerThread
```

## 依赖清单

```
paramiko>=3.0.0
PyYAML>=6.0
PyJWT>=2.0
redis>=4.0
boto3>=1.26
fastapi>=0.100
uvicorn>=0.23
python-multipart>=0.0.6
```

## 认证流程

### Token认证流程
```
1. SFTP客户端连接
2. 用户名填写token，密码直接回车（无密码）
3. 服务器从Redis查询token对应的paths和download_limits
4. 认证成功创建Session，记录授权路径
5. 后续SFTP操作检查Session权限
   - 支持标准SFTP操作: ls/dir, cd, get, stat等
   - 只能访问授权路径下的文件
6. 下载操作检查并更新下载计数
```

### JWT认证流程
```
1. SFTP客户端连接
2. 用户名填写配置的固定用户名（默认"jwt"）
3. 密码填写JWT token
4. 服务器验证JWT签名和过期时间
5. 可选: Redis检查token黑名单
6. 认证成功创建Session，记录授权路径
7. 后续SFTP操作检查Session权限
   - 支持标准SFTP操作: ls/dir, cd, get, stat等
   - 只能访问JWT payload中paths指定的文件
```

### S3签名验证认证流程
```
1. SFTP客户端连接
2. 用户名填写配置的固定用户名（默认"s3"），密码直接回车（无密码）
3. 认证成功，允许连接（此时不进行鉴权）
4. 客户端发送get命令，附带带签名的S3 URL
5. 服务器验证URL中的AWS签名（延迟鉴权）
6. 验证通过后，根据storage.type配置:
   - disk后端: 从本地磁盘读取 /path/to/file
   - s3后端: 从S3读取 s3://bucket/path/to/file
7. 服务器将文件内容传输给客户端

注意: S3签名验证模式只支持get命令，不支持ls/dir/cd等操作
```

## 存储扩展预留

```python
# storage/registry.py
STORAGE_REGISTRY = {
    "disk": DiskStorage,
    "s3": S3Storage,
    # "s3_multi": S3MultiStorage,  # 未来扩展
}
```

## S3签名验证模式（S3 Signature Verification Mode）

### 概述
S3签名验证模式是一种**延迟鉴权**的工作方式。客户端使用固定用户名登录（无需密码），然后通过 `get` 命令提供带签名的S3 URL。服务器验证URL中的AWS签名通过后，根据配置的存储后端（disk或s3）访问对应的文件。

**关键特性**：
- **延迟鉴权**：鉴权推迟到 `get` 命令执行时才进行（验证URL签名）
- **双后端支持**：支持disk本地存储和S3对象存储两种后端
- **路径映射**：从URL中提取文件路径，映射到对应的后端
- **只允许 `get` 命令**：仅支持通过带签名的URL下载文件

### 工作流程
```
1. 客户端使用固定用户名（如"s3"）登录（无需密码）
2. 客户端发送 get 命令，附带带签名的S3 URL
   例如: get https://bucket.s3.amazonaws.com/path/to/file.txt?X-Amz-Signature=...
3. 服务器解析URL，提取bucket、key和签名参数
4. 服务器验证AWS签名的有效性（鉴权）
5. 验证通过后，根据存储后端类型访问文件：
   - disk后端: 从本地磁盘读取 /path/to/file.txt
   - s3后端: 从S3读取 s3://bucket/path/to/file.txt
6. 服务器将文件内容传输给客户端
```

### 使用场景
- **延迟鉴权**：把JWT/Token的鉴权逻辑推迟到文件访问时才执行
- **签名验证**：需要验证客户端提供的S3 URL签名是否有效
- **灵活存储**：同一套URL格式可以映射到本地文件或S3对象
- **统一出口**：所有文件访问通过服务器代理，便于审计和管控

### 配置

#### Disk后端配置（本地文件存储）
```yaml
auth:
  type: s3
  s3:
    enabled: true               # 启用S3签名验证模式
    username: "s3"              # SFTP登录固定用户名（默认s3）

storage:
  type: disk                    # 使用本地磁盘存储
  disk:
    root: ./data                # 本地文件根目录
```

**路径映射**：
- URL: `https://bucket.s3.amazonaws.com/path/to/file.txt?...`
- 映射到本地: `./data/path/to/file.txt`

#### S3后端配置（S3对象存储）
```yaml
auth:
  type: s3
  s3:
    enabled: true               # 启用S3签名验证模式
    username: "s3"              # SFTP登录固定用户名（默认s3）
    # 服务器使用的S3凭证（用于实际访问S3）
    access_key: "AKIA..."       # AWS Access Key ID
    secret_key: "wJalr..."      # AWS Secret Access Key
    region: "us-east-1"         # AWS Region

storage:
  type: s3                      # 使用S3对象存储
  s3:
    bucket: my-bucket           # S3 bucket名称
    endpoint: https://s3.amazonaws.com
```

**路径映射**：
- URL: `https://bucket.s3.amazonaws.com/path/to/file.txt?...`
- 映射到S3: `s3://bucket/path/to/file.txt`

### 连接方式

#### 登录（无需密码）
```bash
# 使用固定用户名登录，直接回车无需密码
sftp -P 2222 s3@localhost
# 密码: <直接回车>
```

#### 下载文件（必须使用带签名的URL）
```bash
# 格式1: AWS V4预签名URL（包含X-Amz-Signature）
get https://bucket-name.s3.amazonaws.com/path/to/file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...&X-Amz-Signature=...

# 格式2: AWS V2签名URL（包含AWSAccessKeyId）
get https://s3.amazonaws.com/bucket-name/path/to/file.txt?AWSAccessKeyId=...&Signature=...
```

### URL要求
**必须包含AWS签名参数**：
- V4签名: `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`, `X-Amz-SignedHeaders`, `X-Amz-Signature`
- V2签名: `AWSAccessKeyId`, `Signature`, `Expires`
- 不支持无签名的裸URL

### 限制
- **仅支持 `get` 命令**，所有其他命令均被拒绝
- **不支持 `ls/dir`** 列出目录
- **不支持 `cd`** 切换目录  
- **不支持上传**（put/mkdir等）
- 所有操作必须通过 `get` 命令指定带签名的URL

### URL解析支持
支持多种S3 URL格式：
- `https://bucket.s3.amazonaws.com/key?X-Amz-Signature=...`
- `https://s3.amazonaws.com/bucket/key?AWSAccessKeyId=...&Signature=...`
- `https://bucket.s3.region.amazonaws.com/key?...`

### 架构说明
- **延迟鉴权**：鉴权推迟到 `get` 命令执行时才进行（类似JWT/Token验证）
- **签名验证**：服务器验证客户端提供的URL签名
- **后端选择**：根据 `storage.type` 配置决定使用disk还是s3后端
- **路径提取**：从URL中提取key部分作为文件路径
- **统一访问**：验证通过后通过存储后端统一访问文件

## 连接超时机制

### 配置
```yaml
server:
  connection_timeout: 300       # 连接超时时间（秒），默认5分钟
  operation_timeout: 60         # 单次操作超时时间（秒），默认1分钟
```

### 超时检测
- **连接超时**：认证成功后，如果X秒内没有任何操作，自动断开连接
- **操作超时**：单次操作（如文件下载）超过X秒未完成，自动中断
- 每次操作后自动更新最后活动时间

### 日志记录
```
2024-01-15 10:30:00 [WARN] [TIMEOUT] session=abc123... reason=connection_timeout
```

## 带宽限速

### 配置
```yaml
server:
  rate_limit: 1024              # 下载限速（KB/s），0表示不限速
```

### 限速实现
- **Token Bucket算法**：使用简单的滑动窗口算法控制下载速率
- **按连接限速**：每个SFTP连接独立计算限速
- **动态调整**：支持配置热重载，可实时调整限速值

### 日志记录
```
2024-01-15 10:30:00 [INFO] [DOWNLOAD] path=file.txt size=1048576 rate_limit=1024KB/s
```

### 使用建议
- **不限速**：`rate_limit: 0` 或删除配置项
- **低速**：`rate_limit: 100`（100KB/s，适合测试）
- **中速**：`rate_limit: 1024`（1MB/s）
- **高速**：`rate_limit: 10240`（10MB/s）
