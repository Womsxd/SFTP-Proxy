# SFTP Proxy

一个Python SFTP前置代理服务，支持token鉴权、文件下载次数限制、多存储后端（Disk/S3）

## 核心特性

- **多种认证方式**: Token (Redis)、JWT (Redis可选)、AWS S3签名
- **下载次数限制**: 支持限制单个文件下载次数
- **多存储后端**: Disk本地存储、S3对象存储
- **独立日志**: API日志与SFTP日志分离，按日期自动切割
- **配置热重载**: HTTP API和命令行支持配置重载
- **管理API**: HTTP接口管理token创建/撤销/查询

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置

复制配置文件并修改：

```bash
cp config.yaml.example config.yaml
```

### 3. 启动服务

```bash
python main.py
```

## 使用方式

### SFTP连接

```bash
# Token认证模式 - 用户名即token，无需密码
sftp -P 2222 your-token-abc123@localhost
# 密码: <直接回车，无需输入>

# JWT认证模式 - 固定用户名 + JWT token密码
sftp -P 2222 jwt@localhost
# 密码: <输入JWT token>

# S3签名验证模式 - 固定用户名 + 带签名的URL
sftp -P 2222 s3@localhost
# 密码: <直接回车，无需输入>

# 下载文件（必须使用带签名的S3 URL）
get https://my-bucket.s3.amazonaws.com/path/to/file.txt?X-Amz-Signature=...
get https://s3.amazonaws.com/my-bucket/path/to/file.txt?AWSAccessKeyId=...&Signature=...
```

### HTTP API

#### 创建Token

```bash
curl -X POST http://localhost:8080/api/tokens \
  -H "Authorization: Bearer your-admin-secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "paths": ["file1.txt", "dir1/"],
    "expire": 600,
    "download_limits": {"file1.txt": 3},
    "auth_type": "token"
  }'
```

#### 查询Token

```bash
curl http://localhost:8080/api/tokens/your-token \
  -H "Authorization: Bearer your-admin-secret-token"
```

#### 撤销Token

```bash
curl -X DELETE http://localhost:8080/api/tokens/your-token \
  -H "Authorization: Bearer your-admin-secret-token"
```

#### 查询下载统计

```bash
curl http://localhost:8080/api/tokens/your-token/downloads \
  -H "Authorization: Bearer your-admin-secret-token"
```

#### 重载配置

```bash
curl -X POST http://localhost:8080/api/admin/reload \
  -H "Authorization: Bearer your-admin-secret-token"
```

## 命令行

```bash
# 测试配置
python main.py --test

# 重载配置
python main.py --reload

# 指定配置文件
python main.py -c /path/to/config.yaml
```

## 项目结构

```
sftp_proxy/
├── src/
│   ├── config.py               # 配置加载与热重载
│   ├── logger.py               # 日志配置(按日期切割)
│   ├── redis_client.py         # Redis操作封装
│   ├── auth/                   # 认证模块
│   ├── storage/                # 存储后端模块
│   ├── sftp/                   # SFTP服务模块
│   └── api/                    # HTTP API模块
├── logs/                       # 日志目录
├── data/                       # 本地存储目录
├── config.yaml                 # 配置文件
└── main.py                     # 入口程序
```

## 配置文件

```yaml
server:
  host: 0.0.0.0
  sftp_port: 2222
  api_port: 8080
  host_key: ./ssh_host_key
  host_key_type: rsa            # rsa | ecdsa | ed25519（不存在时自动生成）
  connection_timeout: 300       # 连接超时（秒），默认5分钟无操作自动断开
  operation_timeout: 60         # 单次操作超时（秒），默认1分钟
  rate_limit: 0                 # 下载限速（KB/s），0表示不限速

redis:
  host: localhost
  port: 6379
  db: 0
  password: null
  key_prefix: "sftp"

token:
  default_expire: 600
  max_expire: 86400

auth:
  type: token  # token | jwt | s3
  jwt:
    username: "jwt"             # JWT模式固定用户名
    secret: your-jwt-secret
    algorithm: HS256
    redis_enabled: false
  s3:
    # S3签名验证模式 - 客户端提供带签名的URL，服务器验证签名后通过存储后端访问S3
    enabled: false              # 是否启用S3签名验证模式
    username: "s3"              # SFTP登录固定用户名（默认s3）
    # 服务器使用的S3凭证（用于实际访问S3并传输文件给客户端）
    access_key: null            # AWS Access Key ID
    secret_key: null            # AWS Secret Access Key  
    region: us-east-1           # AWS Region

storage:
  type: disk  # disk | s3
  disk:
    root: ./data
  s3:
    bucket: my-bucket
    endpoint: https://s3.amazonaws.com
    access_key: your-ak
    secret_key: your-sk

log:
  level: INFO
  dir: ./logs

api:
  admin_token: your-admin-secret-token
```

## 日志

- **API日志**: `logs/api/api-YYYY-MM-DD.log`
- **SFTP日志**: `logs/sftp/sftp-YYYY-MM-DD.log`

日志按日期自动切割，保留最近30天的日志。

## 认证方式

### Token认证
- **用户名即Token**: 使用token作为用户名登录，无需密码
- **标准SFTP操作**: 支持ls/cd/get等标准命令，像普通SFTP一样使用
- **Redis存储**: token与权限映射存储在Redis中
- **支持下载次数限制**: 可限制单个文件的下载次数
- **支持过期时间**: token可设置过期时间

**使用方式**:
```bash
sftp -P 2222 your-token-abc123@localhost
# 密码: <直接回车，无需输入>

# 使用标准SFTP命令
ls
cd documents
get file.txt
```

### JWT认证
- **固定用户名**: 使用配置的固定用户名登录（默认`jwt`）
- **密码即JWT Token**: 密码字段传入JWT token
- **标准SFTP操作**: 支持ls/cd/get等标准命令，像普通SFTP一样使用
- **无状态认证**: 无需Redis存储（可选Redis黑名单）
- **签名验证**: 验证JWT签名和过期时间

**使用方式**:
```bash
sftp -P 2222 jwt@localhost
# 密码: <输入JWT token>

# 使用标准SFTP命令
ls
cd documents
get file.txt
```

### S3签名验证认证（延迟鉴权）
- **延迟鉴权**: 鉴权推迟到`get`命令执行时，验证S3 URL签名后访问文件
- **固定用户名**: 使用配置的固定用户名登录（默认`s3`），无需密码
- **只允许 `get` 命令**: 必须通过带签名的S3 URL获取文件（不支持ls/cd）
- **双后端支持**: 支持disk本地存储和S3对象存储
  - **disk后端**: URL映射到本地文件路径
  - **s3后端**: URL映射到S3对象，需要配置S3凭证
- **URL格式**: `get https://bucket.s3.amazonaws.com/path/to/file?X-Amz-Signature=...`
- **不支持列出目录**: 只允许通过URL直接下载文件

**使用方式**:
```bash
sftp -P 2222 s3@localhost
# 密码: <直接回车，无需输入>

# 下载文件（必须使用带签名的URL，不支持ls/cd）
get https://mybucket.s3.amazonaws.com/reports/data.csv?X-Amz-Signature=...
```

**工作流程**:
1. 客户端使用固定用户名`s3`登录（无需密码）
2. 客户端发送 `get` 命令，附带带签名的S3 URL
3. 服务器验证URL中的AWS签名（鉴权）
4. 验证通过后，根据后端类型访问文件:
   - disk后端: 从本地磁盘读取文件
   - s3后端: 从S3读取文件
5. 服务器将文件内容传输给客户端

**路径映射示例**:
```bash
# disk后端 - URL映射到本地文件
get https://mybucket.s3.amazonaws.com/reports/data.csv?X-Amz-Signature=...
# 实际读取: ./data/reports/data.csv

# s3后端 - URL映射到S3对象  
get https://mybucket.s3.amazonaws.com/reports/data.csv?X-Amz-Signature=...
# 实际读取: s3://mybucket/reports/data.csv
```

## 存储后端

### Disk
- 本地文件系统存储
- 路径安全检查
- 只读访问

### S3
- 支持AWS S3兼容存储
- 支持自定义endpoint
- 支持bucket前缀

## 安全

- Token过期时间控制
- 路径访问限制
- 下载次数限制
- 写入操作禁用
- 日志审计
- **连接超时**：空闲连接自动断开，防止资源泄露
- **带宽限速**：按连接限速，防止带宽滥用

## License

MIT
