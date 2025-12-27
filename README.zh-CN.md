# GetWVKeys

Widevine 实用工具网站和远程 Widevine 设备 API。

## 目录

- [功能简介](#功能简介)
- [环境要求](#环境要求)
- [安装配置](#安装配置)
- [本地开发](#本地开发)
- [数据库迁移](#数据库迁移)
- [环境变量](#环境变量)
- [生产部署](#生产部署)
- [API 使用](#api-使用)
- [其他信息](#其他信息)
- [常见问题](#常见问题)

## 功能简介

GetWVKeys 是一个 Widevine/PlayReady DRM 密钥获取工具，主要功能包括：

- 提供 Widevine CDM 设备的远程访问 API
- 支持 PlayReady 密钥获取
- 用户认证和会话管理（通过 Discord OAuth）
- 密钥缓存和管理
- 脚本动态注入（自动注入 API 密钥等信息）
- 流量日志记录
- 设备库管理

## 环境要求

- Python 3.10 或更高版本
- Poetry（Python 包管理工具）
- MySQL 或 MariaDB 数据库
- Redis（用于 Discord Bot 通信，可选）

## 安装配置

### 1. 安装 Python Poetry

访问 Poetry 官方文档安装：https://python-poetry.org/docs/master/#installation

或使用快速安装命令：

```bash
# Linux/macOS/WSL
curl -sSL https://install.python-poetry.org | python3 -

# Windows (PowerShell)
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | py -
```

### 2. 安装项目依赖

根据您使用的数据库类型选择安装命令：

```bash
# 使用 MySQL
poetry install --with mysql

# 使用 MariaDB
poetry install --with mariadb
```

### 3. 配置文件设置

复制配置文件模板并进行编辑：

```bash
cp config.toml.example config.toml
```

编辑 `config.toml` 文件，配置以下关键信息：

```toml
[general]
# 应用密钥（首次运行时自动生成）
secret_key = ""
# 数据库连接字符串
# MySQL 使用：mysql+mariadbconnector://用户名:密码@主机/数据库名
# MariaDB 使用：mariadb+mariadbconnector://用户名:密码@主机/数据库名
database_uri = "mysql+mariadbconnector://root:password@localhost/getwvkeys"
# Redis 连接字符串（可选，用于 Discord Bot）
redis_uri = "redis://localhost:6379/0"
# 最大会话数
max_sessions = 60
# Discord 服务器 ID
guild_id = ""
# 验证身份用户组 ID
verified_role_id = ""
# 是否禁用登录
login_disabled = false
# 是否禁用注册
registration_disabled = false

[api]
host = "0.0.0.0"
port = 8080
# 应用基础 URL
base_url = "http://localhost:8080"

[oauth]
# Discord OAuth 客户端 ID
client_id = "你的Discord客户端ID"
# Discord OAuth 客户端密钥
client_secret = "你的Discord客户端密钥"
# OAuth 回调 URL
redirect_url = "http://localhost:8080/login/callback"
```

### 4. 数据库设置

**重要提示**：创建数据库时必须使用以下字符集设置：

```sql
CREATE DATABASE getwvkeys
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;
```

### 5. 运行数据库迁移

```bash
poetry run setup
```

## 本地开发

### 开发环境设置

在本地开发测试时，需要禁用 OAuth 回调 URL 的 HTTPS 要求，否则会遇到 `InsecureTransportError` 错误。

**设置环境变量：**

```bash
# Unix/Linux/macOS
export OAUTHLIB_INSECURE_TRANSPORT=1
export DEVELOPMENT=1

# Windows (CMD)
set OAUTHLIB_INSECURE_TRANSPORT=1
set DEVELOPMENT=1

# Windows (PowerShell)
$env:OAUTHLIB_INSECURE_TRANSPORT=1
$env:DEVELOPMENT=1
```

### 启动开发服务器

使用 Flask 内置服务器进行本地开发：

```bash
poetry run serve
```

服务器将在 `http://localhost:8080` 上运行（端口可在配置文件中修改）。

## 数据库迁移

当数据库结构发生变化时，运行以下命令进行迁移：

```bash
poetry run setup
```

该命令会自动应用所有待执行的数据库迁移脚本。

## 环境变量

GetWVKeys 支持以下环境变量：

| 环境变量 | 说明 |
|---------|------|
| `OAUTHLIB_INSECURE_TRANSPORT` | 禁用 OAuth2 的 SSL 要求（仅用于开发） |
| `DEVELOPMENT` | 开发模式，启用详细日志，加载 `config.dev.toml` |
| `STAGING` | 预发布模式，加载 `config.staging.toml` |

## 生产部署

### 使用 Gunicorn（推荐）

Gunicorn 是在生产环境中运行服务器的推荐方式。

**启动命令示例**（在 8081 端口监听所有网络接口）：

```bash
poetry run gunicorn -w 1 -b 0.0.0.0:8081 getwvkeys.main:app
```

**重要提示**：
- **绝对不要使用超过 1 个 worker**
- GetWVKeys 目前不支持多 worker 模式
- 使用多个 worker 会导致会话管理问题

### 反向代理配置

建议在 Gunicorn 前使用 Nginx 或 Apache 作为反向代理。

**Nginx 配置示例：**

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### HTTPS 配置

生产环境中强烈建议使用 HTTPS。可以使用 Let's Encrypt 免费证书：

```bash
# 安装 Certbot
sudo apt-get install certbot python3-certbot-nginx

# 获取证书并自动配置 Nginx
sudo certbot --nginx -d your-domain.com
```

## API 使用

### 认证方式

GetWVKeys API 使用 API 密钥进行认证。用户登录后可以在个人设置页面获取 API 密钥。

### API 端点

主要 API 端点包括：

1. **Widevine 许可证获取**
   - 端点：`/api/widevine`
   - 方法：POST
   - 需要认证

2. **PlayReady 许可证获取**
   - 端点：`/api/playready`
   - 方法：POST
   - 需要认证

3. **设备管理**
   - 端点：`/api/devices`
   - 方法：GET, POST, DELETE
   - 需要认证

### 脚本动态注入

GetWVKeys 支持脚本动态注入功能。当已登录用户下载脚本时，服务器会自动替换以下占位符：

| 占位符 | 替换内容 |
|--------|---------|
| `__getwvkeys_api_key__` | 用户的 API 密钥 |
| `__getwvkeys_api_url__` | 实例的 API URL |

**使用示例：**

```python
# 脚本文件中使用占位符
API_KEY = "__getwvkeys_api_key__"
API_URL = "__getwvkeys_api_url__"

# 用户下载后自动替换为：
API_KEY = "用户的实际API密钥"
API_URL = "https://your-instance.com"
```

## 其他信息

### Redis 配置

- Redis 用作与 Discord Bot 通信的发布-订阅系统
- 如果不使用 Bot 功能，可以在 `.env` 文件中注释掉 Redis 配置：
  ```
  #REDIS_URI=redis://localhost:6379/0
  ```

### URL 黑名单

在 `config.toml` 中可以配置 URL 黑名单，阻止某些域名或 URL：

```toml
[[url_blacklist]]
url = ".*blocked-site\\.com.*"
partial = true

[[url_blacklist]]
url = "https://example.com/blocked-path"
partial = false
```

### 外部构建信息

可以配置外部 API 来获取构建信息：

```toml
[[external_build_info]]
buildinfo = "build_info_string"
url = "https://api.example.com/build"
token = "your_secret_token"
```

## 常见问题

### 1. 数据库迁移失败

**问题**：运行迁移时出错

**解决方案**：确保数据库使用正确的字符集创建：

```sql
CREATE DATABASE getwvkeys
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;
```

### 2. OAuth 回调错误

**问题**：登录时出现 `InsecureTransportError`

**解决方案**：在开发环境中设置环境变量：

```bash
export OAUTHLIB_INSECURE_TRANSPORT=1
```

### 3. 会话管理问题

**问题**：用户会话不稳定或丢失

**解决方案**：
- 确保 Gunicorn 只使用 1 个 worker
- 检查 `secret_key` 配置是否正确设置
- 验证 Redis 连接是否正常（如果使用）

### 4. 依赖安装失败

**问题**：`poetry install` 失败

**解决方案**：
- 确保 Python 版本 >= 3.10
- 更新 Poetry：`poetry self update`
- 清除缓存：`poetry cache clear . --all`

### 5. Discord OAuth 配置

**问题**：如何获取 Discord OAuth 凭据

**解决方案**：
1. 访问 [Discord Developer Portal](https://discord.com/developers/applications)
2. 创建新应用程序
3. 在 OAuth2 设置中配置回调 URL
4. 复制 Client ID 和 Client Secret 到配置文件

### 6. 端口被占用

**问题**：启动时提示端口已被使用

**解决方案**：
```bash
# 查找占用端口的进程
lsof -i :8080

# 或在配置文件中更改端口
[api]
port = 8081
```

## 许可证

本项目采用 GNU Affero General Public License v3.0 (AGPL-3.0) 许可证。

详细信息请参阅 [LICENSE.md](LICENSE.md) 文件。

## 贡献

欢迎提交问题报告和拉取请求！

- GitHub 仓库：https://github.com/GetWVKeys/getwvkeys
- 问题跟踪：https://github.com/GetWVKeys/getwvkeys/issues

## 支持

如需帮助或有疑问，请：
1. 查看本文档的常见问题部分
2. 在 GitHub 上提交 Issue
3. 查看英文原版 README.md 获取最新信息

## 更新日志

当前版本：0.1.3

查看完整更新历史，请访问项目的 [Releases 页面](https://github.com/GetWVKeys/getwvkeys/releases)。
