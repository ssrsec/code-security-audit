# Secret / 硬编码凭据专项审计

本文件用于阶段 1-4 的硬编码账号、密码、密钥、Token、连接串和证书审计。目标是发现可导致登录、签名伪造、云资源访问、数据库访问、供应链访问或横向移动的真实泄露。

## 1. 必扫位置

- 配置文件：`.env`、`.properties`、`.yml`、`.yaml`、`.json`、`.toml`、`.ini`、`config/*`、`settings.*`。
- 构建和部署：`Dockerfile`、`docker-compose.yml`、K8s YAML、Helm values、CI/CD 配置、启动脚本。
- 源代码：常量类、初始化脚本、测试数据加载、SDK client 初始化、JWT/加密/数据库连接封装。
- 前端产物：`src`、`public`、`static`、`dist` 中暴露给浏览器的 API key、endpoint、token。
- 依赖和脚本：`package.json` scripts、postinstall、私有 registry 配置、Maven/Gradle/NPM/PyPI 凭据。

## 2. 高价值 Secret 类型

| 类型 | 例子 | 风险 |
|------|------|------|
| 账号密码 | admin/admin、数据库密码、测试管理员账号 | 未授权登录、权限提升 |
| 云密钥 | AWS AKIA、阿里云 LTAI、腾讯云 AKID、GCP service account | 云资源访问、数据泄露 |
| API Token | GitHub/GitLab token、Slack/飞书/企业微信 webhook、第三方支付 token | 供应链、通知劫持、业务接口滥用 |
| JWT/签名密钥 | `jwt.secret`、`HS256` secret、HMAC key | 伪造身份、绕过鉴权 |
| 数据库/缓存连接串 | JDBC、MongoDB、Redis、Elasticsearch、RabbitMQ | 数据读取、队列污染、反序列化前置 |
| 私钥/证书 | PEM、P12、SSH private key | 身份冒用、TLS/SSH 访问 |
| 加密密钥 | AES/DES/RSA key、固定 IV、salt | 数据解密、签名伪造 |

## 3. 检测方法

- 关键词：`password`、`passwd`、`pwd`、`secret`、`token`、`apikey`、`api_key`、`access_key`、`private_key`、`jwt`、`signing`、`datasource`、`jdbc`、`redis`、`mongodb`、`oss`、`s3`。
- 格式：PEM 私钥块、JWT 三段式、Basic Auth、URL 中的 `user:pass@host`、JDBC URL、云厂商 key 前缀。
- 熵值：对长字符串做高熵线索判断，但不能只凭高熵报漏洞。
- 上下文：变量名、注释、配置路径、调用点、是否被生产 profile 引用。

## 4. 误报过滤

以下默认不进入漏洞表，但可记录在覆盖矩阵或残余风险：

- 文档示例、占位符、明显 fake 值：`changeme`、`example`、`test`、`dummy`、`your_key_here`。
- 本地开发 profile 且生产不加载的样例配置。
- 公共客户端 ID，但不包含 secret 的 OAuth public client id。
- 无权限意义的随机常量、测试 fixture 中不可达账号。

误报过滤必须有代码或配置证据，不能凭直觉排除。

## 5. 可利用性验证

验证优先级：

1. 证明 secret 被生产或默认 profile 加载。
2. 证明 secret 对应的服务、账号或签名逻辑存在。
3. 在授权测试环境中验证最小权限可用性：
   - 数据库：只执行只读查询，如 `SELECT 1` 或当前库名。
   - Redis/MQ：只做 `PING`、`INFO` 摘要或 mock 连接。
   - JWT secret：签发低权限测试 token，验证是否被服务接受。
   - 云 key：只调用身份查询接口，不读取真实资源。
4. 无法验证时标 V1 待验证，并说明缺少网络、账号、服务或 profile 条件。

## 6. 报告脱敏规则

- 默认只展示前 4 位和后 4 位，例如 `AKIA****ABCD`。
- 私钥、JWT、数据库密码、云密钥不得完整写入报告。
- 报告必须说明 secret 类型、所在文件:行号、加载 profile、可利用性验证结果和修复建议。
- 修复建议必须包含：轮换密钥、删除代码中 secret、改用密钥管理服务、最小权限、审计访问日志。

## 7. 组合利用重点

- 文件读取 -> 读取配置 secret -> 伪造 JWT / 登录数据库。
- 未授权日志/配置接口 -> 泄露 token -> 调用管理接口。
- 源码硬编码 JWT secret -> 伪造管理员 token -> 越权操作。
- Redis/MQ 凭据泄露 -> 污染队列/缓存 -> 触发反序列化或业务状态变更。
