---
last_updated: "2026-04-30"
version: "1.0"
---

# 文件上传 / 存储成立条件（通用）

供 阶段 4 判断；**框架无关**，适用于任意语言与 Web 框架（Java、Node、Python、PHP、.NET、Go 等）。

---

## 发现条件

- 代码接收用户上传文件（multipart、base64、或 URL 指定资源）并**写入服务器本地或云存储**；或接收“路径/文件名”参数并据此读写文件。

---

## 成立条件（按风险类型）

### 1. 未限制扩展名 / 类型 → 可执行文件落地

- **现象**：保存时仅用用户提供的文件名或扩展名，或仅做黑名单过滤（如仅禁止 .php），未做白名单（如仅允许 jpg/png/gif）。
- **风险**：若上传目录被 Web 服务器解析执行（如上传 .jsp、.php、.asp、.py 到可执行目录），则可能 RCE。
- **判定**：结合部署（该目录是否可执行）；若无法确认则标 **待验证（HYPOTHESIS）**，并注明“依赖部署配置”。

### 2. 路径穿越（Path Traversal）

- **现象**：保存路径或读取路径由用户输入参与拼接（如 `baseDir + userFileName`、`path.join(staticDir, req.body.path)`），未规范化或禁止 `../`。
- **风险**：可写/读到任意路径，覆盖或读取敏感文件。
- **判定**：确认用户可控部分是否可包含 `..`、绝对路径、或编码绕过（如 %2e%2e/）；成立则 **已确认（CONFIRMED）**。

### 3. 存储型 vs 解析型

- **存储型**：文件仅被存储，由 Web 服务器按扩展名执行（如上传 .jsp 到 images/）→ 属“未限制扩展名”类。
- **解析型**：代码主动解析文件内容（如 ImageMagick、XML 解析、Office 解析、解压）→ 除路径与扩展名外，需结合**解析漏洞**知识库（如 XXE、反序列化）判断；不单独归类为“文件上传漏洞”时，在报告中区分“上传接口”与“解析漏洞”。

---

## 如何确认

- **Read 代码**：找到保存/写入的 API（transferTo、writeFile、save、putObject 等），看文件名/路径是否来自请求、是否白名单、是否做 path 规范化。
- **报告约定**：注明上传目录是否可执行、是否白名单、路径是否用户可控；若依赖部署则标 **待验证（HYPOTHESIS）**。

---

## 多语言示例（仅作概念）

- *Java*：MultipartFile.getOriginalFilename()、transferTo()；需检查扩展名白名单与保存路径。
- *Node*：multer、formidable；path.join 与用户 path 参数。
- *Python*：request.files、save()、open(path)。
- *PHP*：$_FILES、move_uploaded_file；路径与 basename 处理。
- *Go*：FormFile、os.Create、path.Join。

新框架：查“上传 API”与“保存路径/文件名来源”，按上三类判断即可。
