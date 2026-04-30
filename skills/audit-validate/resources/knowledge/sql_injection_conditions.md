---
last_updated: "2026-04-30"
version: "1.0"
---

# SQL 注入成立条件（通用）

供 阶段 4 判断；**框架无关**，适用于 Java/MyBatis、.NET、PHP、Python、Node、Go 等使用 SQL 的任意技术栈。

---

## 发现条件

- 代码中执行 SQL 且**部分语句或参数来自用户输入、配置或不可信数据**（如拼接字符串、格式化字符串、或未使用参数化/占位符的 API）。

---

## 成立条件（按写法类型）

- **字符串拼接 / 格式化**：SQL 由 `"SELECT ... " + userInput`、`f"SELECT ... {id}"`、`"SELECT ... ".format(...)`、`query("... " + req.params.id)` 等构成 → 若输入未严格校验/转义，成立。
- **模板/占位符滥用**：如 MyBatis 的 `${}` 接收用户输入（`${orderBy}`、`${tableName}`）→ 成立；`#{}` 为参数化，不成立（除非另有注入点）。
- **参数化不完整**：部分条件参数化、部分拼接 → 拼接部分成立。
- **ORM 拼接/raw**：如 Django `Model.objects.raw("... %s" % userInput)`、Sequelize `query("... " + input)`、SQLAlchemy `text("... " + input)` → 成立；正确使用参数化/ORM 绑定则按具体 API 判断。
- **存储过程/动态 SQL**：若传入参数被拼进 EXEC/EXECUTE 或动态 SQL 字符串 → 成立。

---

## 如何确认

- **Read 代码**：定位 SQL 执行调用（execute、query、raw、from_sql 等），向上追踪参数来源是否可达用户输入。
- **框架文档**：该框架“参数化”的推荐写法（如 ?、:name、#{}、%s 绑定）与“禁止”写法（拼接、${} 用户输入）。
- **报告约定**：注明「文件:行号」、参数来源、以及是否参数化；若无法确认是否被 WAF/中间件过滤，标 **待验证（HYPOTHESIS）**。

---

## 多语言示例（仅作概念，不穷举）

- *Java*：MyBatis `${}` vs `#{}`；JDBC PreparedStatement vs Statement；JPA 的 @Query 拼接。
- *Python*：cursor.execute("... %s", (x,)) 安全；"..." % x 危险；SQLAlchemy text() 绑定。
- *PHP*：PDO prepare/bindParam 安全；拼接、mysqli_query("... $id") 危险。
- *Node*：? 占位、named 占位 安全；模板字符串拼接危险。
- *Go*：db.Exec("... ?", id) 安全；fmt.Sprintf 拼接危险。

新框架：查官方“参数化查询”文档，对应到“拼接/未绑定”即成立条件。
