# 不安全反序列化成立条件（通用）

供 阶段 4 判断；**框架无关**，对应 **OWASP Top 10 A08:2021 Software and Data Integrity Failures**。各语言/框架有不同表现，本页为通用要点；具体库（如 Fastjson）见对应文档。

---

## 发现条件

- 代码中**将不可信数据反序列化为对象**（二进制、JSON、XML、YAML 等）；或存在**对象注入/类型混淆**（如用户可控类型名、@type、__class__ 等）。

---

## 成立条件（按类型）

### 1. 反序列化 RCE / 类型滥用

- **现象**：反序列化 API 接收用户输入，且未限制类型或未使用安全配置（如 Java Fastjson autoType、Python pickle、PHP unserialize、.NET BinaryFormatter、Java ObjectInputStream 等）。
- **判定**：查阅该库/语言的成立条件文档（如 fastjson_conditions.md）；指定目标类型（typed parse）通常降级（见 Fastjson 文档）。

### 2. 反序列化 DoS / 资源消耗

- **现象**：可构造深层嵌套或大对象导致 CPU/内存耗尽。
- **判定**：可标 Low/Info，除非与业务可用性强相关。

### 3. 数据篡改 / 逻辑绕过

- **现象**：反序列化后的对象属性被用于权限判断、价格、状态等，且攻击者可篡改序列化数据。
- **判定**：若存在签名/校验则风险低；无校验则可能成立（需追踪数据流）。

---

## 各生态参考文档

- **Java**：fastjson_conditions.md、jndi_conditions.md；另有 Jackson、XStream、Hessian 等可仿照 Fastjson 写成立条件。
- **Python**：pickle、yaml.unsafe_load 等；可新增 python_deserialization_conditions.md。
- **PHP**：unserialize、__wakeup/__destruct 利用链；可新增 php_deserialization_conditions.md。
- **.NET**：BinaryFormatter、ObjectStateFormatter 等；可新增 dotnet_deserialization_conditions.md。

---

## 如何确认

- **Read 代码**：定位反序列化 API（parseObject、loads、unserialize、ObjectInputStream.readObject 等），确认输入来源与类型/配置限制。
- **报告约定**：注明库与版本（见 dependency_version_check.md）、是否指定类型、是否开启安全配置；不确定则标 **V1 待验证**，验证后再升 V2-V4。

---

## 与“真实危害”范围

- 可 RCE 或可篡改关键业务数据 → 在默认 scope 内。
- 仅 DoS 或理论链 → 不默认进入漏洞表，可作为建议项或残余风险；存在静态闭环但缺运行时条件时标 **V1 待验证**。
