#!/usr/bin/env python3
"""
Enrich knowledge base files with authoritative metadata.
Sources: CWE Top 25 (2025), OWASP Top 10 (2021), Nuclei tags, PayloadsAllTheThings.
"""
import os
import re
import yaml

KNOWLEDGE_DIR = os.path.join(
    os.path.dirname(__file__), "..",
    "skills", "audit-validate", "resources", "knowledge"
)

METADATA = {
    "sql_injection_conditions.md": {
        "keywords": [
            "SQL注入", "sqli", "SQL injection", "PreparedStatement",
            "MyBatis", "${}", "#{}", "string concatenation",
            "raw query", "ORDER BY", "dynamic column",
            "HQL", "JPQL", "NoSQL injection", "LDAP injection"
        ],
        "cwe": ["CWE-89", "CWE-943"],
        "cwe_rank": 2,
        "owasp": ["A03:2021"],
        "nuclei_tags": ["sqli", "injection"],
        "frameworks": ["Java", "Python", "PHP", "Node.js", "Go", ".NET", "Ruby"],
        "vuln_types": ["injection", "sql_injection"],
        "severity_range": ["high", "critical"],
        "references": [
            "OWASP CheatSheetSeries (31.7k stars)",
            "PayloadsAllTheThings/SQL Injection (64k stars)",
            "CWE Top 25 #2 (2025)"
        ]
    },
    "command_os_injection_conditions.md": {
        "keywords": [
            "命令注入", "OS注入", "command injection", "RCE",
            "Runtime.exec", "ProcessBuilder", "os.system", "subprocess",
            "child_process", "exec", "shell injection", "code execution"
        ],
        "cwe": ["CWE-78", "CWE-77"],
        "cwe_rank": 9,
        "owasp": ["A03:2021"],
        "nuclei_tags": ["rce", "command-injection"],
        "frameworks": ["Java", "Python", "PHP", "Node.js", "Go", ".NET"],
        "vuln_types": ["injection", "command_injection", "rce"],
        "severity_range": ["high", "critical"],
        "references": [
            "CWE Top 25 #9 (2025)",
            "PayloadsAllTheThings/Command Injection"
        ]
    },
    "ssrf_conditions.md": {
        "keywords": [
            "SSRF", "服务端请求伪造", "Server-Side Request Forgery",
            "URL fetch", "webhook", "callback", "proxy",
            "DNS rebinding", "redirect", "internal network"
        ],
        "cwe": ["CWE-918"],
        "owasp": ["A10:2021"],
        "nuclei_tags": ["ssrf", "oast"],
        "frameworks": ["Java", "Python", "PHP", "Node.js", "Go", ".NET"],
        "vuln_types": ["ssrf", "network"],
        "severity_range": ["medium", "critical"],
        "references": [
            "OWASP Top 10 A10:2021",
            "PayloadsAllTheThings/SSRF"
        ]
    },
    "file_upload_conditions.md": {
        "keywords": [
            "文件上传", "file upload", "path traversal", "路径穿越",
            "任意文件读写", "zip slip", "IFormFile", "multipart",
            "extension bypass", "MIME", "magic bytes", "webshell"
        ],
        "cwe": ["CWE-434", "CWE-22"],
        "cwe_rank": 6,
        "owasp": ["A01:2021", "A08:2021"],
        "nuclei_tags": ["fileupload", "lfi", "rfi", "traversal"],
        "frameworks": ["Java", "Python", "PHP", "Node.js", "Go", ".NET"],
        "vuln_types": ["file_upload", "path_traversal", "arbitrary_file"],
        "severity_range": ["medium", "critical"],
        "references": [
            "CWE Top 25 #6 Path Traversal (2025)",
            "PayloadsAllTheThings/Upload Insecure Files",
            "PayloadsAllTheThings/Directory Traversal"
        ]
    },
    "fastjson_conditions.md": {
        "keywords": [
            "Fastjson", "反序列化", "autoType", "deserialization",
            "parseObject", "JSON.parse", "gadget chain",
            "JNDI", "RMI", "LDAP"
        ],
        "cwe": ["CWE-502"],
        "owasp": ["A08:2021"],
        "nuclei_tags": ["deserialization", "fastjson", "rce"],
        "frameworks": ["Java"],
        "vuln_types": ["deserialization", "rce"],
        "severity_range": ["critical"],
        "references": [
            "PayloadsAllTheThings/Insecure Deserialization",
            "Nuclei-templates fastjson (12.1k stars)"
        ]
    },
    "jackson_conditions.md": {
        "keywords": [
            "Jackson", "多态反序列化", "polymorphic deserialization",
            "ObjectMapper", "enableDefaultTyping", "JsonTypeInfo",
            "gadget", "PolymorphicTypeValidator"
        ],
        "cwe": ["CWE-502"],
        "owasp": ["A08:2021"],
        "nuclei_tags": ["deserialization", "jackson"],
        "frameworks": ["Java"],
        "vuln_types": ["deserialization", "rce"],
        "severity_range": ["high", "critical"],
        "references": ["PayloadsAllTheThings/Insecure Deserialization"]
    },
    "xstream_conditions.md": {
        "keywords": [
            "XStream", "XML反序列化", "XML deserialization",
            "fromXML", "SecurityFramework", "allowedTypes"
        ],
        "cwe": ["CWE-502"],
        "owasp": ["A08:2021"],
        "nuclei_tags": ["deserialization", "xstream"],
        "frameworks": ["Java"],
        "vuln_types": ["deserialization", "rce"],
        "severity_range": ["critical"],
        "references": ["PayloadsAllTheThings/Insecure Deserialization"]
    },
    "shiro_deserialization_conditions.md": {
        "keywords": [
            "Shiro", "RememberMe", "反序列化",
            "AES", "CBC", "DefaultSerializer", "硬编码密钥"
        ],
        "cwe": ["CWE-502", "CWE-321"],
        "owasp": ["A08:2021", "A02:2021"],
        "nuclei_tags": ["deserialization", "shiro", "rce"],
        "frameworks": ["Java"],
        "vuln_types": ["deserialization", "rce", "hardcoded_key"],
        "severity_range": ["critical"],
        "references": ["Nuclei-templates shiro"]
    },
    "snakeyaml_conditions.md": {
        "keywords": [
            "SnakeYAML", "YAML反序列化", "yaml.load",
            "Constructor", "SafeConstructor", "!!python/object"
        ],
        "cwe": ["CWE-502"],
        "owasp": ["A08:2021"],
        "nuclei_tags": ["deserialization", "yaml"],
        "frameworks": ["Java", "Python"],
        "vuln_types": ["deserialization", "rce"],
        "severity_range": ["high", "critical"],
        "references": ["PayloadsAllTheThings/Insecure Deserialization"]
    },
    "java_native_deserialization_conditions.md": {
        "keywords": [
            "Java原生反序列化", "ObjectInputStream", "readObject",
            "Serializable", "gadget chain", "ysoserial",
            "Commons Collections", "Spring", "BeanUtils"
        ],
        "cwe": ["CWE-502"],
        "owasp": ["A08:2021"],
        "nuclei_tags": ["deserialization", "java"],
        "frameworks": ["Java"],
        "vuln_types": ["deserialization", "rce"],
        "severity_range": ["critical"],
        "references": [
            "PayloadsAllTheThings/Insecure Deserialization/Java",
            "ysoserial (6.8k stars)"
        ]
    },
    "python_pickle_conditions.md": {
        "keywords": [
            "pickle", "Python反序列化", "PyYAML", "yaml.load",
            "marshal", "__reduce__", "shelve", "cPickle"
        ],
        "cwe": ["CWE-502"],
        "owasp": ["A08:2021"],
        "nuclei_tags": ["deserialization", "python"],
        "frameworks": ["Python"],
        "vuln_types": ["deserialization", "rce"],
        "severity_range": ["critical"],
        "references": [
            "PayloadsAllTheThings/Insecure Deserialization/Python (2026 update: eval-based universal payload)"
        ]
    },
    "php_unserialize_conditions.md": {
        "keywords": [
            "PHP反序列化", "unserialize", "phar://",
            "__wakeup", "__destruct", "POP chain", "gadget"
        ],
        "cwe": ["CWE-502"],
        "owasp": ["A08:2021"],
        "nuclei_tags": ["deserialization", "php"],
        "frameworks": ["PHP"],
        "vuln_types": ["deserialization", "rce"],
        "severity_range": ["critical"],
        "references": ["PayloadsAllTheThings/Insecure Deserialization/PHP"]
    },
    "dotnet_deserialization_conditions.md": {
        "keywords": [
            ".NET反序列化", "BinaryFormatter", "ViewState",
            "LosFormatter", "ObjectStateFormatter", "TypeNameHandling",
            "DataContractSerializer", "XmlSerializer"
        ],
        "cwe": ["CWE-502"],
        "owasp": ["A08:2021"],
        "nuclei_tags": ["deserialization", "dotnet"],
        "frameworks": [".NET"],
        "vuln_types": ["deserialization", "rce"],
        "severity_range": ["critical"],
        "references": ["PayloadsAllTheThings/Insecure Deserialization/.NET"]
    },
    "insecure_deserialization.md": {
        "keywords": [
            "不安全反序列化", "insecure deserialization",
            "反序列化", "gadget chain", "RCE",
            "序列化", "对象注入"
        ],
        "cwe": ["CWE-502"],
        "owasp": ["A08:2021"],
        "nuclei_tags": ["deserialization"],
        "frameworks": ["Java", "Python", "PHP", ".NET", "Ruby", "Node.js"],
        "vuln_types": ["deserialization"],
        "severity_range": ["high", "critical"],
        "references": [
            "OWASP Top 10 A08:2021",
            "PayloadsAllTheThings/Insecure Deserialization (64k stars)"
        ]
    },
    "jndi_conditions.md": {
        "keywords": [
            "JNDI注入", "JNDI injection", "Log4Shell",
            "Log4j", "InitialContext", "lookup",
            "RMI", "LDAP", "DNS", "CVE-2021-44228"
        ],
        "cwe": ["CWE-917", "CWE-20"],
        "owasp": ["A03:2021"],
        "nuclei_tags": ["jndi", "log4j", "rce"],
        "frameworks": ["Java"],
        "vuln_types": ["injection", "jndi", "rce"],
        "severity_range": ["critical"],
        "references": [
            "Nuclei-templates log4j",
            "PayloadsAllTheThings/JNDI Injection"
        ]
    },
    "velocity_ssti_conditions.md": {
        "keywords": [
            "SSTI", "模板注入", "Server-Side Template Injection",
            "Velocity", "VelocityEngine", "evaluate",
            "FreeMarker", "Thymeleaf", "Handlebars"
        ],
        "cwe": ["CWE-1336", "CWE-94"],
        "cwe_rank": 10,
        "owasp": ["A03:2021"],
        "nuclei_tags": ["ssti", "template-injection"],
        "frameworks": ["Java"],
        "vuln_types": ["injection", "ssti", "rce"],
        "severity_range": ["high", "critical"],
        "references": [
            "CWE Top 25 #10 Code Injection (2025)",
            "PayloadsAllTheThings/SSTI (2026 update: error/boolean/time-based detection)"
        ]
    },
    "auth_failures.md": {
        "keywords": [
            "认证缺陷", "authentication failure", "会话管理",
            "登录绕过", "密码重置", "暴力破解",
            "JWT", "Session", "Cookie", "OAuth", "OIDC", "SSO"
        ],
        "cwe": ["CWE-287", "CWE-384", "CWE-613"],
        "owasp": ["A07:2021"],
        "nuclei_tags": ["auth-bypass", "default-login"],
        "frameworks": ["Java", "Python", "PHP", "Node.js", "Go", ".NET"],
        "vuln_types": ["authentication", "session", "auth_bypass"],
        "severity_range": ["medium", "critical"],
        "references": [
            "OWASP Top 10 A07:2021",
            "OWASP CheatSheetSeries/Authentication"
        ]
    },
    "authorization_model.md": {
        "keywords": [
            "授权缺陷", "越权", "未授权访问", "IDOR", "BOLA",
            "水平越权", "垂直越权", "权限绕过",
            "Missing Authorization", "Access Control"
        ],
        "cwe": ["CWE-862", "CWE-863", "CWE-639"],
        "cwe_rank": 4,
        "owasp": ["A01:2021"],
        "nuclei_tags": ["auth-bypass", "idor", "misconfig"],
        "frameworks": ["Java", "Python", "PHP", "Node.js", "Go", ".NET"],
        "vuln_types": ["authorization", "idor", "access_control"],
        "severity_range": ["medium", "critical"],
        "references": [
            "CWE Top 25 #4 Missing Authorization (2025)",
            "OWASP Top 10 A01:2021"
        ]
    },
    "cryptographic_failures.md": {
        "keywords": [
            "加密缺陷", "密码学失败", "弱加密", "硬编码密钥",
            "MD5", "SHA1", "DES", "ECB", "弱随机数",
            "明文传输", "证书校验", "JWT secret"
        ],
        "cwe": ["CWE-327", "CWE-328", "CWE-321", "CWE-330"],
        "owasp": ["A02:2021"],
        "nuclei_tags": ["exposure", "token"],
        "frameworks": ["Java", "Python", "PHP", "Node.js", "Go", ".NET"],
        "vuln_types": ["crypto", "hardcoded_secret", "weak_crypto"],
        "severity_range": ["medium", "high"],
        "references": [
            "OWASP Top 10 A02:2021",
            "OWASP CheatSheetSeries/Cryptographic Storage"
        ]
    },
    "security_misconfiguration.md": {
        "keywords": [
            "安全配置错误", "misconfiguration", "debug模式",
            "默认凭据", "错误回显", "CORS", "CSRF",
            "Actuator", "Swagger", "Druid", "phpinfo"
        ],
        "cwe": ["CWE-16", "CWE-1188"],
        "owasp": ["A05:2021"],
        "nuclei_tags": ["misconfig", "exposure", "panel"],
        "frameworks": ["Java", "Python", "PHP", "Node.js", "Go", ".NET"],
        "vuln_types": ["misconfiguration", "info_disclosure"],
        "severity_range": ["low", "high"],
        "references": [
            "OWASP Top 10 A05:2021",
            "Nuclei-templates misconfig (top tag)"
        ]
    },
    "dependency_version_check.md": {
        "keywords": [
            "依赖检查", "组件漏洞", "CVE", "版本检查",
            "SCA", "supply chain", "outdated component",
            "known vulnerability"
        ],
        "cwe": ["CWE-1395"],
        "owasp": ["A06:2021"],
        "nuclei_tags": ["cve", "vuln"],
        "frameworks": ["Java", "Python", "PHP", "Node.js", "Go", ".NET"],
        "vuln_types": ["dependency", "supply_chain", "known_cve"],
        "severity_range": ["low", "critical"],
        "references": [
            "OWASP Top 10 A06:2021",
            "Nuclei-templates CVE (3587 templates)"
        ]
    },
    "parameter_and_business_logic.md": {
        "keywords": [
            "业务逻辑漏洞", "参数篡改", "Mass Assignment",
            "竞态条件", "TOCTOU", "价格篡改", "权限提升",
            "状态机绕过", "重放攻击", "幂等"
        ],
        "cwe": ["CWE-840", "CWE-362", "CWE-915"],
        "owasp": ["A04:2021"],
        "nuclei_tags": ["misconfig"],
        "frameworks": ["Java", "Python", "PHP", "Node.js", "Go", ".NET"],
        "vuln_types": ["business_logic", "race_condition", "mass_assignment"],
        "severity_range": ["medium", "critical"],
        "references": [
            "OWASP Top 10 A04:2021",
            "OWASP CheatSheetSeries/Mass Assignment"
        ]
    }
}


def update_yaml_header(filepath, meta):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    if content.startswith('---'):
        parts = content.split('---', 2)
        if len(parts) >= 3:
            existing = yaml.safe_load(parts[1]) or {}
            existing.update(meta)
            new_yaml = yaml.dump(existing, default_flow_style=False, allow_unicode=True, sort_keys=False)
            content = f'---\n{new_yaml}---\n{parts[2]}'
    else:
        new_yaml = yaml.dump(meta, default_flow_style=False, allow_unicode=True, sort_keys=False)
        content = f'---\n{new_yaml}---\n\n{content}'

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"  ✅ {os.path.basename(filepath)}: {len(meta.get('keywords', []))} keywords, {len(meta.get('cwe', []))} CWE")


def main():
    print("=== Enriching knowledge base metadata ===\n")
    updated = 0
    for filename, meta in METADATA.items():
        filepath = os.path.join(KNOWLEDGE_DIR, filename)
        if os.path.exists(filepath):
            update_yaml_header(filepath, meta)
            updated += 1
        else:
            print(f"  ⚠️ {filename}: file not found")
    print(f"\nDone: {updated}/{len(METADATA)} files enriched")


if __name__ == '__main__':
    main()
