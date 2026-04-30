# SnakeYAML / YAML 反序列化成立条件

## 发现条件

- Java：`new Yaml()`、`Yaml.load`、`loadAs` 处理外部 YAML。
- Python：`yaml.load` 未指定 SafeLoader。
- YAML 输入来自上传文件、配置导入、HTTP body、MQ、第三方回调。

## 成立条件

- 使用不安全 loader，允许任意类型实例化。
- 版本和配置允许危险 tag 或类型。
- 输入可外部控制并触发对象构造、副作用或业务字段污染。

## 验证要求

- Java 查 SnakeYAML 版本、Constructor/LoaderOptions。
- Python 查 PyYAML 版本和 Loader。
- 有运行环境时用无害类型或 mock 对象验证实例化路径。
- 不确定运行时类型或版本时标 V1 待验证。

## 报告要点

- 区分 RCE、对象实例化和配置污染。
- 写明 loader、安全配置和输入来源。
