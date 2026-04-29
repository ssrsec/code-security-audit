# .NET 不安全反序列化成立条件

## 发现条件

- `BinaryFormatter`、`NetDataContractSerializer`、`LosFormatter`、`ObjectStateFormatter`、`JavaScriptSerializer` 不安全类型处理。
- ViewState、文件上传、队列消息、缓存、HTTP body 可控。

## 成立条件

- 外部可控数据进入危险 formatter。
- 未启用签名/MAC、类型限制或安全 binder。
- 运行时和依赖支持危险类型链，或业务对象反序列化后影响权限/状态。

## 验证要求

- 查 formatter、binder、ViewState MAC、machineKey、类型限制。
- 授权环境中使用无害命令或 mock sink 证明。
- 缺少 machineKey、类型链或运行时条件时标 V1 待验证。

## 报告要点

- 区分 ViewState 配置问题和一般 BinaryFormatter 入口。
- 写明运行时版本、配置和输入路径。
