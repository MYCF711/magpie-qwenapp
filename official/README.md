# 官方依赖保留说明

- 逆向对象：`E:\QianwenApp\qianwen.exe`，版本 `5.2.7.307`。
- 官方安装目录中的 `qianwen.dll`、安全组件、UT 组件与 ASAR 均未修改或删除。
- `dependencies.json` 固定本次分析所涉官方文件的 SHA-256；`bundle-metadata.json` 与 `cowork-llm-sdk.json` 保留官方 ASAR 的构建及依赖锁定信息。
- 最终运行路径采用已实测的纯 HTTP + Baxia/HMAC，因此插件**不加载**这些 DLL，也不需要官方客户端进程。二进制依赖不重复打进插件包，避免把数百 MB 的无关运行时和原生攻击面带进安装。
- 请求所需官方 UA、Origin、Referer、Cookie、`x-device-id`、`x-chat-id`、`x-platform`、`x-csrf-token` 与 `clt-acs-*` / `eo-clt-*` 安全头在协议层保留并签名。
