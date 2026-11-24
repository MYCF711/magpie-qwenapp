# NOTICE

## magpie-plugin-scaffold v0.3.15

- 仓库：https://github.com/MYCF711/magpie-plugin-scaffold
- 许可：MIT。
- 采用内容：九钩插件装配约定、`scripts/check.mjs` 的检查方法、`scripts/check-error-codes.mjs` 与 `scripts/check-ua.mjs` 的基础实现、错误路由与额度窗口语义。

## DClaw plugin 0.4.1

- 本地来源：`Dclaw/plugin`，包版本 0.4.1。
- 许可：MIT。
- 原样复用的厂商无关模块：`src/openai-sse.mjs`、`src/stream-reader.mjs`、`src/refresh-lock.mjs`。
- 改编内容：DPAPI + Chromium AES-GCM 的桌面导入边界、原子缓存、origin 闸门与统一错误外壳。

这些模块的上游 NOTICE 还列明以下 MIT 来源，相关归属继续保留：

- magpie-community/plugins：CodeArts / zen-free 的 SSE 解析与折叠、raccoon / workbuddy 的刷新单飞模式。
- sabercomo/magpie-workbuddy-plus：原子缓存与权限位模式。
- MYCF711 的 magpie-magicrew-auth、magpie-officeace：refresh 单飞模式。
- 同作者的 magpie-wps-lingxi 插件：空闲读取不丢在飞块的 reader 模式。

## 千问 / QianwenApp

- 千问名称、官方图标和服务权利归原厂商所有；本插件是非官方适配层。
- `icon-official.png` 是用户提供的官方应用图标，仅用于供应商与插件标识。
- 端点、Cookie 形状、register、HMAC 签名、请求字段与 SSE 行为来自用户提供的本地脱敏协议事实及实测；未复制许可不完整仓库的实现代码。
- `src/wsg.mjs` 只嵌入用户确认可公开的非个人密文/key=IV 常量并派生 record secret；账号与设备秘密只经参数传递，不写入该模块或日志。

本项目自身以 MIT 发布，完整正文见 `LICENSE`。
