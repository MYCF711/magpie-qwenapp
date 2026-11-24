# magpie-qwenapp

把 **千问（Qianwen / Qwen）** 接入 [magpie](https://github.com/yetone/magpie)，用标准 **OpenAI Chat Completions** 协议调用千问模型。

插件使用千问**原生 cowork 通道**（`/v1/chat/completions` + WSG / signWg 签名），不是 Web 网页接口。因此：

- **不注入官方系统提示词**：调用方的 `system` / `user` / `assistant` 原样透传，实测 `prompt_tokens` 与调用方内容一致（Web 通道同一句话是 4192，原生是 58）。
- **不启动官方客户端**：运行期不需要 `qianwen.exe`、不加载官方 DLL。
- **支持原生工具调用**：标准 `tools` / `tool_choice` / `tool_calls`，包括流式 `delta.tool_calls`。
- **真流式**：逐块驱动 `ReadableStream`，支持取消、空闲超时和 UTF-8 断字。
- **真实用量**：直接读上游 `total_usage`，没有读数时不估算。

## 安装

```bash
magpie plugin add github:MYCF711/magpie-qwenapp
```

要求 Node.js ≥ 22.19.0。

## 登录

三种方式，按顺序排列：

| 方式 | 命令 | 说明 |
|---|---|---|
| **手机号 + 短信验证码** | `magpie plugin login qwenapp 1` | 不需要官方客户端、二维码或浏览器。依次输入手机号和 6 位验证码，输入 `0` 可重发。凭据完整后由 magpie 保存。 |
| **导入 Windows 客户端** | `magpie plugin login qwenapp 2` | 从本机已登录的千问客户端读取登录态。需要临时完全退出客户端以释放 Cookie 数据库锁；导入后不再需要它。 |
| **粘贴凭据** | `magpie plugin login qwenapp 3` | 手动粘贴 Cookie 或完整凭据。纯 Cookie 只能走 Web 兼容通道。 |

登录成功后账号卡片显示脱敏手机号（如 `199****0001`），其次是昵称，最后是 `千问用户-xxxx`。

### 关于原生凭据

原生 cowork 需要四个字段：`serviceTicket`、`kpsWg`、`uId`、`nickname`。

其中 `kpsWg` **不是服务端下发的**，而是客户端用 WSG 对本会话材料做本地派生：

```text
kpsWg  = wsgEncrypt("token=<serviceTicket>&uid=<uId>&nickname=<nickname>")
uidWsg = wsgEncrypt(uId)
uc.ut  = wsgEncrypt(utdid)
```

插件按同一公式派生，并已用真实账号的既有凭据逐字节对拍验证（长度 176、前缀 `O/`、完全一致）。四条缺任何一条都会明确报错，不会用 Web 会话冒充原生登录。

## 调用

```bash
curl http://127.0.0.1:3425/v1/chat/completions \
  -H "Authorization: Bearer <MAGPIE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwenapp/qwen4-max",
    "messages": [
      {"role": "system", "content": "你是一个简洁的 API 助手。"},
      {"role": "user", "content": "用一句话介绍量子计算。"}
    ],
    "stream": true
  }'
```

模型目录：

```bash
curl http://127.0.0.1:3425/v1/models -H "Authorization: Bearer <MAGPIE_API_KEY>"
```

已实测可用模型：`qwen4-max`、`qwen3.8-flash`、`qwen3.8-max`、`qwen3.7-max`。模型列表从账号面板动态读取，失败时使用静态回退。

## 请求头与官方依赖

插件保留官方请求形状：

- 桌面 UA（`TONGYI_DESKTOP/5.2.7.307`）、`Origin`、`Referer`、`Cookie`
- 原生签名：`X-U-SIGN-WG`、`X-U-KPS-WG`、`X-U-VCODE`、`x-utdid`
- Web 兼容路径：`x-device-id`、`x-chat-id`、`x-platform`、`x-csrf-token`、`clt-acs-*`、`eo-clt-*`

`official/` 目录保存所适配官方构建的 SHA-256 哈希清单与非个人的 WSG 常量/对照向量。插件用纯 JavaScript 实现签名，因此**不打包官方二进制**。

## 安全设计

- **固定出站目标**：HTTPS + 固定 origin/path，禁止 userinfo 与非默认端口，所有请求 `redirect: "error"`。
- **凭据只在 magpie**：Cookie 与 native 字段只进入 `auth.key`，不写入日志、错误正文或插件缓存。
- **按账号隔离**：安全缓存、会话映射、token 池一律以完整登录 Cookie 指纹为键。即使两个账号带相同 `uid` 也不会共用缓存。
- **秘密脱敏**：Cookie、ticket、token、手机号、短信验证码、CSRF、签名在错误和日志中全部脱敏。
- **额度提示转错误**：千问会把额度/会员卡片当助手正文下发（含未渲染 `{{membership_payment_buttons_card_1}}` 占位符）。插件识别后返回 `429 rate_limited`，不会把提示混进回答。
- **截断不伪装**：上游流在 `finish_reason` / `[DONE]` 之前结束会返回 `504`，不会补一个假的正常结束。
- **不碰宿主配置**：不修改 magpie 全局 `proxy`、`settings` 或其他插件。

## 边界

- 图片、音频、文件等非文本 content parts 不会被静默丢弃，未支持时返回 `400`。
- Web 兼容通道没有已核实的原生 tools 协议，请求工具时返回 `400 unsupported_tools`，不会把工具 schema 注入 system。
- `401` 只用于有明确登录失效证据的响应；模型级 `403/404` 不会误停用整个账号。
- 没有可靠额度读数时明确返回未知，不上报 `used:0` 占位。
- 上游风控、限流、额度耗尽按真实错误返回，不伪造成功文本。

## 开发与验证

```bash
node --check index.mjs
npm run check                      # 静态契约 + 协议纯函数 + 离线端到端
node --test tests/*.test.mjs       # 协议、安全、SSE、账号隔离
node scripts/privacy-scan.mjs .    # 秘密扫描
```

测试全部离线运行，使用合成凭据，不访问真实账号或网络。

## 许可

MIT，见 [LICENSE](LICENSE)。官方构建的商标与版权归其所有者，见 [NOTICE.md](NOTICE.md)。