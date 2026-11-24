import { CHAT_URL, NATIVE_CHAT_URL, MODEL_LIST_URL, MODEL_PANEL_URL, REGISTER_URL } from "./constants.mjs"
import { QwenError, CODES } from "./errors.mjs"

export const ALLOWED_ENDPOINTS = Object.freeze({
  chat: new URL(CHAT_URL),
  nativeChat: new URL(NATIVE_CHAT_URL),
  register: new URL(REGISTER_URL),
  panel: new URL(MODEL_PANEL_URL),
  models: new URL(MODEL_LIST_URL),
})

const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
const DEFAULT_ALLOWLIST = Object.freeze(["accept", "content-type"])
const MAX_HEADERS = 64
const MAX_NAME = 128
const MAX_VALUE = 32 * 1024

export function assertTrustedUrl(input, endpoint) {
  let url
  try { url = input instanceof URL ? new URL(input.href) : new URL(String(input)) } catch {
    throw new QwenError("拒绝无法解析的上游 URL", { status: 502, code: CODES.internalError })
  }
  if (url.protocol !== "https:") {
    throw new QwenError("上游 URL 只允许 HTTPS", { status: 502, code: CODES.internalError })
  }
  if (url.username || url.password) {
    throw new QwenError("上游 URL 不允许 userinfo", { status: 502, code: CODES.internalError })
  }
  if (url.port && url.port !== "443") {
    throw new QwenError("上游 URL 不允许非默认端口", { status: 502, code: CODES.internalError })
  }
  if (endpoint) {
    const expected = typeof endpoint === "string" ? ALLOWED_ENDPOINTS[endpoint] : endpoint
    if (!expected || url.origin !== expected.origin || url.pathname !== expected.pathname) {
      throw new QwenError("上游 URL 不在固定的 qianwen.com 端点白名单内", { status: 502, code: CODES.internalError })
    }
  } else if (!Object.values(ALLOWED_ENDPOINTS).some((item) => item.origin === url.origin && item.pathname === url.pathname)) {
    throw new QwenError("上游 URL 不在固定的 qianwen.com 端点白名单内", { status: 502, code: CODES.internalError })
  }
  return url
}

export function assertSdkChatUrl(input) {
  let url
  try { url = new URL(input instanceof Request ? input.url : String(input)) } catch {
    throw new QwenError("无法解析模型请求 URL", { status: 400, code: CODES.invalidRequest })
  }
  if (url.protocol !== "https:" || url.username || url.password || (url.port && url.port !== "443")) {
    throw new QwenError("模型请求 URL 的协议或凭据形状不合法", { status: 400, code: CODES.invalidRequest })
  }
  const validPath = url.pathname === "/v1/chat/completions" || url.pathname === "/chat/completions"
  if (url.hostname !== "chat2.qianwen.com" || !validPath) {
    throw new QwenError("仅支持千问 Chat Completions 端点", { status: 501, code: CODES.notImplemented })
  }
  return url
}

/** 默认只保留 accept/content-type；敏感头只能由运行时从 magpie auth.key 重建。 */
export function headerSafe(input, { allowlist = DEFAULT_ALLOWLIST } = {}) {
  const allowed = new Set([...allowlist].map((name) => String(name).toLowerCase()))
  const source = input instanceof Headers ? input : new Headers(input || {})
  const out = new Headers()
  let count = 0
  for (const [rawName, value] of source) {
    const name = rawName.toLowerCase()
    if (!allowed.has(name)) continue
    if (++count > MAX_HEADERS || name.length > MAX_NAME || !HEADER_NAME.test(name)) {
      throw new QwenError("请求头数量或名称不合法", { status: 400, code: CODES.invalidRequest })
    }
    const text = String(value)
    if (text.length > MAX_VALUE || /[\r\n\0]/.test(text)) {
      throw new QwenError("请求头值包含非法字符或过长", { status: 400, code: CODES.invalidRequest })
    }
    out.set(name, text)
  }
  return out
}

export function redactHeaders(input) {
  const out = {}
  for (const [key, value] of new Headers(input || {})) {
    out[key] = /cookie|authorization|token|ticket|session|sign|actkn|sacsft|dvidn|snver|csrf|key|kps|utdid|vcode|device|acs-kp/i.test(key)
      ? "[redacted]"
      : String(value).slice(0, 300)
  }
  return out
}
