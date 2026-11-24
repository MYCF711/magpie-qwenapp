import { createHash } from "node:crypto"
import { QwenError, CODES } from "./errors.mjs"

export const REQUIRED_COOKIES = Object.freeze(["tongyi_sso_ticket", "tongyi_sso_ticket_hash"])
const NATIVE_STRING_FIELDS = ["serviceTicket", "kpsWg", "uId", "nickname", "uidWsg", "utdid", "securityMobile", "displayUserId", "avatarUrl"]
const MOBILE_SHAPE = /^1[3-9]\d{9}$/
const MASKED_SHAPE = /^\d{3}\*{4}\d{4}$/

/** 脱敏手机号只用于界面显示名：保留前3后4，绝不出现在 auth.key、日志或错误正文。 */
export function maskMobile(value) {
  const raw = String(value ?? "").trim()
  // 上游账号资料里的 security_mobile 本身可能已经是脱敏形态，直接沿用，不重复处理。
  if (MASKED_SHAPE.test(raw)) return raw
  const text = raw.replace(/[\s()-]/g, "").replace(/^(\+?86|0086)/, "")
  return MOBILE_SHAPE.test(text) ? `${text.slice(0, 3)}****${text.slice(-4)}` : ""
}

/**
 * 账号显示名优先级：脱敏手机号 > 非手机号昵称 > uid 后四位 > 凭据指纹后四位兜底。
 * 返回值会进入 magpie 的 accountId，因此必须可区分且不含完整手机号或其它秘密。
 *
 * 最后一档是给「只粘贴 Cookie」的账号准备的：那种凭据没有 `native` 字段，
 * 前三条都取不到，于是 `successAuth()` 就不给 `accountId`，magpie 会退化成
 * 把 `auth.key`（一坨 JSON）截断显示成 `API key …"}}}`。用 sha256 指纹的后四位
 * 生成 `千问用户-xxxx` 既不含任何秘密，又能让多个纯 Cookie 账号互相区分。
 */
export function accountLabelOf({ native, mobile, fingerprint } = {}) {
  const masked = maskMobile(mobile) || maskMobile(native?.securityMobile)
  if (masked) return masked
  const nickname = String(native?.nickname ?? "").trim()
  if (nickname && !MOBILE_SHAPE.test(nickname.replace(/[\s()-]/g, ""))) return nickname.slice(0, 80)
  const uid = String(native?.uId ?? "").trim()
  if (uid) return `千问用户-${uid.slice(-4)}`
  const fp = String(fingerprint ?? "").trim()
  return fp ? `千问用户-${fp.slice(-4)}` : "千问用户"
}

export function parseCookie(input) {
  const raw = String(input || "").trim()
  if (!raw) return {}
  const out = Object.create(null)
  for (const part of raw.split(";")) {
    const at = part.indexOf("=")
    if (at <= 0) continue
    const name = part.slice(0, at).trim()
    const value = part.slice(at + 1).trim()
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /[\r\n\0;]/.test(value)) continue
    out[name] = value
  }
  return out
}

export function serializeCookie(jar) {
  return Object.entries(jar || {})
    .filter(([name, value]) => name && value !== undefined && value !== null && String(value) !== "")
    .map(([name, value]) => `${name}=${value}`)
    .join("; ")
}

export function validateCookie(input) {
  const jar = typeof input === "string" ? parseCookie(input) : { ...(input || {}) }
  for (const [name, value] of Object.entries(jar)) {
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /[\r\n\0;]/.test(String(value))) {
      throw new QwenError("Cookie 名称或值包含非法分隔/控制字符", { status: 400, code: CODES.invalidRequest })
    }
  }
  const missing = REQUIRED_COOKIES.filter((name) => !String(jar[name] || "").trim())
  if (missing.length) {
    throw new QwenError(`Cookie 缺少必需字段：${missing.join("、")}`, { status: 400, code: CODES.invalidRequest })
  }
  return jar
}

export function normalizeCookie(input) {
  return serializeCookie(validateCookie(input))
}

export function normalizeNative(native) {
  if (!native || typeof native !== "object" || Array.isArray(native)) return null
  const out = {}
  for (const key of NATIVE_STRING_FIELDS) {
    const source = key === "utdid" && native.utdid === undefined ? native.unetUtdid : native[key]
    if (source !== undefined && source !== null && String(source) !== "") {
      const value = String(source)
      if (value.length > 64 * 1024 || /[\r\n\0]/.test(value)) {
        throw new QwenError(`native.${key} 过长或含控制字符`, { status: 400, code: CODES.invalidRequest })
      }
      out[key] = value
    }
  }
  for (const key of ["serviceTicket", "kpsWg", "uId"]) {
    if (!out[key]) throw new QwenError(`原生凭据缺少 ${key}`, { status: 400, code: CODES.invalidRequest })
  }
  if (out.nickname === undefined) out.nickname = ""
  const uc = native.ucParams && typeof native.ucParams === "object" && !Array.isArray(native.ucParams) ? native.ucParams : {}
  out.ucParams = {}
  for (const [key, value] of Object.entries(uc).slice(0, 64)) {
    if (!/^[a-z][a-z0-9_]{0,30}$/i.test(key) || (typeof value !== "string" && typeof value !== "number")) continue
    const text = String(value)
    if (text.length <= 4096 && !/[\r\n\0]/.test(text)) out.ucParams[key] = text
  }
  return out
}

export function parseCredential(input, { native: nativeOverride } = {}) {
  let value = input
  if (typeof input === "string" && input.trim().startsWith("{")) {
    try { value = JSON.parse(input) } catch {
      throw new QwenError("auth.key JSON credential 无法解析", { status: 400, code: CODES.invalidRequest })
    }
  }
  const cookie = value && typeof value === "object" && !Array.isArray(value) ? value.cookie : value
  const native = nativeOverride === undefined
    ? (value && typeof value === "object" && !Array.isArray(value) ? value.native : undefined)
    : nativeOverride
  return {
    cookie: normalizeCookie(cookie),
    ...(native ? { native: normalizeNative(native) } : {}),
  }
}

export function serializeCredential(input, options) {
  return JSON.stringify(parseCredential(input, options))
}

export function cookieFingerprint(input) {
  const credential = parseCredential(input)
  const jar = validateCookie(credential.cookie)
  return createHash("sha256")
    .update(`${jar.tongyi_sso_ticket}\n${jar.tongyi_sso_ticket_hash}`)
    .digest("hex")
    .slice(0, 32)
}

export function authCredentialOf(auth) {
  const key = String(auth?.key || "").trim()
  if (!key) {
    throw new QwenError("千问账号未登录，请导入 Windows 客户端 Cookie 或粘贴 Cookie", {
      status: 401,
      code: CODES.signInRequired,
      signIn: "expired",
    })
  }
  return parseCredential(key)
}

/** 只返回上游 Cookie；native 字段绝不拼入 Cookie 头。 */
export function authKeyOf(auth) {
  return authCredentialOf(auth).cookie
}

export function successAuth(credential, { note = "", native, mobile } = {}) {
  const parsed = parseCredential(credential, { native })
  const fingerprint = cookieFingerprint(parsed)
  const uid = parsed.native?.uId || fingerprint
  const label = String(note || accountLabelOf({ native: parsed.native, mobile, fingerprint }) || "").trim().slice(0, 80)
  return {
    type: "success",
    key: JSON.stringify(parsed),
    ...(label ? { accountId: label } : {}),
    uid,
    metadata: {
      kind: parsed.native ? "qianwen-native" : "qianwen-cookie",
      accountFingerprint: fingerprint,
      ...(parsed.native?.uId ? { userId: parsed.native.uId } : {}),
    },
  }
}

/** refresh 是合并结果：保留宿主字段与 native，只规范化 auth.key 内的保密 JSON。 */
export function refreshAuth(auth) {
  const parsed = authCredentialOf(auth)
  const fingerprint = cookieFingerprint(parsed)
  const uid = parsed.native?.uId || auth?.uid || fingerprint
  // 旧的 Windows 导入记录/纯 Cookie 记录可能没有 accountId，magpie 会退化成把 auth.key 截断显示。
  // 这里按当前 native 字段（再退到凭据指纹）重算显示名，让已有账号在下次续期后也变成可读名称；
  // 宿主显式设置的 accountId 优先，不覆盖用户自己的命名。
  const label = String(auth?.accountId || "").trim() || accountLabelOf({ native: parsed.native, fingerprint })
  return {
    ...auth,
    key: JSON.stringify(parsed),
    uid,
    ...(label ? { accountId: label } : {}),
    metadata: {
      ...(auth?.metadata && typeof auth.metadata === "object" ? auth.metadata : {}),
      kind: parsed.native ? "qianwen-native" : "qianwen-cookie",
      accountFingerprint: fingerprint,
      ...(parsed.native?.uId ? { userId: parsed.native.uId } : {}),
    },
  }
}

export function authIdentity(auth) {
  // 缓存、会话与锁只信完整登录 Cookie 的稳定指纹：即使两台账号恰好带相同 uid，
  // 也绝不会共用安全缓存或会话。代价只是同一账号重复登录各留一份独立缓存，
  // 换来的是任何 uid 碰撞/伪造都不可能造成跨账号串状态。
  return cookieFingerprint(authCredentialOf(auth))
}
