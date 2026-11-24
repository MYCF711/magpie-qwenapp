import { constants as cryptoConstants, createPublicKey, publicEncrypt, randomBytes as nodeRandomBytes } from "node:crypto"
import { normalizeCookie } from "./cookie.mjs"
import { QwenError, CODES } from "./errors.mjs"
import { wsgEncrypt } from "./wsg.mjs"

export const PASSPORT_ORIGIN = "https://passport.qianwen.com"
export const LOGIN_PAGE_URL = "https://passport.qianwen.com/havanaone/login/login.htm?bizPassParams=x-platform%3DexternalH5&bizEntrance=tongyi&bizName=tongyi&redirectType=topRedirect&lang=zh_CN&returnUrl=https%3A%2F%2Fwww.qianwen.com%2Fdesktop-app"
export const SEND_SMS_PATH = "/havanaone/loginLegacy/sms/sendSms.do"
export const SMS_LOGIN_PATH = "/havanaone/loginLegacy/sms/login.do"
export const ACCOUNT_INFO_URL = "https://api.qianwen.com/api/account/v2/info"

const COOKIE_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/

export function normalizeMobile(value) {
  let text = String(value ?? "").trim().replace(/[\s()-]/g, "")
  if (text.startsWith("+86")) text = text.slice(3)
  else if (text.startsWith("0086")) text = text.slice(4)
  if (/^86\d{11}$/.test(text)) text = text.slice(2)
  return /^1[3-9]\d{9}$/.test(text) ? text : null
}

export function validSmsCode(value) {
  return /^\d{6}$/.test(String(value ?? "").trim())
}

function domainMatches(host, domain) {
  const expected = String(domain || "").replace(/^\./, "").toLowerCase()
  return host === expected || host.endsWith(`.${expected}`)
}

function defaultPath(pathname) {
  const end = pathname.lastIndexOf("/")
  return end > 0 ? pathname.slice(0, end) : "/"
}

/** 每个短信 flow 独立持有；不写磁盘，不读取任何既有 profile。 */
export class MemoryCookieJar {
  constructor() { this.records = [] }

  set(name, value, { domain = "www.qianwen.com", path = "/", maxAge, hostOnly = false } = {}) {
    if (!COOKIE_NAME.test(name) || /[\r\n\0;]/.test(String(value))) return
    const record = { name, value: String(value), domain: String(domain).replace(/^\./, "").toLowerCase(), path, hostOnly: Boolean(hostOnly) }
    if (maxAge !== undefined) record.expiresAt = Date.now() + Number(maxAge) * 1000
    const index = this.records.findIndex((item) => item.name === name && item.domain === record.domain && item.path === path)
    if (index >= 0) this.records.splice(index, 1)
    this.records.push(record)
  }

  ingest(headers, url) {
    const target = new URL(url)
    let lines = []
    if (typeof headers?.getSetCookie === "function") lines = headers.getSetCookie()
    if (!lines.length) {
      const raw = headers?.get?.("set-cookie")
      if (raw) lines = raw.split(/,(?=\s*[!#$%&'*+.^_`|~0-9A-Za-z-]+=[^;]*)/g)
    }
    for (const line of lines) {
      const parts = String(line).split(";")
      const at = parts[0].indexOf("=")
      if (at <= 0) continue
      const name = parts[0].slice(0, at).trim()
      const value = parts[0].slice(at + 1).trim()
      const attributes = Object.create(null)
      for (const part of parts.slice(1)) {
        const index = part.indexOf("=")
        const key = (index < 0 ? part : part.slice(0, index)).trim().toLowerCase()
        attributes[key] = index < 0 ? true : part.slice(index + 1).trim()
      }
      const domain = attributes.domain || target.hostname
      if (!domainMatches(target.hostname, domain)) continue
      this.set(name, value, {
        domain,
        path: attributes.path || defaultPath(target.pathname),
        hostOnly: !attributes.domain,
        ...(attributes["max-age"] !== undefined ? { maxAge: Number(attributes["max-age"]) } : {}),
      })
      if (attributes.expires && !attributes["max-age"]) {
        const record = this.records.at(-1)
        const expires = Date.parse(attributes.expires)
        if (record && Number.isFinite(expires)) record.expiresAt = expires
      }
    }
  }

  get(name, url) {
    if (url) return this.cookieObject(url)[name] || ""
    const now = Date.now()
    for (let index = this.records.length - 1; index >= 0; index -= 1) {
      const record = this.records[index]
      if (record.name === name && (!record.expiresAt || record.expiresAt > now)) return record.value
    }
    return ""
  }

  cookieObject(url) {
    const target = new URL(url)
    const now = Date.now()
    const out = {}
    const pathMatches = (cookiePath) => cookiePath === "/" || target.pathname === cookiePath ||
      target.pathname.startsWith(cookiePath.endsWith("/") ? cookiePath : `${cookiePath}/`)
    const selected = this.records
      .filter((record) => (!record.expiresAt || record.expiresAt > now) &&
        (record.hostOnly ? target.hostname === record.domain : domainMatches(target.hostname, record.domain)) && pathMatches(record.path))
      // 后写覆盖：长 path 优先；同 path 时 host-only 优先；同键新记录最后生效。
      .sort((a, b) => a.path.length - b.path.length || Number(a.hostOnly) - Number(b.hostOnly))
    for (const record of selected) out[record.name] = record.value
    return out
  }

  cookieHeader(url) {
    return Object.entries(this.cookieObject(url)).map(([name, value]) => `${name}=${value}`).join("; ")
  }

  clear() { this.records = [] }
}

export function assertHavanaUrl(value, expectedPath) {
  let url
  try { url = new URL(value, LOGIN_PAGE_URL) } catch {
    throw new QwenError("登录 URL 无法解析", { status: 400, code: CODES.invalidRequest })
  }
  if (url.protocol !== "https:" || url.origin !== PASSPORT_ORIGIN || url.pathname !== expectedPath || url.username || url.password || url.port) {
    throw new QwenError("登录 URL 不在固定 HTTPS origin/path 白名单", { status: 400, code: CODES.invalidRequest })
  }
  return url
}

function assignmentObject(html, name) {
  const marker = new RegExp(`window\\.${name}\\s*=`).exec(html)
  if (!marker) return null
  const start = html.indexOf("{", marker.index)
  if (start < 0) return null
  let depth = 0
  let quote = ""
  let escaped = false
  for (let index = start; index < html.length; index += 1) {
    const char = html[index]
    if (escaped) { escaped = false; continue }
    if (char === "\\") { escaped = true; continue }
    if (quote) {
      if (char === quote) quote = ""
      continue
    }
    if (char === '"' || char === "'") { quote = char; continue }
    if (char === "{") depth += 1
    if (char === "}" && --depth === 0) return html.slice(start, index + 1)
  }
  return null
}

function parseWindowObject(html, name) {
  const source = assignmentObject(html, name)
  if (!source) throw new QwenError(`登录页缺少 window.${name}`, { status: 502, code: CODES.upstreamError })
  try { return JSON.parse(source) } catch {
    throw new QwenError(`登录页 window.${name} 不是安全 JSON 对象`, { status: 502, code: CODES.upstreamError })
  }
}

function publicApi(value, path) {
  const url = assertHavanaUrl(value || `${PASSPORT_ORIGIN}${path}`, path)
  for (const key of ["bizEntrance", "bizName"]) {
    const value = url.searchParams.get(key)
    if (value !== null && value !== "tongyi") {
      throw new QwenError(`登录 API query ${key} 必须为 tongyi`, { status: 400, code: CODES.invalidRequest })
    }
    url.searchParams.set(key, "tongyi")
  }
  return url.toString()
}

export function parseLoginPage(html) {
  const viewConfig = parseWindowObject(String(html || ""), "viewConfig")
  const viewData = parseWindowObject(String(html || ""), "viewData")
  const loginFormData = viewData.loginFormData || viewData.loginData || {}
  const formCsrf = loginFormData._csrf || viewData._csrf
  if (typeof formCsrf !== "string" || !formCsrf) {
    throw new QwenError("登录页缺少表单 _csrf", { status: 502, code: CODES.upstreamError })
  }
  if (Number(viewConfig.smsCodeLength || 6) !== 6) {
    throw new QwenError("登录页短信码长度不是已支持的 6 位", { status: 400, code: CODES.invalidRequest })
  }
  const publicFields = {}
  for (const key of ["umidToken", "umidTag", "requestExtParams"]) {
    const value = loginFormData[key] ?? viewData[key]
    if (typeof value === "string" && value) publicFields[key] = value
  }
  return {
    viewConfig,
    viewData,
    formCsrf,
    contextToken: String(loginFormData.contextToken || viewData.contextToken || ""),
    sendUrl: publicApi(viewConfig.api?.sendSmsApi, SEND_SMS_PATH),
    loginUrl: publicApi(viewConfig.api?.smsLoginApi, SMS_LOGIN_PATH),
    rsaModulusSec: viewConfig.rsaModulusSec || loginFormData.rsaModulusSec || "",
    rsaExponentSec: viewConfig.rsaExponentSec || loginFormData.rsaExponentSec || "",
    ua: String(viewConfig.ua_Opt || loginFormData.ua || ""),
    deviceId: String(loginFormData.deviceId || viewData.deviceId || ""),
    pageTraceId: String(loginFormData.pageTraceId || viewData.pageTraceId || ""),
    publicFields,
  }
}

export function responseData(payload, login = false) {
  const candidates = login
    ? [payload?.data?.content?.data, payload?.content?.data, payload?.data]
    : [payload?.content?.data, payload?.data?.content?.data, payload?.data]
  return candidates.find((value) => value && typeof value === "object" && !Array.isArray(value)) || {}
}

function normalizedFlag(value) {
  if (value === true || value === 1 || (typeof value === "string" && /^(?:true|1)$/i.test(value.trim()))) return true
  if (value === false || value === 0 || (typeof value === "string" && /^(?:false|0)$/i.test(value.trim()))) return false
  return "unknown"
}

function errorFlag(source, key) {
  return Boolean(source && Object.hasOwn(source, key) && normalizedFlag(source[key]) !== false)
}

function failedSuccessFlag(source, key = "success") {
  return Boolean(source && Object.hasOwn(source, key) && normalizedFlag(source[key]) !== true)
}

export function loginPayloadError(payload, data) {
  return errorFlag(payload, "hasError") || errorFlag(payload, "failed") || failedSuccessFlag(payload) ||
    errorFlag(data, "hasError") || errorFlag(data, "failed") || failedSuccessFlag(data) ||
    Boolean(payload?.errorCode || payload?.errorMsg || data?.errorCode || data?.errorMsg) ||
    errorFlag(payload, "isCheckCodeShowed") || errorFlag(data, "isCheckCodeShowed") ||
    Boolean(data?.titleMsg && data?.actionType)
}

export function safeLoginRedirect(value) {
  try {
    const url = new URL(String(value || ""))
    return url.protocol === "https:" && url.origin === "https://www.qianwen.com" &&
      !url.username && !url.password && !url.port && (url.pathname === "/desktop-app" || url.pathname === "/")
  } catch { return false }
}

/** 仅官方 handleLoginResult 分支 + 固定安全目标；resultCode/通用 success 本身不是成功凭据。 */
export function officialLoginSuccess(payload, data) {
  if (loginPayloadError(payload, data) || data?.smsRegToken || data?.smsRegTips) return false
  const redirects = [
    [data?.redirect, data?.redirectUrl],
    [data?.parentRedirect, data?.parentRedirectUrl],
    [data?.iframeRedirect, data?.iframeRedirectUrl],
    [data?.replace, data?.replaceUrl],
  ]
  if (redirects.some(([flag, url]) => flag === true && safeLoginRedirect(url))) return true
  return typeof data?.st === "string" && data.st.length > 0
}

function hexBuffer(value, exponent = false) {
  if (typeof value === "number") return hexBuffer(value.toString(16), exponent)
  let text = String(value || "").trim().replace(/^0x/i, "")
  if (exponent && text === "65537") text = "10001"
  if (!/^[0-9a-f]+$/i.test(text) || text.length % 2) text = `0${text}`
  return Buffer.from(text, "hex")
}

/** JSEncrypt RSA/PKCS1 v1.5 等价：Sec modulus/exponent 存在时返回 Base64，否则 null。 */
export function rsaEncryptMobile(mobile, modulus, exponent) {
  if (!modulus || !exponent) return null
  const n = hexBuffer(modulus)
  const e = hexBuffer(exponent, true)
  if (!n.length || !e.length) return null
  const key = createPublicKey({ key: { kty: "RSA", n: n.toString("base64url"), e: e.toString("base64url") }, format: "jwk" })
  return publicEncrypt({ key, padding: cryptoConstants.RSA_PKCS1_PADDING }, Buffer.from(String(mobile), "utf8")).toString("base64")
}

function infoSources(info) {
  return [info?.data?.account, info?.data?.user, info?.data, info?.content?.data, info]
    .filter((value) => value && typeof value === "object" && !Array.isArray(value))
}

function explicitField(sources, names, { allowEmpty = false } = {}) {
  for (const source of sources) {
    for (const name of names) {
      if (!Object.hasOwn(source, name)) continue
      const value = source[name]
      // 上游 userId 一类字段可能是数字：规范成字符串继续用，别让一个别名直接终止整条匹配。
      if (typeof value === "number" && Number.isFinite(value)) return { found: true, value: String(value) }
      if (typeof value !== "string") continue
      if (value || allowEmpty) return { found: true, value }
    }
  }
  return { found: false, value: null }
}

/** 只接受实际 Cookie/info 字段；四字段缺一即失败，绝不使用 OAuth/register token 冒充。 */
export function buildNativeCredential({ jar, info, randomBytes = nodeRandomBytes } = {}) {
  if (loginPayloadError(info, info?.data || {}) || Number(info?.httpCode) === 401 || info?.errorCode === "NOT_LOGIN") {
    throw new QwenError("短信登录后的 /info 仍返回 NOT_LOGIN，未保存 Web 会话", { status: 401, code: CODES.sessionExpired })
  }
  const cookie = {
    ...(jar?.cookieObject ? jar.cookieObject("https://www.qianwen.com/") : {}),
    ...(jar?.cookieObject ? jar.cookieObject(ACCOUNT_INFO_URL) : {}),
  }
  const sources = infoSources(info)
  // 仅 info 等明确账号来源可提供 uId/nickname；Cookie 不得充当这些字段的别名来源。
  // 别名来自实测：/api/account/v2/info 返回 userId / userNick / telephone / userAvatarUrl，而不是 uId / nickname。
  const service = explicitField(sources, ["serviceTicket", "service_ticket"])
  const kps = explicitField(sources, ["kpsWg", "kps_wg"])
  const uid = explicitField(sources, ["uId", "uid", "userId", "user_id"])
  const nickname = explicitField(sources, ["userNick", "nickname", "nick", "displayName"], { allowEmpty: true })
  const mobile = explicitField(sources, ["telephone", "mobile", "security_mobile", "securityMobile"])
  const serviceTicket = service.value || cookie.tongyi_sso_ticket || null
  const resolvedUid = uid.value
  const resolvedNickname = nickname.value
  // kpsWg 不是服务端字段：它由客户端用 WSG 对本次会话材料做本地派生。
  // 已用真实 Windows 账号的 kpsWg 逐字节对拍确认（长度 176、前缀 O/ 完全一致）。
  const derivedKps = serviceTicket && resolvedUid
    ? wsgEncrypt(`token=${serviceTicket}&uid=${resolvedUid}&nickname=${resolvedNickname ?? ""}`)
    : null
  const native = {
    // 既有桌面账号证据仅支持 tongyi_sso_ticket 这一条 serviceTicket 回退。
    serviceTicket,
    // 服务端明确给出 kpsWg 时以其为准；否则用同一公式本地派生，绝不使用 OAuth/register token 冒充。
    kpsWg: kps.value || derivedKps,
    uId: resolvedUid,
    nickname: resolvedNickname,
    // 只用于本地生成脱敏显示名；仍只存在 auth.key，不进日志。
    ...(mobile.value ? { securityMobile: mobile.value } : {}),
  }
  const missing = ["serviceTicket", "kpsWg", "uId", "nickname"].filter((key) => typeof native[key] !== "string" || (key !== "nickname" && !native[key]))
  if (missing.length) {
    throw new QwenError(`登录仅有 Web 会话，Cookie/info 缺少完整 native 字段：${missing.join("、")}；未冒充原生登录`, {
      status: 400,
      code: CODES.invalidRequest,
    })
  }
  for (const name of ["serviceTicket", "service_ticket", "kpsWg", "kps_wg", "uId", "uid", "userId", "user_id", "nickname", "nick", "displayName", "uidWsg", "utdid"]) {
    delete cookie[name]
  }
  for (const name of ["tongyi_sso_ticket", "tongyi_sso_ticket_hash"]) {
    const fromInfo = explicitField(sources, [name])
    if (!cookie[name] && fromInfo.value) cookie[name] = fromInfo.value
  }
  const normalizedCookie = normalizeCookie(cookie)
  const utdid = randomBytes(12).toString("hex")
  return {
    cookie: normalizedCookie,
    native: {
      ...native,
      uidWsg: wsgEncrypt(native.uId),
      utdid,
      ucParams: { ut: wsgEncrypt(utdid) },
    },
  }
}
