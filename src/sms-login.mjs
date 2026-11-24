import { randomBytes as nodeRandomBytes, randomUUID as nodeRandomUUID } from "node:crypto"
import { OFFICIAL_UA } from "./constants.mjs"
import { accountLabelOf, successAuth } from "./cookie.mjs"
import { CODES, QwenError, readBounded, sanitizeText } from "./errors.mjs"
import { withIdleTimeout } from "./stream.mjs"
import {
  ACCOUNT_INFO_URL,
  LOGIN_PAGE_URL,
  PASSPORT_ORIGIN,
  MemoryCookieJar,
  buildNativeCredential,
  normalizeMobile,
  officialLoginSuccess,
  loginPayloadError,
  parseLoginPage,
  responseData,
  rsaEncryptMobile,
  validSmsCode,
} from "./sms-protocol.mjs"

const REQUEST_MS = 15_000
const FLOW_MS = 10 * 60_000
const RESEND_MS = 60_000
const MAX_SEND = 3
const MAX_VERIFY = 5

function mobilePrompt(message = "手机号") {
  return {
    type: "text",
    key: "mobile",
    message,
    placeholder: "请输入千问账号手机号",
    validate: (value) => normalizeMobile(value) ? undefined : "手机号格式不正确",
  }
}

function smsCodePrompt(message = "短信验证码；输入 0 可重发") {
  return {
    type: "password",
    key: "sms_code",
    message,
    placeholder: "请输入 6 位短信验证码；输入 0 可重发",
    validate: (value) => value === "0" || validSmsCode(value) ? undefined : "请输入完整短信验证码；输入 0 可重发",
  }
}

function secretStrings(value, depth = 0, out = []) {
  if (out.length >= 256 || depth > 8 || value === null || value === undefined) return out
  if (typeof value === "string") {
    if (value) out.push(value)
    return out
  }
  if (Array.isArray(value)) {
    for (const item of value) secretStrings(item, depth + 1, out)
  } else if (typeof value === "object") {
    for (const item of Object.values(value)) secretStrings(item, depth + 1, out)
  }
  return out
}

function safeMessage(error, secrets = []) {
  const cleaned = sanitizeText(error?.message || error || "登录请求失败", secrets.filter(Boolean))
  return cleaned.replace(/(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)/g, "[redacted]").slice(0, 600)
}

export function createSmsLoginMethod({
  fetchImpl = globalThis.fetch,
  now = () => Date.now(),
  uuid = nodeRandomUUID,
  randomBytes = nodeRandomBytes,
} = {}) {
  if (typeof fetchImpl !== "function") throw new TypeError("短信登录需要 fetchImpl")
  let pending = null
  // 不记名的方法级限流状态：ask({}) 替换 flow 不会清除上游 429 冷却。
  const sharedRateLimit = { sendUntil: 0, verifyUntil: 0 }

  function retryAfterSeconds(value) {
    const raw = String(value || "").trim()
    const numeric = Number(raw)
    if (raw && Number.isFinite(numeric) && numeric >= 0) return Math.ceil(numeric)
    const at = Date.parse(raw)
    if (Number.isFinite(at)) return Math.max(0, Math.ceil((at - Number(now())) / 1000))
    return 60
  }

  function secretsOf(flow, otp = "") {
    return [
      flow?.mobile,
      otp,
      flow?.formCsrf,
      flow?.smsToken,
      flow?.contextToken,
      flow?.jar?.get("XSRF-TOKEN"),
      flow?.deviceId,
      flow?.pageTraceId,
      ...(flow?.jar?.records || []).map((record) => record.value),
    ]
  }

  function applyRateLimit(flow, error) {
    if (error?.status !== 429) return 0
    const seconds = Math.max(60, retryAfterSeconds(error.retryAfter))
    const until = Number(now()) + seconds * 1000
    sharedRateLimit.sendUntil = Math.max(sharedRateLimit.sendUntil, until)
    sharedRateLimit.verifyUntil = Math.max(sharedRateLimit.verifyUntil, until)
    if (flow) {
      flow.cooldownUntil = Math.max(flow.cooldownUntil || 0, until)
      flow.verifyCooldownUntil = Math.max(flow.verifyCooldownUntil || 0, until)
    }
    return Math.max(0, Math.ceil((Math.max(sharedRateLimit.sendUntil, sharedRateLimit.verifyUntil) - Number(now())) / 1000))
  }

  function clearSecrets(flow) {
    if (!flow) return
    flow.mobile = null
    flow.formCsrf = null
    flow.smsToken = null
    flow.contextToken = null
    flow.otp = null
    flow.jar?.clear()
    if (flow.stage !== "verified") flow.credential = null
  }

  function close(flow, message) {
    if (!flow) return
    flow.stage = "closed"
    flow.failure = String(message || flow.failure || "短信登录未完成，请重新登录").slice(0, 600)
    clearSecrets(flow)
  }

  function expired(flow) {
    if (!flow || flow.stage === "closed") return true
    if (Number(now()) < flow.expiresAt) return false
    close(flow, "短信登录已超过 10 分钟，请重新登录")
    return true
  }

  function current(flow, id, operationId) {
    return pending === flow && flow.id === id && flow.operationId === operationId && flow.stage !== "closed" && Number(now()) < flow.expiresAt
  }

  async function request(flow, url, { method = "GET", form, accept, signal, html = false } = {}) {
    const headers = {
      "user-agent": OFFICIAL_UA,
      accept: accept || "application/json, text/plain, */*",
      cookie: flow.jar.cookieHeader(url),
    }
    if (form) {
      headers["content-type"] = "application/x-www-form-urlencoded; charset=UTF-8"
      headers["x-xsrf-token"] = flow.jar.get("XSRF-TOKEN", url)
      headers.origin = PASSPORT_ORIGIN
      headers.referer = LOGIN_PAGE_URL
    }
    let response
    try {
      response = await fetchImpl(url, {
        method,
        headers,
        ...(form ? { body: form.toString() } : {}),
        redirect: "error",
        signal,
      })
      flow.jar.ingest(response.headers, url)
      const body = response.body ? withIdleTimeout(response.body, { timeoutMs: REQUEST_MS, totalMs: REQUEST_MS, signal }) : null
      const text = await readBounded({ body }, { limit: html ? 2 * 1024 * 1024 : 1024 * 1024, signal })
      let payload = {}
      if (!html && text.trim()) {
        try { payload = JSON.parse(text) } catch { payload = { _text: text } }
      }
      if (!response.ok) {
        const data = responseData(payload)
        const message = data.titleMsg || data.errorMsg || payload.errorMsg || `登录 HTTP ${response.status}`
        const status = response.status === 429 ? 429 : response.status >= 500 ? 503 : 502
        const code = response.status === 429 ? CODES.rateLimited : response.status >= 500 ? CODES.upstreamUnavailable : CODES.upstreamError
        const error = new QwenError(message, { status, code })
        error.retryAfter = response.headers?.get?.("retry-after") || ""
        error.secrets = secretStrings(payload)
        throw error
      }
      return { response, text, payload }
    } catch (error) {
      if (error instanceof QwenError) throw error
      if (signal?.aborted && signal.reason instanceof Error) throw signal.reason
      throw new QwenError("短信登录网络请求失败", { status: 503, code: CODES.upstreamUnavailable, cause: error })
    }
  }

  async function withDeadline(fn) {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(new QwenError("短信登录请求超过 15 秒", {
      status: 504,
      code: CODES.upstreamTimeout,
    })), REQUEST_MS)
    try { return await fn(controller.signal) } finally { clearTimeout(timer) }
  }

  async function initialize(flow, signal) {
    const { text } = await request(flow, LOGIN_PAGE_URL, {
      accept: "text/html, application/javascript;q=0.9",
      signal,
      html: true,
    })
    const page = parseLoginPage(text)
    if (!flow.jar.get("XSRF-TOKEN", LOGIN_PAGE_URL)) throw new QwenError("登录页未签发 XSRF-TOKEN Cookie", { status: 502, code: CODES.upstreamError })
    flow.page = page
    flow.sendUrl = page.sendUrl
    flow.loginUrl = page.loginUrl
    flow.formCsrf = page.formCsrf
    flow.contextToken = page.contextToken
    flow.deviceId = page.deviceId || uuid().replaceAll("-", "")
    flow.pageTraceId = page.pageTraceId || uuid().replaceAll("-", "")
  }

  function commonForm(flow) {
    const form = new URLSearchParams()
    const values = {
      _csrf: flow.formCsrf || "",
      phoneCode: "86",
      countryCode: "CN",
      codeLength: "6",
      contextToken: flow.contextToken || "",
      bizEntrance: "tongyi",
      bizName: "tongyi",
      bizPassParams: "x-platform=externalH5",
      redirectType: "topRedirect",
      returnUrl: "https://www.qianwen.com/desktop-app",
      lang: "zh_CN",
      defaultView: "sms",
      isIframe: "false",
      documentReferer: "",
      ua: flow.page?.ua || "",
      deviceId: flow.deviceId || "",
      pageTraceId: flow.pageTraceId || "",
      jsVersion: "0.10.38",
      hitRSA2048Gray: "true",
      ...(flow.page?.publicFields || {}),
    }
    for (const [key, value] of Object.entries(values)) form.set(key, String(value))
    let encrypted = null
    if (flow.page?.rsaModulusSec && flow.page?.rsaExponentSec) {
      try { encrypted = rsaEncryptMobile(flow.mobile, flow.page.rsaModulusSec, flow.page.rsaExponentSec) } catch { encrypted = null }
    }
    form.set("loginId", encrypted ? "" : flow.mobile)
    form.set("loginId2", encrypted || "")
    return form
  }

  async function send(flow, resend = false) {
    if (flow.sendCount >= MAX_SEND) {
      close(flow, "短信发送次数已达 3 次上限，请重新登录")
      return null
    }
    const id = flow.id
    const operationId = uuid()
    flow.operationId = operationId
    flow.stage = resend ? "resending" : "sending"
    flow.sendCount += 1
    let responseSecrets = []
    try {
      const result = await withDeadline(async (signal) => {
        if (!flow.page) await initialize(flow, signal)
        return request(flow, flow.sendUrl, { method: "POST", form: commonForm(flow), signal })
      })
      if (!current(flow, id, operationId)) return null
      const data = responseData(result.payload)
      responseSecrets = Object.values(data).filter((value) => typeof value === "string")
      const failure = loginPayloadError(result.payload, data) || !data.smsToken
      if (failure) {
        const message = data.isCheckCodeShowed
          ? "上游要求风险验证码，当前短信流程未继续"
          : data.titleMsg || result.payload.errorMsg || "发送短信未返回 smsToken"
        throw new QwenError(message, { status: 400, code: CODES.invalidRequest })
      }
      flow.smsToken = String(data.smsToken)
      // 官方 send handler 不写 ctxToken/_csrf；保留页面/组件状态，不响应式“轮换”。
      flow.lastSentAt = Number(now())
      flow.cooldownUntil = flow.lastSentAt + RESEND_MS
      flow.verifyCooldownUntil = 0
      flow.stage = "code"
      flow.operationId = null
      return smsCodePrompt(resend ? "短信已重发；请输入新验证码" : "短信已发送；输入 0 可重发")
    } catch (error) {
      const cooldownSeconds = applyRateLimit(flow, error)
      if (!current(flow, id, operationId)) return null
      const message = safeMessage(error, [...secretsOf(flow), ...responseSecrets, ...(error.secrets || [])])
      if (flow.sendCount >= MAX_SEND) {
        close(flow, `${message}；短信发送次数已达上限`)
        return null
      }
      const cooldownHint = error?.status === 429 ? `；冷却 ${cooldownSeconds} 秒` : ""
      flow.stage = resend ? "code" : "mobile"
      flow.operationId = null
      return resend ? smsCodePrompt(`${message}${cooldownHint}；可输入 0 重试重发`) : mobilePrompt(`${message}${cooldownHint}；请确认手机号后重试`)
    }
  }

  async function verify(flow, code) {
    if (!flow.smsToken) {
      close(flow, "请先发送短信验证码")
      return null
    }
    if (flow.verifyCount >= MAX_VERIFY) {
      close(flow, "短信验证码错误次数已达 5 次上限，请重新登录")
      return null
    }
    const id = flow.id
    const operationId = uuid()
    flow.operationId = operationId
    flow.stage = "verifying"
    flow.verifyCount += 1
    try {
      const result = await withDeadline(async (signal) => {
        const form = commonForm(flow)
        form.delete("codeLength")
        form.set("smsCode", code)
        form.set("smsToken", flow.smsToken)
        form.set("keepLogin", "false")
        const login = await request(flow, flow.loginUrl, { method: "POST", form, signal })
        const data = responseData(login.payload, true)
        if (loginPayloadError(login.payload, data)) {
          const message = data.isCheckCodeShowed || login.payload.isCheckCodeShowed
            ? "上游要求风险验证码，当前短信流程未继续"
            : data.titleMsg || data.errorMsg || login.payload.errorMsg || "上游返回登录错误"
          throw new QwenError(message, { status: 400, code: CODES.invalidRequest })
        }
        if (data.smsRegToken || data.smsRegTips) {
          throw new QwenError("该手机号进入注册确认分支，尚未完成 native 登录", { status: 400, code: CODES.invalidRequest })
        }
        if (!officialLoginSuccess(login.payload, data)) {
          const message = data.titleMsg || data.errorMsg || login.payload.errorMsg || "短信验证码不正确或登录未成功"
          const error = new QwenError(message, { status: 400, code: CODES.invalidRequest })
          error.otpRetry = true
          throw error
        }
        const info = await request(flow, ACCOUNT_INFO_URL, { signal })
        const credential = buildNativeCredential({ jar: flow.jar, info: info.payload, randomBytes })
        return { credential }
      })
      if (!current(flow, id, operationId)) {
        // 迟到结果不得写入新 flow，也不允许交给 authorize。
        return null
      }
      flow.credential = result.credential
      // 显示名必须在 clearSecrets 之前算：本次登录手机号的脱敏形式优先，不再写死“千问用户”。
      flow.note = accountLabelOf({ native: result.credential.native, mobile: flow.mobile })
      flow.stage = "verified"
      flow.operationId = null
      clearSecrets(flow)
      return null
    } catch (error) {
      const cooldownSeconds = applyRateLimit(flow, error)
      if (!current(flow, id, operationId)) return null
      const message = safeMessage(error, [...secretsOf(flow, code), ...(error.secrets || [])])
      const stateExpired = /expired|已过期|已失效|smsToken.*invalid|contextToken.*invalid|consumed|already used|已消费/i.test(message)
      if (stateExpired || flow.verifyCount >= MAX_VERIFY || error?.status === 401 || error?.code === CODES.sessionExpired || /native|Web 会话|注册确认/.test(message)) {
        close(flow, message)
        return null
      }
      flow.stage = "code"
      flow.operationId = null
      return smsCodePrompt(`${message}${error?.status === 429 ? `；冷却 ${cooldownSeconds} 秒` : ""}；请重新输入，或输入 0 重发`)
    }
  }

  async function ask(inputs = {}) {
    if (Object.keys(inputs).length === 0) {
      if (pending) close(pending, "登录流程已由新代次替换")
      pending = {
        id: uuid(),
        stage: "mobile",
        jar: new MemoryCookieJar(),
        createdAt: Number(now()),
        expiresAt: Number(now()) + FLOW_MS,
        sendCount: 0,
        verifyCount: 0,
        lastSentAt: 0,
        cooldownUntil: sharedRateLimit.sendUntil,
        verifyCooldownUntil: sharedRateLimit.verifyUntil,
        operationId: null,
        credential: null,
        failure: "",
      }
      return mobilePrompt()
    }
    const flow = pending
    if (!flow || expired(flow) || flow.stage === "closed") return null
    if (flow.stage === "verified") return null
    if (["sending", "resending", "verifying"].includes(flow.stage)) {
      return flow.stage === "verifying" ? smsCodePrompt("正在验证（最多 15 秒）") : flow.stage === "resending" ? smsCodePrompt("正在重发（最多 15 秒）") : mobilePrompt("正在发送（最多 15 秒）")
    }
    if (flow.stage === "mobile") {
      if (!Object.hasOwn(inputs, "mobile")) return mobilePrompt()
      const mobile = normalizeMobile(inputs.mobile)
      if (!mobile) return mobilePrompt("手机号格式不正确")
      const cooldownUntil = flow.lastSentAt ? Math.max(flow.cooldownUntil || 0, sharedRateLimit.sendUntil, flow.lastSentAt + RESEND_MS) : Math.max(flow.cooldownUntil || 0, sharedRateLimit.sendUntil)
      const remaining = Math.ceil((cooldownUntil - Number(now())) / 1000)
      if (remaining > 0) return mobilePrompt(`发送冷却中，请等待 ${remaining} 秒`)
      flow.mobile = mobile
      return send(flow, false)
    }
    if (flow.stage === "code") {
      if (!Object.hasOwn(inputs, "sms_code")) return smsCodePrompt()
      const code = String(inputs.sms_code ?? "").trim()
      if (code === "0") {
        const cooldownUntil = Math.max(flow.cooldownUntil || 0, flow.verifyCooldownUntil || 0, sharedRateLimit.sendUntil, sharedRateLimit.verifyUntil, flow.lastSentAt + RESEND_MS)
        const remaining = Math.ceil((cooldownUntil - Number(now())) / 1000)
        if (remaining > 0) return smsCodePrompt(`重发冷却中，请等待 ${remaining} 秒`)
        return send(flow, true)
      }
      if (!validSmsCode(code)) return smsCodePrompt("请输入 6 位数字验证码；输入 0 可重发")
      const verifyRemaining = Math.ceil((Math.max(flow.verifyCooldownUntil || 0, sharedRateLimit.verifyUntil) - Number(now())) / 1000)
      if (verifyRemaining > 0) return smsCodePrompt(`验证限流冷却中，请等待 ${verifyRemaining} 秒；暂不能重发`)
      return verify(flow, code)
    }
    return null
  }

  async function authorize(_inputs, { signal } = {}) {
    const flow = pending
    pending = null
    if (signal?.aborted) {
      close(flow, "登录已取消")
      return { type: "failed", error: "登录已取消" }
    }
    if (!flow || flow.stage !== "verified" || Number(now()) >= flow.expiresAt || !flow.credential) {
      const message = flow?.failure || "短信登录未完成或已过期，请重新登录"
      close(flow, message)
      return { type: "failed", error: message }
    }
    try {
      return successAuth(flow.credential, { note: flow.note })
    } catch (error) {
      const secrets = [flow.credential?.cookie, ...Object.values(flow.credential?.native || {}), ...Object.values(flow.credential?.native?.ucParams || {})]
      return { type: "failed", error: safeMessage(error, secrets) }
    } finally {
      clearSecrets(flow)
      flow.credential = null
    }
  }

  return {
    type: "api",
    label: "手机号 + 短信验证码",
    placeholder: "无需客户端；手机号接收 6 位验证码",
    prompts: [mobilePrompt(), smsCodePrompt()],
    ask,
    authorize,
  }
}
