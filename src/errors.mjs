const DEFAULT_MESSAGE = "上游请求失败，但未返回可显示的原因"

export const CODES = Object.freeze({
  signInRequired: "sign_in_required",
  sessionExpired: "session_expired",
  auditBlocked: "audit_blocked",
  invalidRequest: "invalid_request",
  unsupportedTools: "unsupported_tools",
  modelNotFound: "model_not_found",
  concurrencyConflict: "concurrency_conflict",
  rateLimited: "rate_limited",
  upstreamUnavailable: "upstream_unavailable",
  upstreamTimeout: "upstream_timeout",
  upstreamError: "upstream_error",
  internalError: "internal_error",
  notImplemented: "not_implemented",
})

export class QwenError extends Error {
  constructor(message, { status = 502, code = CODES.upstreamError, signIn, cause, retryable = false, retryAfter } = {}) {
    super(String(message || DEFAULT_MESSAGE), cause ? { cause } : undefined)
    this.name = "QwenError"
    this.status = status
    this.code = code
    if (signIn) this.signIn = signIn
    this.retryable = retryable
    // 秒数；asErrorResponse 会写成 Retry-After 头，让调用方知道等到什么时候。
    const seconds = Number(retryAfter)
    if (Number.isFinite(seconds) && seconds > 0) this.retryAfter = Math.round(seconds)
  }
}

export function sanitizeText(value, secrets = []) {
  let text = String(value ?? "")
  for (const secret of secrets) {
    const raw = String(secret || "")
    if (raw.length >= 4) text = text.replaceAll(raw, "[redacted]")
  }
  return text
    .replace(/((?:tongyi_sso_ticket(?:_hash)?|xsrf-token|bx-umidtoken|eo-clt-(?:sacsft|actkn|dvidn|snver)|clt-acs-sign|x-u-sign-wg|x-u-kps-wg|serviceticket|kpswg|signwg)["']?\s*[:=]\s*["']?)[^;\s,"'}]+/gi, "$1[redacted]")
    .replace(/((?:cookie|authorization|proxy-authorization)["']?\s*:\s*["']?)[^"'\r\n]+/gi, "$1[redacted]")
    .replace(/([?&](?:sign|ticket|actkn|sacsft|token)=)[^&\s]+/gi, "$1[redacted]")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 500) || DEFAULT_MESSAGE
}

export function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  })
}

export function errorResponse(message, status, code, extra = {}) {
  const { signIn, secrets = [], ...headers } = extra
  const safe = sanitizeText(message, secrets)
  return jsonResponse(
    { error: { message: safe, type: code, code, status } },
    status,
    signIn ? { "x-magpie-sign-in": signIn, ...headers } : headers,
  )
}

export function asErrorResponse(error, secrets = []) {
  if (error instanceof Response) return error
  const status = Number(error?.status) || 502
  const code = error?.code || (status === 504 ? CODES.upstreamTimeout : CODES.upstreamError)
  return errorResponse(error?.message || DEFAULT_MESSAGE, status, code, {
    signIn: error?.signIn,
    secrets,
    ...(error?.retryAfter ? { "retry-after": String(error.retryAfter) } : {}),
  })
}

export function streamErrorFrame(error, secrets = []) {
  const status = Number(error?.status) || 502
  const code = error?.code || (status === 504 ? CODES.upstreamTimeout : CODES.upstreamError)
  return {
    error: {
      message: sanitizeText(error?.message || DEFAULT_MESSAGE, secrets),
      type: "upstream_error",
      code,
      status,
    },
  }
}

export async function readBounded(response, { limit, signal } = {}) {
  const max = Number.isFinite(limit) && limit > 0 ? limit : 1024 * 1024
  if (!response?.body) return ""
  const reader = response.body.getReader()
  const decoder = new TextDecoder("utf-8", { fatal: false })
  let bytes = 0
  let text = ""
  const onAbort = () => { void reader.cancel(signal?.reason).catch(() => {}) }
  signal?.addEventListener("abort", onAbort, { once: true })
  try {
    for (;;) {
      if (signal?.aborted) throw signal.reason || new DOMException("The operation was aborted.", "AbortError")
      const { done, value } = await reader.read()
      if (done) break
      bytes += value?.byteLength || 0
      if (bytes > max) {
        try { void reader.cancel("response body limit exceeded").catch(() => {}) } catch {}
        throw new QwenError(`上游响应体超过 ${max} 字节上限`, { status: 502, code: CODES.upstreamError })
      }
      text += decoder.decode(value, { stream: true })
    }
    text += decoder.decode()
    return text
  } finally {
    signal?.removeEventListener("abort", onAbort)
    try { reader.releaseLock() } catch {}
  }
}

export async function readJson(response, options = {}) {
  const text = await readBounded(response, options)
  if (!text.trim()) return {}
  try { return JSON.parse(text) } catch (cause) {
    throw new QwenError("上游返回了无法解析的 JSON", { status: 502, code: CODES.upstreamError, cause })
  }
}

export function extractErrorMessage(body) {
  if (typeof body === "string") return body
  const nested = body?.error && typeof body.error === "object" ? body.error : null
  return nested?.message || nested?.msg || body?.error_msg || body?.errmsg || body?.message || body?.msg || body?.error_description || body?._text || DEFAULT_MESSAGE
}

export function retryAfterMs(response, fallback = 500) {
  const raw = response?.headers?.get?.("retry-after")
  if (!raw) return fallback
  const seconds = /^\d+$/.test(raw.trim()) ? Number(raw) : (Date.parse(raw) - Date.now()) / 1000
  return Number.isFinite(seconds) ? Math.max(0, Math.min(5000, seconds * 1000)) : fallback
}
