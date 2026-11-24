import { randomBytes, randomUUID } from "node:crypto"
import {
  LIMITS,
  OFFICIAL_UA,
  ORIGIN,
  REGISTER_URL,
  MODEL_PANEL_URL,
  MODEL_LIST_URL,
} from "./constants.mjs"
import { authCredentialOf, authIdentity, authKeyOf, parseCookie } from "./cookie.mjs"
import { securityCacheFile, readCache, writeCache, withCacheLock } from "./cache.mjs"
import { ConversationStore, externalConversationId } from "./conversation.mjs"
import { createRefreshLock } from "./refresh-lock.mjs"
import { assertSdkChatUrl, assertTrustedUrl } from "./security.mjs"
import {
  CODES,
  QwenError,
  asErrorResponse,
  errorResponse,
  extractErrorMessage,
  readBounded,
  readJson,
  retryAfterMs,
  sanitizeText,
  streamErrorFrame,
} from "./errors.mjs"
import {
  buildChatBody,
  chatHeaders,
  chatUrl,
  nativeChatHeaders,
  nativeChatUrl,
  encodeDone,
  encodeOpenAIChunk,
  normalizeMessages,
  normalizeNativeMessages,
} from "./protocol.mjs"
import { readSseEvents, foldOpenAI } from "./openai-sse.mjs"
import { assertNotQuotaNotice } from "./quota-notice.mjs"
import { withIdleTimeout } from "./stream.mjs"
import { staticModels, panelRows, fallbackRows, buildModels, normalizePanelOrder } from "./models.mjs"

const AUTH_FAILURE = /(?:^|[^a-z])(?:not_logged_in|login\s*(?:failed|required|expired)|session\s*(?:expired|invalid)|invalid\s*(?:ticket|cookie)|ticket\s*(?:expired|invalid)|cookie\s*(?:expired|invalid)|登录已失效|登录过期|未登录|凭据失效|票据失效)(?:$|[^a-z])/i
const MODEL_FAILURE = /model|模型|reasoning|unsupported model|model.*(?:not|unavailable|forbidden|permission)/i
const AUDIT_FAILURE = /audit|content.?filter|内容.{0,8}(?:审核|风控|违规)|not.?safe/i
const sharedRegisterLock = createRefreshLock({ replayMs: 0 })

function field(root, names) {
  const wanted = new Set(names)
  const seen = new Set()
  function visit(value, depth) {
    if (!value || typeof value !== "object" || depth > 8 || seen.has(value)) return undefined
    seen.add(value)
    for (const [key, item] of Object.entries(value)) {
      if (wanted.has(key) && (typeof item === "string" || Array.isArray(item) || typeof item === "object")) return item
    }
    for (const item of Object.values(value)) {
      if (item && typeof item === "object") {
        const found = visit(item, depth + 1)
        if (found !== undefined) return found
      }
    }
    return undefined
  }
  return visit(root, 0)
}

function tokenRows(root, inherited, recursive) {
  const direct = (names) => {
    for (const source of [root, inherited]) {
      if (!source) continue
      for (const name of names) {
        const value = source[name]
        if (typeof value === "string" && value) return value
        if (Array.isArray(value) && value.length) return value
      }
    }
    if (!recursive) return undefined
    return field(root, names) ?? (inherited ? field(inherited, names) : undefined)
  }
  const dvidn = direct(["eo-clt-dvidn", "dvidn"])
  const actkn = direct(["eo-clt-actkn", "actkn"])
  const snver = direct(["eo-clt-snver", "snver"]) || "lv"
  const bacsft = direct(["eo-clt-bacsft", "bacsft", "eo-clt-sacsft"])
  const rows = Array.isArray(bacsft) ? bacsft : bacsft ? [bacsft] : []
  const tokens = []
  for (const row of rows) {
    const sacsft = typeof row === "string" ? row : field(row, ["eo-clt-sacsft", "sacsft", "value", "token", "bacsft"])
    if (typeof sacsft !== "string" || !sacsft) continue
    const item = {
      dvidn: String(field(row, ["eo-clt-dvidn", "dvidn"]) || dvidn || ""),
      actkn: String(field(row, ["eo-clt-actkn", "actkn"]) || actkn || ""),
      snver: String(field(row, ["eo-clt-snver", "snver"]) || snver || "lv"),
      sacsft,
    }
    if (validSecurityToken(item)) tokens.push(item)
  }
  return dedupeSecurityTokens(tokens)
}

export function tokensFromRegister(payload) {
  const dataRoot = payload?.data && typeof payload.data === "object" ? payload.data : null
  const related = dataRoot?.unifyRelate
  if (Array.isArray(related)) {
    const candidates = [
      ...related.filter((item) => item?.businessScene === "qwen_chat"),
      ...related.filter((item) => item?.businessScene === "qwen_web_capsule"),
      ...related.filter((item) => item?.businessScene !== "qwen_chat" && item?.businessScene !== "qwen_web_capsule"),
      dataRoot,
    ]
    for (const candidate of candidates) {
      const tokens = tokenRows(candidate, dataRoot, false)
      if (tokens.length) return tokens
    }
  } else {
    const relate = payload?.root?.unifyRelate ?? payload?.unifyRelate ?? related
    const chat = relate?.qwen_chat
    const capsules = chat?.qwen_web_capsule
    const selected = Array.isArray(capsules) ? capsules[0] : capsules
    const root = selected?.root ?? selected ?? dataRoot
    if (root && typeof root === "object") {
      const tokens = tokenRows(root, dataRoot, true)
      if (tokens.length) return tokens
    }
  }
  throw new QwenError("register 响应没有可消费的 data.unifyRelate token 池", {
    status: 502,
    code: CODES.upstreamError,
  })
}

function abortError(signal) {
  return signal?.reason instanceof Error ? signal.reason : new DOMException("The operation was aborted.", "AbortError")
}

async function awaitWithSignal(promise, signal) {
  if (!signal) return promise
  if (signal.aborted) throw abortError(signal)
  let onAbort
  const aborted = new Promise((_, reject) => {
    onAbort = () => reject(abortError(signal))
    signal.addEventListener("abort", onAbort, { once: true })
  })
  try { return await Promise.race([promise, aborted]) } finally {
    signal.removeEventListener("abort", onAbort)
  }
}

function validSecurityToken(token) {
  return Boolean(token && typeof token.sacsft === "string" && token.sacsft &&
    typeof token.dvidn === "string" && token.dvidn && typeof token.actkn === "string" && token.actkn)
}

function tokenIdentity(token) {
  return JSON.stringify([token.sacsft, token.dvidn, token.actkn, String(token.snver || "lv")])
}

function dedupeSecurityTokens(tokens) {
  const unique = new Map()
  for (const token of Array.isArray(tokens) ? tokens : []) {
    if (validSecurityToken(token)) unique.set(tokenIdentity(token), token)
  }
  return [...unique.values()]
}

async function classifyResponse(response, secrets = [], signal) {
  const status = response.status
  let body = {}
  try {
    const bounded = response.body ? withIdleTimeout(response.body, {
      timeoutMs: LIMITS.jsonMs,
      totalMs: LIMITS.jsonMs,
      signal,
    }) : null
    const text = await readBounded({ body: bounded }, { limit: LIMITS.errorBytes, signal })
    try { body = JSON.parse(text) } catch { body = { _text: text } }
  } catch (error) {
    if (signal?.aborted || error?.name === "AbortError") throw signal ? abortError(signal) : error
    if (error?.status === 504 || error?.code === CODES.upstreamTimeout) {
      return new QwenError("读取千问错误响应体超时", {
        status: 504,
        code: CODES.upstreamTimeout,
        retryable: status >= 500,
        cause: error,
      })
    }
    // 保留原始 HTTP 分类；读取失败/超限本身不覆盖 429、5xx 等上游语义。
    body = { _text: "千问错误响应体读取失败或超过大小上限" }
  }
  const message = sanitizeText(extractErrorMessage(body), secrets)
  const modelError = MODEL_FAILURE.test(message)
  const authError = AUTH_FAILURE.test(message)
  if ((status === 401 || status === 403) && authError) {
    return new QwenError(`千问登录态已失效：${message}`, { status: 401, code: CODES.sessionExpired, signIn: "expired" })
  }
  if (status === 401) {
    return new QwenError(`千问返回 401，但没有明确登录失效证据：${message}`, {
      status: 502,
      code: CODES.upstreamError,
      signIn: "kept",
    })
  }
  if (status === 404 && modelError) {
    return new QwenError(message, { status: 404, code: CODES.modelNotFound, signIn: "kept" })
  }
  if (status === 404) {
    return new QwenError(`千问端点返回 404（未据此停用模型）：${message}`, { status: 502, code: CODES.upstreamError })
  }
  if (status === 403) {
    return new QwenError(`千问拒绝请求（账号登录态保留）：${message}`, {
      status: 403,
      code: CODES.upstreamError,
      signIn: "kept",
    })
  }
  if (status === 400 || status === 422) {
    return new QwenError(message, { status: 400, code: AUDIT_FAILURE.test(message) ? CODES.auditBlocked : CODES.invalidRequest })
  }
  if (status === 409) return new QwenError(message, { status: 409, code: CODES.concurrencyConflict })
  if (status === 429) {
    const error = new QwenError(message, { status: 429, code: CODES.rateLimited, retryable: true })
    error.retryAfter = response.headers?.get?.("retry-after") || ""
    return error
  }
  if (status === 504) return new QwenError(message, { status: 504, code: CODES.upstreamTimeout, retryable: true })
  if (status >= 500) return new QwenError(message, { status: 503, code: CODES.upstreamUnavailable, retryable: true })
  return new QwenError(message, { status: 502, code: CODES.upstreamError })
}

export function createQwenRuntime({
  fetchImpl = globalThis.fetch,
  cacheRoot,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  routing = {},
  cacheLock = {},
} = {}) {
  if (typeof fetchImpl !== "function") throw new TypeError("createQwenRuntime 需要 fetchImpl")
  const accounts = new Map()

  function accountFor(auth) {
    const credential = authCredentialOf(auth)
    const key = credential.cookie
    const identity = authIdentity(auth)
    let account = accounts.get(identity)
    if (!account || account.key !== key) {
      account = {
        identity,
        key,
        native: credential.native || null,
        jar: parseCookie(key),
        file: securityCacheFile(identity, cacheRoot),
        cache: null,
        conversations: new ConversationStore(),
        modelSnapshot: null,
      }
      accounts.set(identity, account)
    } else {
      account.native = credential.native || null
    }
    return account
  }

  function secretsOf(account, attemptSecrets = []) {
    const nativeSecrets = account.native ? Object.values(account.native).flatMap((value) =>
      value && typeof value === "object" ? Object.values(value) : [value]) : []
    const tokenSecrets = (account.cache?.tokens || []).flatMap((token) => [token?.sacsft, token?.dvidn, token?.actkn])
    const consumed = attemptSecrets.flatMap((item) => typeof item === "string"
      ? [item]
      : [item?.sacsft, item?.dvidn, item?.actkn, item?.snver, item?.sign, item?.signWg])
    return [account.key, ...Object.values(account.jar), ...nativeSecrets, ...tokenSecrets, ...consumed].filter(Boolean)
  }

  function loadCache(account) {
    if (!account.cache) account.cache = readCache(account.file) || {}
    return account.cache
  }

  function saveCache(account) {
    const saved = writeCache(account.file, account.cache)
    if (saved) account.cachePersisted = true
    return saved
  }

  function freshCache(account) {
    const disk = readCache(account.file)
    if (disk) return disk
    // 仅用于测试/首次内存种子；一旦落盘，磁盘始终是唯一权威，避免复活旧 token。
    return !account.cachePersisted && account.cache && typeof account.cache === "object" ? account.cache : {}
  }

  async function backoff(ms, signal) {
    if (signal?.aborted) throw abortError(signal)
    let onAbort
    const aborted = new Promise((_, reject) => {
      onAbort = () => reject(abortError(signal))
      signal?.addEventListener("abort", onAbort, { once: true })
    })
    try { await Promise.race([sleep(ms), aborted]) } finally {
      if (onAbort) signal?.removeEventListener("abort", onAbort)
    }
  }

  async function timedFetch(url, init = {}, timeoutMs = LIMITS.connectMs) {
    const caller = init.signal
    if (caller?.aborted) throw abortError(caller)
    const controller = new AbortController()
    const onAbort = () => controller.abort(abortError(caller))
    caller?.addEventListener("abort", onAbort, { once: true })
    const timer = setTimeout(() => {
      controller.abort(new QwenError(`等待千问响应头超过 ${timeoutMs}ms`, {
        status: 504,
        code: CODES.upstreamTimeout,
        retryable: true,
      }))
    }, timeoutMs)
    try {
      return await fetchImpl(url, {
        ...init,
        signal: controller.signal,
        redirect: "error",
      })
    } catch (error) {
      if (caller?.aborted) throw abortError(caller)
      if (controller.signal.aborted && controller.signal.reason instanceof Error) throw controller.signal.reason
      throw new QwenError("千问网络请求失败", {
        status: 503,
        code: CODES.upstreamUnavailable,
        cause: error,
        retryable: true,
      })
    } finally {
      clearTimeout(timer)
      caller?.removeEventListener("abort", onAbort)
    }
  }

  async function requestJson(account, url, init = {}, endpoint) {
    const trusted = assertTrustedUrl(url, endpoint)
    const response = await timedFetch(trusted, {
      ...init,
      headers: {
        "user-agent": OFFICIAL_UA,
        accept: "application/json",
        ...init.headers,
      },
    }, LIMITS.jsonMs)
    if (!response.ok) throw await classifyResponse(response, account ? secretsOf(account) : [], init.signal)
    const bounded = response.body ? withIdleTimeout(response.body, {
      timeoutMs: LIMITS.jsonMs,
      totalMs: LIMITS.jsonMs,
      signal: init.signal,
    }) : null
    return readJson({ body: bounded }, { limit: LIMITS.jsonBytes, signal: init.signal })
  }

  async function refreshSecurity(account, signal) {
    const cache = loadCache(account)
    const fingerprint = typeof cache.fingerprint === "string" && cache.fingerprint ? cache.fingerprint : randomBytes(16).toString("hex")
    const chid = randomBytes(8).toString("hex").slice(0, 11)
    const body = {
      screenResolution: "1920x1080",
      cookieEnabled: true,
      localStorageEnabled: true,
      timezoneOffset: -480,
      fontList: [],
      pluginList: [],
      language: ["zh-CN"],
      unifyRelateGenerate: [],
      fingerprint,
      businessScene: "qwen_web",
      chid,
    }
    const url = new URL(REGISTER_URL)
    url.searchParams.set("chid", chid)
    const payload = await requestJson(account, url, {
      method: "POST",
      signal,
      headers: {
        "content-type": "application/json",
        origin: ORIGIN,
        referer: `${ORIGIN}/`,
        cookie: account.key,
        "bx-umidtoken": String(account.jar["bx-umidtoken"] || ""),
        "eo-clt-sftcnt": String(account.jar["eo-clt-sftcnt"] || "100"),
        "clt-acs-caer": "vrad",
        "eo-clt-acs-bx-intss": "2",
      },
      body: JSON.stringify(body),
    }, "register")
    if (payload?.status !== undefined && Number(payload.status) !== 0) {
      throw new QwenError(`register 业务拒绝：${sanitizeText(payload.msg || payload.code || "未知业务错误", secretsOf(account))}`, {
        status: 502,
        code: CODES.upstreamError,
      })
    }
    const tokens = tokensFromRegister(payload)
    const deviceId = tokens[0].dvidn
    account.cache = { version: 1, deviceId, fingerprint, tokens: dedupeSecurityTokens(tokens), updatedAt: new Date().toISOString() }
    if (!saveCache(account)) {
      throw new QwenError("register 后安全 token 缓存写入失败", { status: 502, code: CODES.internalError })
    }
    return account.cache
  }

  async function consumeCachedToken(account, signal, { respectLowWater = true, refreshError = null } = {}) {
    return withCacheLock(account.file, () => {
      if (signal?.aborted) throw abortError(signal)
      // 每次消费都在进程内+跨进程锁内重读磁盘，绝不信任长期内存副本。
      const cache = freshCache(account)
      account.cache = cache
      cache.tokens = dedupeSecurityTokens(cache.tokens)
      if (respectLowWater && cache.tokens.length <= LIMITS.tokenLowWater) return null
      const token = cache.tokens.shift() || null
      if (!token) return null
      if (refreshError) {
        cache.refreshWarning = { at: new Date().toISOString(), code: refreshError?.code || CODES.upstreamUnavailable }
      } else {
        delete cache.refreshWarning
      }
      if (!saveCache(account)) {
        throw new QwenError("千问安全 token 缓存原子写入失败；本次尚未发送聊天请求", {
          status: 502,
          code: CODES.internalError,
        })
      }
      return { deviceId: token.dvidn || cache.deviceId, token }
    }, { ...cacheLock, signal })
  }

  async function refreshPool(account) {
    return sharedRegisterLock.run(account.file, () => withCacheLock(account.file, async () => {
      account.cache = freshCache(account)
      account.cache.tokens = dedupeSecurityTokens(account.cache.tokens)
      // 等锁期间另一 runtime/进程可能已完成 register，避免重复刷新。
      if (account.cache.tokens.length > LIMITS.tokenLowWater) return account.cache
      return refreshSecurity(account)
    }, cacheLock))
  }

  async function acquireToken(account, signal) {
    if (signal?.aborted) throw abortError(signal)
    const ready = await consumeCachedToken(account, signal)
    if (ready) return ready
    let refreshError = null
    try {
      // 共享刷新不绑定首个调用方 signal；各等待者独立取消，消费前再次检查。
      await awaitWithSignal(refreshPool(account), signal)
    } catch (error) {
      if (signal?.aborted || error?.name === "AbortError") throw error
      refreshError = error
    }
    if (signal?.aborted) throw abortError(signal)
    // 刷新失败但仍有旧 token 时降级消费；空池才向上抛出刷新错误。
    const fallback = await consumeCachedToken(account, signal, { respectLowWater: false, refreshError })
    if (fallback) return fallback
    if (refreshError) throw refreshError
    throw new QwenError("千问安全 token 池为空，且 register 后仍不可用", { status: 503, code: CODES.upstreamUnavailable })
  }

  async function* upstreamChunks(response, signal) {
    const idle = withIdleTimeout(response.body, { timeoutMs: LIMITS.streamIdleMs, signal })
    const frames = readSseEvents(idle, { signal, maxBytes: LIMITS.sseBytes })
    yield* frames
  }

  async function* normalizedNativeEvents(body, { model, signal }) {
    const fallbackId = `chatcmpl-${randomUUID()}`
    const fallbackCreated = Math.floor(Date.now() / 1000)
    let sawDone = false
    let sawFinish = false
    // 千问会把额度/会员提示当成助手正文下发；在首个正文块判定，命中即 429，绝不进入正文字段。
    let contentSeen = false
    for await (const frame of readSseEvents(body, { signal, maxBytes: LIMITS.sseBytes })) {
      const text = String(frame?.data ?? "").trim()
      if (!text || text === "true") continue
      if (text === "[DONE]") {
        sawDone = true
        return
      }
      let event
      try { event = JSON.parse(text) } catch {
        throw new QwenError("native SSE data 不是合法 JSON", { status: 502, code: CODES.upstreamError })
      }
      if (!event || typeof event !== "object" || Array.isArray(event)) {
        throw new QwenError("native SSE data 不是 JSON 对象", { status: 502, code: CODES.upstreamError })
      }
      if (event.error) {
        const message = typeof event.error === "string" ? event.error : event.error?.message || event.message || "上游返回错误事件"
        throw new QwenError(`千问 native 错误事件：${message}`, { status: 502, code: CODES.upstreamError })
      }
      const choices = Array.isArray(event.choices) ? event.choices.map((choice, index) => {
        const finishReason = choice?.finish_reason === "null" ? null : choice?.finish_reason ?? null
        if (finishReason) sawFinish = true
        return {
          index: Number.isInteger(choice?.index) ? choice.index : index,
          delta: { ...(choice?.delta || choice?.message || {}) },
          finish_reason: finishReason,
        }
      }) : []
      // 首个非空正文块：若其实是额度/会员提示，直接抛 429，不把它当回答发出去。
      if (!contentSeen) {
        const piece = choices.map((choice) => (typeof choice.delta?.content === "string" ? choice.delta.content : "")).join("")
        if (piece) {
          assertNotQuotaNotice(piece, { model })
          contentSeen = true
        }
      }
      yield {
        id: typeof event.id === "string" && event.id ? event.id : fallbackId,
        object: "chat.completion.chunk",
        created: Number.isFinite(event.created) ? event.created : fallbackCreated,
        model: typeof event.model === "string" && event.model ? event.model : model,
        choices,
        ...(event.usage && typeof event.usage === "object" ? { usage: event.usage } : {}),
      }
    }
    if (!sawDone && !sawFinish) {
      throw new QwenError("native SSE 在 finish_reason/[DONE] 之前结束，响应可能已截断", {
        status: 504,
        code: CODES.upstreamTimeout,
      })
    }
  }

  async function nativeChatResult(account, response, { model, stream, signal, attemptSecrets = [] }) {
    const local = new AbortController()
    const onAbort = () => local.abort(signal?.reason || new DOMException("The operation was aborted.", "AbortError"))
    signal?.addEventListener("abort", onAbort, { once: true })
    if (signal?.aborted) onAbort()
    const idle = withIdleTimeout(response.body, { timeoutMs: LIMITS.streamIdleMs, signal: local.signal })
    const events = normalizedNativeEvents(idle, { model, signal: local.signal })
    if (!stream) {
      try {
        const completion = await foldOpenAI(events, { model })
        return new Response(JSON.stringify(completion), {
          status: 200,
          headers: { "content-type": "application/json; charset=utf-8" },
        })
      } finally {
        signal?.removeEventListener("abort", onAbort)
      }
    }
    const iterator = events[Symbol.asyncIterator]()
    let settled = false
    const cleanup = () => signal?.removeEventListener("abort", onAbort)
    const output = new ReadableStream({
      async pull(controller) {
        if (settled) return
        try {
          const { done, value } = await iterator.next()
          if (done) {
            settled = true
            controller.enqueue(encodeDone())
            controller.close()
            cleanup()
          } else {
            controller.enqueue(encodeOpenAIChunk(value))
          }
        } catch (error) {
          settled = true
          cleanup()
          if (local.signal.aborted || error?.name === "AbortError") {
            controller.error(error)
            return
          }
          controller.enqueue(encodeOpenAIChunk(streamErrorFrame(error, secretsOf(account, attemptSecrets))))
          controller.close()
        }
      },
      cancel(reason) {
        settled = true
        if (!local.signal.aborted) local.abort(reason || new DOMException("The operation was aborted.", "AbortError"))
        try { void iterator.return(reason).catch(() => {}) } catch {}
        try { void response.body?.cancel(reason).catch(() => {}) } catch {}
        cleanup()
      },
    })
    return new Response(output, {
      status: 200,
      headers: {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-cache, no-transform",
        "x-accel-buffering": "no",
      },
    })
  }

  async function chatResult(account, response, { model, stream, signal, attemptSecrets = [] }) {
    const { translateQwenEvents } = await import("./protocol.mjs")
    const local = new AbortController()
    const onAbort = () => local.abort(signal?.reason || new DOMException("The operation was aborted.", "AbortError"))
    signal?.addEventListener("abort", onAbort, { once: true })
    if (signal?.aborted) onAbort()
    const frames = upstreamChunks(response, local.signal)
    if (!stream) {
      try {
        const chunks = translateQwenEvents(frames, { model })
        const completion = await foldOpenAI(chunks, { model })
        return new Response(JSON.stringify(completion), {
          status: 200,
          headers: { "content-type": "application/json; charset=utf-8" },
        })
      } finally {
        signal?.removeEventListener("abort", onAbort)
      }
    }
    const iterator = translateQwenEvents(frames, { model })[Symbol.asyncIterator]()
    let settled = false
    const cleanup = () => signal?.removeEventListener("abort", onAbort)
    const output = new ReadableStream({
      async pull(controller) {
        if (settled) return
        if (local.signal.aborted) {
          settled = true
          cleanup()
          controller.error(local.signal.reason)
          return
        }
        try {
          const { done, value } = await iterator.next()
          if (done) {
            settled = true
            controller.enqueue(encodeDone())
            controller.close()
            cleanup()
          } else {
            controller.enqueue(encodeOpenAIChunk(value))
          }
        } catch (error) {
          settled = true
          cleanup()
          if (error?.name === "AbortError" || local.signal.aborted) {
            controller.error(error)
            return
          }
          controller.enqueue(encodeOpenAIChunk(streamErrorFrame(error, secretsOf(account, attemptSecrets))))
          controller.close()
        }
      },
      async cancel(reason) {
        settled = true
        if (!local.signal.aborted) local.abort(reason || new DOMException("The operation was aborted.", "AbortError"))
        try { await iterator.return(reason) } catch {}
        try { await response.body?.cancel(reason) } catch {}
        cleanup()
      },
    })
    return new Response(output, {
      status: 200,
      headers: {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-cache, no-transform",
        connection: "keep-alive",
        "x-accel-buffering": "no",
      },
    })
  }

  async function forward(getAuth, input, init = {}) {
    let account
    const attemptSecrets = []
    try {
      assertSdkChatUrl(input)
      const auth = await getAuth()
      account = accountFor(auth)
      const sourceBody = init.body === undefined && input instanceof Request ? await input.text() : init.body
      let body
      try { body = typeof sourceBody === "string" ? JSON.parse(sourceBody) : JSON.parse(new TextDecoder().decode(sourceBody)) } catch {
        throw new QwenError("Chat Completions 请求体不是合法 JSON", { status: 400, code: CODES.invalidRequest })
      }
      const stream = body?.stream === true
      const requestRouting = { route: account.native ? "native" : "web", ...routing, ...(body.qwenapp || {}) }
      const nativeMode = requestRouting.native === true || requestRouting.route === "native" || requestRouting.route === "cowork"
      const messages = nativeMode ? normalizeNativeMessages(body) : normalizeMessages(body)
      const incomingHeaders = new Headers(init.headers || (input instanceof Request ? input.headers : {}) || {})
      const externalId = externalConversationId(body, incomingHeaders)
      const conversation = account.conversations.resolve({ externalId, messages })
      const model = String(body.model || "Qwen").replace(/^qwenapp\//, "")
      let lastError = null
      for (let attempt = 0; attempt <= LIMITS.retries; attempt += 1) {
        const reqId = randomUUID().replaceAll("-", "")
        let upstream
        try {
          const vendorBody = buildChatBody({ ...body, messages, qwenapp: requestRouting }, conversation, reqId)
          const bodyStr = JSON.stringify(vendorBody)
          let trusted
          let headers
          if (nativeMode) {
            const signed = nativeChatUrl({ native: account.native, bodyStr, ch: requestRouting.ch ?? body.ch })
            trusted = assertTrustedUrl(signed.url, "nativeChat")
            headers = nativeChatHeaders({ native: account.native })
            attemptSecrets.push({ sign: signed.sign, signWg: headers["x-u-sign-wg"] })
          } else {
            const { deviceId, token } = await acquireToken(account, init.signal)
            attemptSecrets.push(token)
            const signed = chatUrl({
              deviceId,
              ticketHash: account.jar.tongyi_sso_ticket_hash,
              sacsft: token.sacsft,
              bodyStr,
              ch: requestRouting.ch ?? body.ch,
            })
            attemptSecrets.push(signed.sign)
            trusted = assertTrustedUrl(signed.url, "chat")
            headers = chatHeaders({
              jar: account.jar,
              deviceId,
              ticketHash: account.jar.tongyi_sso_ticket_hash,
              reqId,
              token,
              timestamp: signed.timestamp,
              sign: signed.sign,
              sessionId: conversation.session_id,
            })
          }
          upstream = await timedFetch(trusted, {
            method: "POST",
            headers: {
              "user-agent": OFFICIAL_UA,
              cookie: account.key,
              ...headers,
            },
            body: bodyStr,
            signal: init.signal,
          }, LIMITS.connectMs)
          if (!upstream.ok) {
            lastError = await classifyResponse(upstream, secretsOf(account, attemptSecrets), init.signal)
            const mayRetry = attempt < LIMITS.retries && (upstream.status === 429 || upstream.status >= 500)
            if (mayRetry) {
              await backoff(retryAfterMs(upstream, 300 * (attempt + 1)), init.signal)
              continue
            }
            return asErrorResponse(lastError, secretsOf(account, attemptSecrets))
          }
          account.conversations.commit(conversation.key, reqId)
          return nativeMode
            ? await nativeChatResult(account, upstream, { model, stream, signal: init.signal, attemptSecrets })
            : await chatResult(account, upstream, { model, stream, signal: init.signal, attemptSecrets })
        } catch (error) {
          if (init.signal?.aborted || error?.name === "AbortError") throw error
          lastError = error instanceof QwenError ? error : new QwenError("千问聊天请求内部失败", {
            status: 502,
            code: CODES.internalError,
            cause: error,
          })
          const mayRetry = attempt < LIMITS.retries && lastError.retryable === true
          if (mayRetry) {
            await backoff(300 * (attempt + 1), init.signal)
            continue
          }
          return asErrorResponse(lastError, secretsOf(account, attemptSecrets))
        }
      }
      return asErrorResponse(lastError || new QwenError("千问聊天请求失败", { status: 502, code: CODES.upstreamError }), secretsOf(account, attemptSecrets))
    } catch (error) {
      if (error?.name === "AbortError" || init.signal?.aborted) throw error
      return asErrorResponse(error, account ? secretsOf(account, attemptSecrets) : [])
    }
  }

  function nativeToolModels(models) {
    for (const model of Object.values(models || {})) {
      if (model?.capabilities) model.capabilities.toolcall = model.id === "qwen4-max"
    }
    return models
  }

  async function models(auth) {
    const fallback = staticModels()
    if (!auth?.key) return fallback
    let account
    try { account = accountFor(auth) } catch { return fallback }
    try {
      let payload
      try {
        payload = await requestJson(account, MODEL_PANEL_URL, {
          headers: { cookie: account.key, origin: ORIGIN, referer: `${ORIGIN}/`, "x-xsrf-token": String(account.jar["XSRF-TOKEN"] || "") },
        }, "panel")
        const rows = normalizePanelOrder(panelRows(payload))
        const live = buildModels(rows)
        if (account.native) nativeToolModels(live)
        account.modelSnapshot = live
        return live
      } catch (error) {
        if (error?.signIn === "expired") throw error
        payload = await requestJson(account, MODEL_LIST_URL, {
          headers: {
            cookie: account.key,
            origin: ORIGIN,
            referer: `${ORIGIN}/`,
            "x-platform": "pc_tongyi",
            "x-csrf-token": String(account.jar["XSRF-TOKEN"] || ""),
          },
        }, "models")
        const live = buildModels(fallbackRows(payload))
        if (account.native) nativeToolModels(live)
        account.modelSnapshot = live
        return live
      }
    } catch (error) {
      if (error?.signIn === "expired") {
        const wrapped = new QwenError("千问登录态已失效，请重新导入或粘贴 Cookie", {
          status: 401,
          code: CODES.sessionExpired,
          cause: error,
        })
        wrapped.signIn = "expired"
        throw wrapped
      }
      const stale = account.modelSnapshot || fallback
      if (account.native) nativeToolModels(stale)
      stale[Symbol.for("magpie.fellBack")] = true
      return stale
    }
  }

  async function usage(auth) {
    if (!auth?.key) return { error: "未登录千问", windows: [] }
    try { authKeyOf(auth) } catch (error) { return { error: sanitizeText(error.message), windows: [] } }
    return {
      error: "额度未知：千问没有提供可核实的账户额度读数",
      windows: [],
    }
  }

  return { forward, models, usage, accountFor, acquireToken, refreshSecurity }
}
