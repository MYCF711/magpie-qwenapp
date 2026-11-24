import { createHmac, randomBytes, randomUUID } from "node:crypto"
import { CHAT_URL, NATIVE_CHAT_URL, QUERY_PARAM_KEYS, SIGN_VERSION } from "./constants.mjs"
import { CODES, QwenError } from "./errors.mjs"
import { assertNotQuotaNotice } from "./quota-notice.mjs"
import { buildChat2ValueToSign, buildSignWg, officialWsgSign } from "./wsg.mjs"

export function hasUnsupportedTools(body) {
  if (body?.tools !== undefined && (!Array.isArray(body.tools) || body.tools.length > 0)) return true
  if (body?.tool_choice !== undefined && body?.tool_choice !== "none") return true
  if (body?.functions !== undefined && (!Array.isArray(body.functions) || body.functions.length > 0)) return true
  const messages = Array.isArray(body?.messages) ? body.messages : []
  return messages.some((message) =>
    message?.role === "tool" || message?.role === "function" ||
    (message?.tool_calls !== undefined && (!Array.isArray(message.tool_calls) || message.tool_calls.length > 0)) ||
    message?.function_call)
}

export function textContent(content) {
  if (typeof content === "string") return content
  if (content === null || content === undefined) return ""
  if (!Array.isArray(content)) {
    throw new QwenError("消息 content 必须是字符串或文本 content parts", { status: 400, code: CODES.invalidRequest })
  }
  let text = ""
  for (const part of content) {
    if (typeof part === "string") { text += part; continue }
    if (part?.type === "text" || part?.type === "input_text") {
      if (typeof part.text === "string") { text += part.text; continue }
    }
    throw new QwenError("当前千问协议只支持文本 content parts；图片、音频或文件不会被静默丢弃", {
      status: 400,
      code: CODES.invalidRequest,
    })
  }
  return text
}

function assertMessageArray(body) {
  if (!Array.isArray(body?.messages) || body.messages.length === 0) {
    throw new QwenError("请求必须包含至少一条 message", { status: 400, code: CODES.invalidRequest })
  }
}

export function normalizeMessages(body) {
  assertMessageArray(body)
  if (hasUnsupportedTools(body)) {
    throw new QwenError("千问 Web /api/v2/chat 不支持 tools；完整 Windows 原生凭据可使用 native 标准 tools", {
      status: 400,
      code: CODES.unsupportedTools,
    })
  }
  return body.messages.map((message) => {
    if (!["system", "developer", "user", "assistant"].includes(message?.role)) {
      throw new QwenError(`不支持的消息 role：${String(message?.role || "missing")}`, {
        status: 400,
        code: CODES.invalidRequest,
      })
    }
    const content = textContent(message.content)
    return {
      role: message.role,
      content,
      mime_type: "text/plain",
      meta_data: {
        ...(message.meta_data && typeof message.meta_data === "object" ? message.meta_data : {}),
        ori_query: content,
      },
      status: "complete",
    }
  })
}

/** 原生 /v1/chat/completions 保留标准 tools/tool_choice/tool 消息，不转换为 Web 字段。 */
export function normalizeNativeMessages(body) {
  assertMessageArray(body)
  if (body?.tools !== undefined && !Array.isArray(body.tools)) {
    throw new QwenError("native tools 必须是数组", { status: 400, code: CODES.invalidRequest })
  }
  if (body?.functions !== undefined || body?.function_call || body.messages.some((message) => message?.role === "function" || message?.function_call)) {
    throw new QwenError("legacy functions/function_call 暂无原生证据，请使用标准 tools/tool_calls", {
      status: 400,
      code: CODES.unsupportedTools,
    })
  }
  return body.messages.map((message) => {
    if (!["system", "developer", "user", "assistant", "tool"].includes(message?.role)) {
      throw new QwenError(`不支持的 native 消息 role：${String(message?.role || "missing")}`, {
        status: 400,
        code: CODES.invalidRequest,
      })
    }
    if (message.tool_calls !== undefined && !Array.isArray(message.tool_calls)) {
      throw new QwenError("native assistant tool_calls 必须是数组", { status: 400, code: CODES.invalidRequest })
    }
    const content = message.role === "assistant" && message.content === null && message.tool_calls?.length
      ? null
      : textContent(message.content)
    return {
      role: message.role,
      content,
      ...(message.tool_calls !== undefined ? { tool_calls: message.tool_calls } : {}),
      ...(message.tool_call_id !== undefined ? { tool_call_id: message.tool_call_id } : {}),
      ...(message.name !== undefined ? { name: message.name } : {}),
    }
  })
}

export function normalizeModelId(value) {
  return String(value || "Qwen").trim().replace(/^qwenapp\//, "") || "Qwen"
}

export function buildChatBody(input, conversation, reqId = randomUUID().replaceAll("-", "")) {
  const source = Array.isArray(input) ? {} : input
  const options = source.qwenapp && typeof source.qwenapp === "object" ? source.qwenapp : {}
  const native = options.native === true || options.route === "native" || options.route === "cowork"
  const messages = Array.isArray(input) ? input : native ? normalizeNativeMessages(source) : normalizeMessages(source)
  const parent = String(conversation?.parent_req_id || "0")
  const hasParent = parent !== "" && parent !== "0"
  const scene = String(options.scene ?? source.scene ?? "chat")
  const from = String(options.from ?? source.from ?? "")
  const subScene = String(options.sub_scene ?? options.subScene ?? source.sub_scene ?? "")
  if (native) {
    const rawQuery = [...messages].reverse().find((message) => message.role === "user")?.content || ""
    const body = {
      model: normalizeModelId(source.model),
      messages,
      stream: true,
      stream_options: { include_usage: true },
      store: false,
      enable_thinking: true,
      session_id: conversation.session_id,
      query_id: randomUUID().replaceAll("-", ""),
      job_id: "",
      task_id: "",
      scene,
      pr: "qwen",
      fr: "win",
      request_id: reqId,
      turn_id: String(conversation.turn || 1),
      ext: {
        initiate_type: "user",
        skill_call_list: "",
        connector_call_list: "",
        tool_call_list: "",
        raw_query: rawQuery,
        attachment: [],
        query_index: Number(conversation.turn || 1),
        ...(options.ext && typeof options.ext === "object" ? options.ext : {}),
      },
    }
    if (Array.isArray(source.tools) && source.tools.length) body.tools = source.tools
    if (source.tool_choice !== undefined) body.tool_choice = source.tool_choice
    if (from) body.from = from
    if (subScene) body.sub_scene = subScene
    const nativeBizData = options.biz_data ?? options.bizData ?? source.biz_data
    if (nativeBizData !== undefined && nativeBizData !== null && nativeBizData !== "") {
      let parsed = nativeBizData
      if (typeof parsed === "string") {
        if (parsed.length > 256 * 1024) {
          throw new QwenError("native biz_data JSON 过大", { status: 400, code: CODES.invalidRequest })
        }
        try { parsed = JSON.parse(parsed) } catch {
          throw new QwenError("native biz_data 必须是合法 JSON 对象", { status: 400, code: CODES.invalidRequest })
        }
      }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new QwenError("native biz_data 必须解析为 JSON 对象", { status: 400, code: CODES.invalidRequest })
      }
      body.biz_data = parsed
    }
    return body
  }
  return {
    req_id: reqId,
    parent_req_id: parent,
    relate_req_id: hasParent ? parent : randomUUID().replaceAll("-", ""),
    messages,
    scene,
    sub_scene: subScene,
    scene_param: hasParent ? "continue_chat" : "first_turn",
    operation_type: "send",
    session_id: conversation.session_id,
    biz_id: "ai_qwen",
    topic_id: conversation.topic_id,
    model: normalizeModelId(source.model),
    from: from || "default",
    protocol_version: "v2",
    messages_merge: false,
    chat_client: "h5",
    deep_search: 0,
    ai_tool_scene: "",
    query_id: reqId,
    job_id: "",
    task_id: "",
    pr: "qwen",
    fr: "h5",
    request_id: reqId,
    turn_id: "0",
    ...((options.biz_data ?? options.bizData ?? source.biz_data) !== undefined ? {
      biz_data: typeof (options.biz_data ?? options.bizData ?? source.biz_data) === "string"
        ? (options.biz_data ?? options.bizData ?? source.biz_data)
        : JSON.stringify(options.biz_data ?? options.bizData ?? source.biz_data),
    } : {}),
  }
}

function hmac(key, text) {
  return createHmac("sha256", key).update(text, "utf8").digest("base64")
}

export function signChat({ deviceId, ticketHash, sacsft, bodyStr, timestamp, nonce }) {
  const bodyKey = `${sacsft}:${timestamp}`
  const bodyHmac = hmac(bodyKey, bodyStr)
  const signText = `${deviceId}${SIGN_VERSION}${ticketHash}${QUERY_PARAM_KEYS}${bodyHmac}`
  return { bodyKey, bodyHmac, signText, sign: hmac(bodyKey, signText) }
}

export function chatUrl({ deviceId, ticketHash, sacsft, bodyStr, timestamp = Date.now(), nonce, ch }) {
  const at = String(timestamp)
  const random = nonce || randomBytes(8).toString("hex").slice(0, 11)
  const signature = signChat({ deviceId, ticketHash, sacsft, bodyStr, timestamp: at, nonce: random })
  const values = {
    biz_id: "ai_qwen",
    chat_client: "h5",
    device: "pc",
    fe_version: "1.0.0",
    fr: "h5",
    la: "zh-CN",
    nonce: random,
    pr: "qwen",
    timestamp: at,
    tz: "Asia/Shanghai",
    ut: deviceId,
    ve: SIGN_VERSION,
    wv: SIGN_VERSION,
  }
  const query = new URLSearchParams()
  for (const key of QUERY_PARAM_KEYS.split(",")) query.append(key, values[key])
  if (ch !== undefined && ch !== null && ch !== "") query.append("ch", String(ch))
  return {
    url: `${CHAT_URL}?${query.toString()}`,
    timestamp: at,
    nonce: random,
    ...signature,
  }
}

export function chatHeaders({ jar, deviceId, ticketHash, reqId, token, timestamp, sign, sessionId }) {
  const csrf = String(jar["XSRF-TOKEN"] || "").trim()
  if (!csrf) {
    throw new QwenError("Cookie 缺少 XSRF-TOKEN；请从 www.qianwen.com 或 chat2-api.qianwen.com 一并导入/粘贴", {
      status: 400,
      code: CODES.invalidRequest,
    })
  }
  return {
    "content-type": "application/json",
    accept: "application/json, text/event-stream, text/plain, */*",
    origin: "https://www.qianwen.com",
    referer: sessionId ? `https://www.qianwen.com/chat/${encodeURIComponent(sessionId)}` : "https://www.qianwen.com/",
    "x-device-id": deviceId,
    "x-chat-id": reqId,
    "x-platform": "pc_tongyi",
    "x-csrf-token": csrf,
    "clt-acs-sign": sign,
    "clt-acs-reqt": String(timestamp),
    "clt-acs-request-params": QUERY_PARAM_KEYS,
    "eo-clt-dvidn": token.dvidn,
    "eo-clt-sacsft": token.sacsft,
    "eo-clt-snver": token.snver,
    "eo-clt-actkn": token.actkn,
    "eo-clt-acs-ve": SIGN_VERSION,
    "clt-acs-caer": "vrad",
    "eo-clt-acs-kp": ticketHash,
  }
}

export function nativeChatUrl({ native, bodyStr, ch }) {
  if (!native) throw new QwenError("原生 cowork 路由需要完整 Windows 原生凭据", { status: 400, code: CODES.invalidRequest })
  const params = {
    biz_id: "ai_qwen",
    pr: "qwen",
    fr: "win",
    device: "pc",
    chat_client: "h5",
    sign_type: "2",
    uc_param_str: "utmtpcsnnnvebipfdnprfrtqla",
    ...(ch !== undefined && ch !== null && String(ch).trim() ? { ch: String(ch).trim() } : {}),
  }
  const reserved = new Set([...Object.keys(params), "sign", "nonce", "timestamp"])
  for (const [key] of Object.entries(native.ucParams || {})) {
    if (key === "sign") throw new QwenError("ucParams 不允许注入 sign", { status: 400, code: CODES.invalidRequest })
  }
  const empiricalOrder = ["bi", "la", "mt", "pf", "tq", "ut", "ve", "pc", "sn", "nn", "dn"]
  for (const key of empiricalOrder) {
    const value = native.ucParams?.[key]
    params[key] = !reserved.has(key) && typeof value === "string" ? value : ""
  }
  params.nonce = randomBytes(8).toString("hex")
  params.timestamp = String(Date.now())
  const valueToSign = buildChat2ValueToSign({ pathname: "/v1/chat/completions", query: params, bodyText: bodyStr })
  const sign = officialWsgSign(valueToSign)
  const wire = Object.entries(params)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&")
  return { url: `${NATIVE_CHAT_URL}?${wire}&sign=${sign}`, sign, valueToSign }
}

export function nativeChatHeaders({ native, vcode = String(Date.now()) }) {
  if (!native) throw new QwenError("纯 Cookie 登录只能使用 Web 兼容路由，不能冒充原生 cowork", {
    status: 400,
    code: CODES.invalidRequest,
  })
  const signed = buildSignWg({ ...native, vcode })
  return {
    "content-type": "application/json",
    accept: "application/json, text/event-stream, text/plain, */*",
    origin: "https://www.qianwen.com",
    referer: "https://www.qianwen.com/",
    "x-utdid": String(native.utdid || ""),
    "x-u-sign-wg": signed.signWg,
    "x-u-kps-wg": native.kpsWg,
    "x-u-vcode": signed.vcode,
  }
}

function messageArrays(payload) {
  const data = payload?.data && typeof payload.data === "object" ? payload.data : payload
  if (Array.isArray(data?.messages)) return { data, messages: data.messages }
  if (Array.isArray(payload?.messages)) return { data, messages: payload.messages }
  if (Array.isArray(data?.response_messages)) return { data, messages: data.response_messages }
  return { data, messages: [] }
}

function realUsage(payload, data) {
  const candidate = data?.extra_info?.chat_odps?.total_usage || payload?.usage || data?.usage
  if (!candidate || typeof candidate !== "object") return null
  const usage = {}
  for (const key of ["prompt_tokens", "completion_tokens", "total_tokens"]) {
    const raw = candidate[key]
    const valid = (typeof raw === "number" && Number.isFinite(raw)) ||
      (typeof raw === "string" && /^\d+(?:\.\d+)?$/.test(raw.trim()))
    if (!valid) continue
    const value = Number(raw)
    if (Number.isFinite(value) && value >= 0) usage[key] = value
  }
  return Object.keys(usage).length ? usage : null
}

function channelValues(message) {
  const out = []
  const explicit = message.reasoning_content ?? message.reasoning ?? message.think_content
  if (typeof explicit === "string") out.push({ channel: "reasoning", value: explicit })
  if (typeof message.content === "string") {
    const thinking = message.content_type === "think" || message.mime_type === "text/thinking" || message.mime_type === "text/think"
    out.push({ channel: thinking ? "reasoning" : "content", value: message.content })
  }
  return out
}

function isTextMessage(message) {
  const mime = String(message?.mime_type || "text/plain")
  return mime.startsWith("text/") || mime === "multi_load/iframe" ||
    typeof message?.reasoning_content === "string" || typeof message?.reasoning === "string" || typeof message?.think_content === "string"
}

function deltaOf(previous, next, mode) {
  if (!previous) return { text: next, mode: "unknown" }
  if (next === previous) return { text: "", mode }
  if (next.startsWith(previous)) return { text: next.slice(previous.length), mode: "snapshot" }
  if (previous.startsWith(next)) return { text: "", mode }
  // 非前缀的新内容按增量处理；已识别快照若被服务端改写，避免重复输出旧前缀。
  return { text: next, mode: mode === "snapshot" ? "snapshot" : "delta" }
}

function chunk(id, created, model, delta, finishReason = null) {
  return {
    id,
    object: "chat.completion.chunk",
    created,
    model,
    choices: [{ index: 0, delta, finish_reason: finishReason }],
  }
}

/** 同一个状态机供真流式与非流折叠使用。 */
export async function* translateQwenEvents(frames, { model, id = `chatcmpl-${randomUUID()}`, created = Math.floor(Date.now() / 1000) } = {}) {
  const states = new Map()
  let usage = null
  let terminal = false
  let finished = false
  let upstreamFinishReason = null
  yield chunk(id, created, model, { role: "assistant" })

  const finish = function* () {
    if (finished) return
    finished = true
    const last = chunk(id, created, model, {}, upstreamFinishReason || "stop")
    if (usage) last.usage = usage
    yield last
  }

  for await (const frame of frames) {
    const text = String(frame?.data ?? "").trim()
    if (!text || text === "true") continue
    if (text === "[DONE]") { terminal = true; yield* finish(); return }
    let payload
    try { payload = JSON.parse(text) } catch {
      throw new QwenError("上游 SSE data 不是合法 JSON", { status: 502, code: CODES.upstreamError })
    }
    if (payload === true) continue
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new QwenError("上游 SSE data 不是 JSON 对象", { status: 502, code: CODES.upstreamError })
    }
    const code = Number(payload.error_code ?? payload.data?.error_code ?? 0)
    const errorMessage = payload.error_msg || payload.data?.error_msg
    if ((Number.isFinite(code) && code !== 0) || errorMessage) {
      throw new QwenError(errorMessage || `千问上游错误码 ${code}`, { status: 502, code: CODES.upstreamError })
    }
    const { data, messages } = messageArrays(payload)
    usage = realUsage(payload, data) || usage
    const choices = Array.isArray(payload.choices) ? payload.choices : Array.isArray(data?.choices) ? data.choices : []
    for (const choice of choices) {
      const source = choice?.delta || choice?.message || {}
      const delta = {}
      if (typeof source.content === "string" && source.content) delta.content = source.content
      if (typeof source.reasoning_content === "string" && source.reasoning_content) delta.reasoning_content = source.reasoning_content
      if (Array.isArray(source.tool_calls) && source.tool_calls.length) {
        throw new QwenError("上游返回了未声明的原生 tool_calls，插件不会静默丢弃", { status: 502, code: CODES.upstreamError })
      }
      if (Object.keys(delta).length) yield chunk(id, created, model, delta)
      if (choice?.finish_reason) {
        upstreamFinishReason = choice.finish_reason
        terminal = true
      }
    }
    for (let index = 0; index < messages.length; index += 1) {
      const message = messages[index]
      if (!message || typeof message !== "object") continue
      if ((Array.isArray(message.tool_calls) && message.tool_calls.length) || message.function_call) {
        throw new QwenError("上游 Web 消息返回了未支持的 tool_calls/function_call，插件不会静默丢弃", {
          status: 502,
          code: CODES.upstreamError,
        })
      }
      if (message.role && message.role !== "assistant") continue
      if (!isTextMessage(message)) {
        const content = message.content
        const meaningful = (typeof content === "string" && content.length > 0) ||
          (content !== undefined && content !== null && typeof content !== "string") ||
          (Array.isArray(message.attachments) && message.attachments.length > 0)
        if (meaningful && message.mime_type !== "signal/post") {
          throw new QwenError("上游 Web 返回了不支持的 assistant 非文本消息，未输出原始内容", {
            status: 502,
            code: CODES.upstreamError,
          })
        }
        continue
      }
      if (message.status === "complete") terminal = true
      const identity = message.id || message.req_id || `${index}:${message.mime_type || "text/plain"}`
      for (const { channel, value } of channelValues(message)) {
        if (!value) continue
        // 千问把额度/会员提示当正文下发：命中即 429，不能进入正文字段。
        assertNotQuotaNotice(value, { model })
        const key = `${identity}:${channel}`
        const previous = states.get(key) || { content: "", last: "", mode: "unknown" }
        if (previous.last === value) continue
        const delta = deltaOf(previous.content, value, previous.mode)
        let content = value
        if (delta.mode === "delta") content = previous.content + value
        else if (delta.mode === "snapshot") content = value
        else if (previous.content) content = previous.content + delta.text
        states.set(key, { content, last: value, mode: delta.mode })
        if (delta.text) yield chunk(id, created, model, channel === "reasoning" ? { reasoning_content: delta.text } : { content: delta.text })
      }
    }
    if (frame.event === "complete" || frame.name === "complete") {
      terminal = true
      yield* finish()
      return
    }
  }
  if (!terminal) {
    throw new QwenError("上游 SSE 在 complete/[DONE] 之前结束，响应可能已截断", {
      status: 504,
      code: CODES.upstreamTimeout,
    })
  }
  yield* finish()
}

export function encodeOpenAIChunk(value) {
  return new TextEncoder().encode(`data: ${JSON.stringify(value)}\n\n`)
}

export function encodeDone() {
  return new TextEncoder().encode("data: [DONE]\n\n")
}
