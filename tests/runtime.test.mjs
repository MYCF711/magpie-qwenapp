import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createQwenRuntime, tokensFromRegister } from "../src/runtime.mjs"
import { LIMITS, OFFICIAL_UA } from "../src/constants.mjs"
import { parseCredential, successAuth } from "../src/cookie.mjs"
import { deriveRecordSecret, wsgDecrypt, wsgEncrypt } from "../src/wsg.mjs"
import { parseSse } from "../src/openai-sse.mjs"
import { SYNTHETIC_COOKIE, syntheticAuth, registerPayload, chatRequest, sseResponse, deferred } from "./helpers.mjs"

const SDK_CHAT = "https://chat2.qianwen.com/v1/chat/completions"

function cacheDirectory(t) {
  const directory = mkdtempSync(join(tmpdir(), "qwenapp-runtime-test-"))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  return directory
}

function runtimeFor(t, fetchImpl, options = {}) {
  return createQwenRuntime({ fetchImpl, cacheRoot: cacheDirectory(t), sleep: async () => {}, ...options })
}

function forward(runtime, body = chatRequest({ stream: false }), headers = { "content-type": "application/json" }) {
  return runtime.forward(async () => syntheticAuth(), SDK_CHAT, { method: "POST", headers, body: JSON.stringify(body) })
}

function nativeEvent(content, { complete = false, usage } = {}) {
  return `data: ${JSON.stringify({
    error_code: 0,
    error_msg: "",
    data: {
      extra_info: usage ? { chat_odps: { total_usage: usage } } : {},
      messages: [{ id: "synthetic-message", role: "assistant", mime_type: "multi_load/iframe", content, status: complete ? "complete" : "processing" }],
    },
  })}\n\n`
}

test("tokensFromRegister 读取 live data.unifyRelate 数组与 100 token 合成形状", () => {
  const fixture = JSON.parse(readFileSync(new URL("../reference/fixtures/register-native-shape.json", import.meta.url), "utf8"))
  const tokens = tokensFromRegister(fixture)
  assert.equal(tokens.length, 2)
  assert.deepEqual(tokens[0], {
    dvidn: "synthetic-device",
    actkn: "synthetic-access-token",
    snver: "synthetic-version",
    sacsft: "synthetic-security-token-0",
  })
  const hundred = tokensFromRegister(registerPayload(100, "hundred"))
  assert.equal(hundred.length, 100)
  assert.equal(hundred[99].sacsft, "synthetic-sacsft-hundred-99")
  assert.equal(new Set(hundred.map((token) => token.sacsft)).size, 100)
})

test("register single-flight：并发空缓存只请求一次，token 按序消费", async (t) => {
  const gate = deferred()
  let registerCalls = 0
  const runtime = runtimeFor(t, async () => {
    registerCalls += 1
    await gate.promise
    return new Response(JSON.stringify(registerPayload(8, "single")))
  })
  const account = runtime.accountFor(syntheticAuth())
  const pending = Promise.all([runtime.acquireToken(account), runtime.acquireToken(account), runtime.acquireToken(account)])
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(registerCalls, 1)
  gate.resolve()
  const tokens = await pending
  assert.equal(registerCalls, 1)
  assert.deepEqual(tokens.map((item) => item.token.sacsft), [
    "synthetic-sacsft-single-0",
    "synthetic-sacsft-single-1",
    "synthetic-sacsft-single-2",
  ])
})

test("token 池低水位并发只补一次，不重复 register", async (t) => {
  const gate = deferred()
  let registerCalls = 0
  const runtime = runtimeFor(t, async () => {
    registerCalls += 1
    await gate.promise
    return new Response(JSON.stringify(registerPayload(6, "low-water")))
  })
  const account = runtime.accountFor(syntheticAuth())
  account.cache = {
    deviceId: "synthetic-old-device",
    tokens: Array.from({ length: LIMITS.tokenLowWater + 1 }, (_, index) => ({
      dvidn: "synthetic-old-device",
      actkn: "synthetic-old-actkn",
      snver: "synthetic-old-version",
      sacsft: `synthetic-old-token-${index}`,
    })),
  }
  const pending = Promise.all([runtime.acquireToken(account), runtime.acquireToken(account), runtime.acquireToken(account)])
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(registerCalls, 1)
  gate.resolve()
  const tokens = await pending
  assert.equal(tokens[0].token.sacsft, "synthetic-old-token-0")
  assert.equal(registerCalls, 1)
  assert.equal(new Set(tokens.map((item) => item.token.sacsft)).size, 3)
})

test("账号缓存按 Cookie 指纹隔离，缓存不含 Cookie/native 秘密或 magpie 全局配置", async (t) => {
  const native = {
    serviceTicket: "synthetic-service-ticket",
    kpsWg: "synthetic-kps-wg",
    uId: "1000000000000000001",
    nickname: "synthetic-nickname",
  }
  const first = successAuth({ cookie: SYNTHETIC_COOKIE, native })
  const secondCookie = SYNTHETIC_COOKIE.replace("synthetic-ticket;", "synthetic-ticket-second;")
  const second = successAuth({ cookie: secondCookie, native: { ...native, uId: "1000000000000000002" } })
  let calls = 0
  const runtime = runtimeFor(t, async () => new Response(JSON.stringify(registerPayload(4, `isolated-${calls++}`))))
  const accountA = runtime.accountFor(first)
  const accountB = runtime.accountFor(second)
  assert.notEqual(accountA.identity, accountB.identity)
  assert.notEqual(accountA.file, accountB.file)
  assert.notEqual(accountA.conversations, accountB.conversations)
  await Promise.all([runtime.acquireToken(accountA), runtime.acquireToken(accountB)])
  const directory = join(accountA.file, "..")
  const files = readdirSync(directory)
  assert.equal(files.length, 2)
  assert.ok(files.every((name) => name.startsWith("qwenapp-security__") && name.endsWith(".json")))
  assert.ok(!files.some((name) => /settings|cordis|magpie\.json/i.test(name)))
  for (const file of files) {
    const text = readFileSync(join(directory, file), "utf8")
    assert.doesNotMatch(text, /tongyi_sso|synthetic-ticket|synthetic-service-ticket|synthetic-kps-wg|synthetic-xsrf/)
    assert.equal(JSON.parse(text).cookie, undefined)
    assert.equal(JSON.parse(text).native, undefined)
  }
})

test("POST 重试使用新 req_id/nonce/sign/token，敏感入口头丢弃且 redirect:error", async (t) => {
  const chatCalls = []
  let registerCalls = 0
  const runtime = runtimeFor(t, async (url, init) => {
    assert.equal(init.redirect, "error")
    if (String(url).includes("/security/external/access/register")) {
      registerCalls += 1
      return new Response(JSON.stringify(registerPayload(10, "retry")))
    }
    const headers = new Headers(init.headers)
    chatCalls.push({ url: new URL(url), headers, body: JSON.parse(init.body) })
    if (chatCalls.length === 1) return new Response(JSON.stringify({ error_msg: "synthetic temporary" }), { status: 500 })
    return sseResponse(`${nativeEvent("成功", { complete: true, usage: { prompt_tokens: 2, completion_tokens: 1, total_tokens: 3 } })}`)
  })
  const response = await forward(runtime, chatRequest({ stream: false }), {
    "content-type": "application/json",
    authorization: "Bearer synthetic-caller-authorization",
    cookie: "tongyi_sso_ticket=synthetic-caller-cookie",
    "user-agent": "caller-agent",
    "x-csrf-token": "synthetic-caller-csrf",
    "x-custom-secret": "synthetic-custom",
  })
  assert.equal(response.status, 200)
  assert.equal(registerCalls, 1)
  assert.equal(chatCalls.length, 2)
  const [first, second] = chatCalls
  assert.notEqual(first.body.req_id, second.body.req_id)
  assert.notEqual(first.url.searchParams.get("nonce"), second.url.searchParams.get("nonce"))
  assert.notEqual(first.headers.get("clt-acs-sign"), second.headers.get("clt-acs-sign"))
  assert.notEqual(first.headers.get("eo-clt-sacsft"), second.headers.get("eo-clt-sacsft"))
  for (const call of chatCalls) {
    assert.equal(call.headers.get("user-agent"), OFFICIAL_UA)
    assert.equal(call.headers.get("authorization"), null)
    assert.equal(call.headers.get("x-custom-secret"), null)
    assert.equal(call.headers.get("cookie"), parseCredential(syntheticAuth().key).cookie)
    assert.notEqual(call.headers.get("x-csrf-token"), "synthetic-caller-csrf")
  }
  const completion = await response.json()
  assert.equal(completion.choices[0].message.content, "成功")
  assert.deepEqual(completion.usage, { prompt_tokens: 2, completion_tokens: 1, total_tokens: 3 })
})

test("runtime 真流式逐块驱动，不在完整收集后一次输出", async (t) => {
  let upstream
  let pulls = 0
  const runtime = runtimeFor(t, async (url) => {
    if (String(url).includes("/security/external/access/register")) return new Response(JSON.stringify(registerPayload(5, "stream")))
    return new Response(new ReadableStream({
      start(controller) { upstream = controller },
      pull() { pulls += 1 },
    }), { headers: { "content-type": "text/event-stream" } })
  })
  const response = await forward(runtime, chatRequest({ stream: true }))
  assert.equal(response.status, 200)
  assert.match(response.headers.get("content-type"), /text\/event-stream/)
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  const first = await reader.read()
  assert.equal(first.done, false)
  assert.match(decoder.decode(first.value), /"role":"assistant"/)

  const secondPending = reader.read()
  await new Promise((resolve) => setImmediate(resolve))
  assert.ok(upstream, "上游尚未创建")
  upstream.enqueue(new TextEncoder().encode(nativeEvent("逐")))
  const second = await secondPending
  assert.match(decoder.decode(second.value), /"content":"逐"/)

  upstream.enqueue(new TextEncoder().encode(`event: complete\n${nativeEvent("逐块", { complete: true })}`))
  upstream.close()
  let rest = ""
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    rest += decoder.decode(value, { stream: true })
  }
  assert.match(rest, /"content":"块"/)
  assert.match(rest, /data: \[DONE\]/)
  assert.ok(pulls > 0)
})

test("取消客户端流会取消上游，不继续产出", async (t) => {
  let upstream
  let cancelled = 0
  const runtime = runtimeFor(t, async (url) => {
    if (String(url).includes("/security/external/access/register")) return new Response(JSON.stringify(registerPayload(5, "cancel")))
    return new Response(new ReadableStream({
      start(controller) { upstream = controller },
      cancel() { cancelled += 1 },
    }))
  })
  const response = await forward(runtime, chatRequest({ stream: true }))
  const reader = response.body.getReader()
  await reader.read()
  await new Promise((resolve) => setImmediate(resolve))
  assert.ok(upstream)
  await reader.cancel("synthetic client cancel")
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(cancelled, 1)
})

const NATIVE_UTDID = "012345" + "6789ab" + "cdef" + "01234567"
const NATIVE_UID = "1000000000000000001"
const NATIVE_RECORD_SECRET = deriveRecordSecret()
const NATIVE_CREDENTIAL = Object.freeze({
  serviceTicket: "synthetic-native-service-ticket",
  kpsWg: "synthetic-native-kps-wg",
  uId: NATIVE_UID,
  nickname: "synthetic-native-nickname",
  uidWsg: wsgEncrypt(NATIVE_UID, NATIVE_RECORD_SECRET),
  utdid: NATIVE_UTDID,
  ucParams: { ut: wsgEncrypt(NATIVE_UTDID, NATIVE_RECORD_SECRET) },
})

function nativeAuth() {
  return successAuth({ cookie: SYNTHETIC_COOKIE, native: NATIVE_CREDENTIAL })
}

function outputEvents(text) {
  const frames = parseSse(text)
  assert.equal(frames.at(-1).data, "[DONE]")
  return frames.slice(0, -1).map((frame) => JSON.parse(frame.data))
}

test("完整 JSON credential 自动走 native cowork，不调用 register 且不泄漏 native 字段", async (t) => {
  let chatCalls = 0
  const runtime = runtimeFor(t, async (url, init) => {
    assert.ok(!String(url).includes("/security/external/access/register"), "native 不应调用 Web register")
    chatCalls += 1
    const headers = new Headers(init.headers)
    const target = new URL(url)
    assert.equal(target.origin, "https://chat2.qianwen.com")
    assert.equal(target.pathname, "/v1/chat/completions")
    assert.equal(target.searchParams.get("nonce").length, 16)
    assert.match(target.searchParams.get("timestamp"), /^\d{13}$/)
    assert.match(target.searchParams.get("sign"), /^3bf7[a-f0-9]{40}$/)
    assert.equal(wsgDecrypt(target.searchParams.get("ut")).toString("utf8"), NATIVE_UTDID)
    assert.equal(headers.get("x-u-kps-wg"), NATIVE_CREDENTIAL.kpsWg)
    assert.equal(headers.get("x-utdid"), NATIVE_UTDID)
    assert.match(headers.get("x-u-vcode"), /^\d+$/)
    assert.ok(headers.get("x-u-sign-wg"))
    assert.equal(headers.get("cookie"), SYNTHETIC_COOKIE)
    assert.equal(headers.get("eo-clt-actkn"), null)
    const body = JSON.parse(init.body)
    assert.equal(body.fr, "win")
    assert.equal(body.turn_id, "1")
    assert.equal(body.ext.query_index, 1)
    assert.equal(body.ext.raw_query, "synthetic question")
    assert.doesNotMatch(JSON.stringify(body.messages), /synthetic-native-service-ticket|synthetic-native-kps-wg/)
    return sseResponse(readFileSync(new URL("../reference/fixtures/native-openai-content.sse", import.meta.url), "utf8"))
  })
  const response = await runtime.forward(async () => nativeAuth(), SDK_CHAT, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(chatRequest({ stream: false })),
  })
  assert.equal(response.status, 200)
  assert.equal(chatCalls, 1)
  const completion = await response.json()
  assert.equal(completion.choices[0].message.content, "SYNTHETIC_OK")
  assert.equal(completion.choices[0].message.reasoning_content, "synthetic reasoning")
})

test("native SSE 转为 chat.completion.chunk，中间 'null' 归一为 null，content/reasoning/usage 不丢", async (t) => {
  const upstream = readFileSync(new URL("../reference/fixtures/native-openai-content.sse", import.meta.url), "utf8")
  const runtime = runtimeFor(t, async () => sseResponse(upstream))
  const response = await runtime.forward(async () => nativeAuth(), SDK_CHAT, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(chatRequest({ stream: true })),
  })
  assert.equal(response.status, 200)
  const events = outputEvents(await response.text())
  assert.ok(events.length >= 4)
  assert.ok(events.every((event) => event.object === "chat.completion.chunk"))
  const intermediate = events.filter((event) => event.choices[0].finish_reason !== "stop")
  assert.ok(intermediate.every((event) => event.choices[0].finish_reason === null))
  assert.ok(events.some((event) => event.choices[0].delta.content === "SYNTHETIC_" && event.choices[0].delta.reasoning_content === "synthetic reasoning"))
  assert.equal(events.map((event) => event.choices[0].delta.content || "").join(""), "SYNTHETIC_OK")
  assert.equal(events.map((event) => event.choices[0].delta.reasoning_content || "").join(""), "synthetic reasoning")
  assert.equal(events.at(-1).choices[0].finish_reason, "stop")
  assert.deepEqual(events.at(-1).usage, { prompt_tokens: 8, completion_tokens: 5, total_tokens: 13 })
})

test("native tools 流式分片原样透传且 envelope/finish_reason 归一", async (t) => {
  const upstream = readFileSync(new URL("../reference/fixtures/native-openai-tool-call.sse", import.meta.url), "utf8")
  const expected = outputEvents(upstream).flatMap((event) => event.choices[0].delta.tool_calls || [])
  const runtime = runtimeFor(t, async () => sseResponse(upstream))
  const response = await runtime.forward(async () => nativeAuth(), SDK_CHAT, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model: "qwen4-max",
      messages: [{ role: "user", content: "synthetic tool request" }],
      tools: [{ type: "function", function: { name: "echo_marker", parameters: { type: "object" } } }],
      tool_choice: "auto",
      stream: true,
    }),
  })
  assert.equal(response.status, 200)
  const events = outputEvents(await response.text())
  assert.ok(events.every((event) => event.object === "chat.completion.chunk"))
  assert.ok(events.filter((event) => event.choices[0].finish_reason !== "tool_calls").every((event) => event.choices[0].finish_reason === null))
  const actual = events.flatMap((event) => event.choices[0].delta.tool_calls || [])
  assert.deepEqual(actual, expected)
  assert.equal(actual[0].id, "call_synthetic_echo_1")
  assert.equal(events.at(-1).choices[0].finish_reason, "tool_calls")
  assert.deepEqual(events.at(-1).usage, { prompt_tokens: 20, completion_tokens: 10, total_tokens: 30 })
})

test("native tools 非流运行时折叠保留 tool_call_id 与 arguments", async (t) => {
  const upstream = readFileSync(new URL("../reference/fixtures/native-openai-tool-call.sse", import.meta.url), "utf8")
  const runtime = runtimeFor(t, async (url, init) => {
    assert.equal(new URL(url).pathname, "/v1/chat/completions")
    const body = JSON.parse(init.body)
    assert.equal(body.tools[0].function.name, "echo_marker")
    assert.equal(body.tool_choice, "auto")
    return sseResponse(upstream)
  })
  const response = await runtime.forward(async () => nativeAuth(), SDK_CHAT, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model: "qwen4-max",
      messages: [{ role: "user", content: "synthetic tool request" }],
      tools: [{ type: "function", function: { name: "echo_marker", parameters: { type: "object" } } }],
      tool_choice: "auto",
      stream: false,
    }),
  })
  assert.equal(response.status, 200)
  const completion = await response.json()
  assert.equal(completion.choices[0].finish_reason, "tool_calls")
  assert.equal(completion.choices[0].message.tool_calls[0].id, "call_synthetic_echo_1")
  assert.equal(completion.choices[0].message.tool_calls[0].function.arguments, '{"value": "SYNTHETIC_TOOL_OK"}')
})

test("native 上游错误正文中的 serviceTicket/kpsWg/token 全部脱敏", async (t) => {
  const runtime = runtimeFor(t, async () => new Response(JSON.stringify({
    error_msg: `synthetic failure ${NATIVE_CREDENTIAL.serviceTicket} ${NATIVE_CREDENTIAL.kpsWg} synthetic-ticket`,
  }), { status: 400 }))
  const response = await runtime.forward(async () => nativeAuth(), SDK_CHAT, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(chatRequest({ stream: false })),
  })
  assert.equal(response.status, 400)
  const text = await response.text()
  assert.ok(!text.includes(NATIVE_CREDENTIAL.serviceTicket))
  assert.ok(!text.includes(NATIVE_CREDENTIAL.kpsWg))
  assert.ok(!text.includes("synthetic-ticket"))
  assert.match(text, /\[redacted\]/)
})
