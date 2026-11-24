import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createQwenRuntime, tokensFromRegister } from "../src/runtime.mjs"
import { successAuth } from "../src/cookie.mjs"
import { readCache, writeCache } from "../src/cache.mjs"
import { translateQwenEvents } from "../src/protocol.mjs"
import { openAIEvents, parseSse } from "../src/openai-sse.mjs"
import { redactHeaders } from "../src/security.mjs"
import { LIMITS } from "../src/constants.mjs"
import { SYNTHETIC_COOKIE, syntheticAuth, chatRequest } from "./helpers.mjs"

const SDK_CHAT = "https://chat2.qianwen.com/v1/chat/completions"
const NATIVE = Object.freeze({
  serviceTicket: "synthetic-service-ticket",
  kpsWg: "synthetic-kps-wg",
  uId: "1000000000000000001",
  nickname: "synthetic-nickname",
  utdid: "012345" + "6789ab" + "cdef" + "01234567",
  ucParams: {},
})

function nativeAuth() {
  return successAuth({ cookie: SYNTHETIC_COOKIE, native: NATIVE })
}

function temporaryRoot(t, prefix = "qwenapp-security-review-") {
  const root = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  return root
}

function runtimeFor(t, fetchImpl, { cacheRoot = temporaryRoot(t) } = {}) {
  return createQwenRuntime({ fetchImpl, cacheRoot, sleep: async () => {} })
}

function forward(runtime, auth, { stream = false, body } = {}) {
  return runtime.forward(async () => auth, SDK_CHAT, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || chatRequest({ stream })),
  })
}

function sse(text, status = 200) {
  return new Response(text, { status, headers: { "content-type": "text/event-stream; charset=utf-8" } })
}

async function errorFrom(response) {
  const text = await response.text()
  if (text.trim().startsWith("{")) {
    const body = JSON.parse(text)
    assert.ok(body.error, `HTTP ${response.status} 应含 error`)
    return body.error
  }
  for (const frame of parseSse(text)) {
    if (!frame.data || frame.data === "[DONE]") continue
    const event = JSON.parse(frame.data)
    if (event.error) return event.error
  }
  assert.fail(`应返回错误而非成功：HTTP ${response.status}`)
}

async function assertNativeFailure(response, code) {
  const error = await errorFrom(response)
  assert.equal(error.code, code)
  assert.equal(error.status, code === "upstream_timeout" ? 504 : 502)
  assert.ok(error.message.length > 0)
  return error
}

async function collect(iterator) {
  const values = []
  for await (const value of iterator) values.push(value)
  return values
}

test("F-01a native 非流在 content EOF 截断时返回504，不伪造 stop", async (t) => {
  const runtime = runtimeFor(t, async () => sse('data: {"choices":[{"delta":{"content":"synthetic-partial"}}]}\n\n'))
  const error = await assertNativeFailure(await forward(runtime, nativeAuth()), "upstream_timeout")
  assert.doesNotMatch(error.message, /synthetic-partial/)
})

test("F-01b native 流式截断返回 error frame，不自行补正常 DONE", async (t) => {
  const runtime = runtimeFor(t, async () => sse('data: {"choices":[{"delta":{"content":"synthetic-partial"}}]}\n\n'))
  const response = await forward(runtime, nativeAuth(), { stream: true })
  const text = await response.text()
  const error = await errorFrom(new Response(text))
  assert.equal(error.code, "upstream_timeout")
  assert.doesNotMatch(text, /data:\s*\[DONE\]/)
  assert.doesNotMatch(text, /"finish_reason":"stop"/)
})

test("F-01c native 截断的 tool_call 参数不得折叠成成功调用", async (t) => {
  const runtime = runtimeFor(t, async () => sse('data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_synthetic_partial","type":"function","function":{"name":"echo_marker","arguments":"{\\\"value\\\":"}}]}}]}\n\n'))
  const error = await assertNativeFailure(await forward(runtime, nativeAuth()), "upstream_timeout")
  assert.ok(!JSON.stringify(error).includes("call_synthetic_partial"))
})

test("F-01d native HTTP 200 error event 在流式/非流式都保持错误", async (t) => {
  for (const stream of [false, true]) {
    const runtime = runtimeFor(t, async () => sse('data: {"error":{"message":"synthetic upstream failure"}}\n\ndata:[DONE]\n\n'))
    const error = await assertNativeFailure(await forward(runtime, nativeAuth(), { stream }), "upstream_error")
    assert.match(error.message, /synthetic upstream failure/)
  }
})

test("F-01e openAIEvents 遇到 DONE 立即终止，不接受尾随分片", async () => {
  const body = sse([
    'data: {"choices":[{"delta":{"content":"before"}}]}',
    '',
    'data:[DONE]',
    '',
    'data: {"choices":[{"delta":{"content":"after"}}]}',
    '',
  ].join("\n"))
  const events = await collect(openAIEvents(body))
  assert.equal(events.length, 1)
  assert.equal(events[0].choices[0].delta.content, "before")
  assert.doesNotMatch(JSON.stringify(events), /after/)
})

async function webRuntimeWithTokens(t, fetchImpl, count = 8) {
  const cacheRoot = temporaryRoot(t)
  const runtime = runtimeFor(t, fetchImpl, { cacheRoot })
  const account = runtime.accountFor(syntheticAuth())
  account.cache = {
    deviceId: "synthetic-device",
    tokens: Array.from({ length: count }, (_, index) => ({
      dvidn: "synthetic-device",
      actkn: `synthetic-actkn-${index}`,
      snver: "synthetic-version",
      sacsft: `synthetic-consumed-token-${index}`,
    })),
  }
  assert.equal(writeCache(account.file, account.cache), true)
  account.cache = null
  return runtime
}

test("F-02a 当前已消费 sacsft 在 HTTP 400 中也必须脱敏", async (t) => {
  let consumed = ""
  const runtime = await webRuntimeWithTokens(t, async (_url, init) => {
    consumed = new Headers(init.headers).get("eo-clt-sacsft")
    return new Response(JSON.stringify({ error_msg: `synthetic rejection ${consumed}` }), { status: 400 })
  })
  const response = await forward(runtime, syntheticAuth())
  assert.equal(response.status, 400)
  const text = await response.text()
  assert.ok(consumed)
  assert.ok(!text.includes(consumed))
  assert.match(text, /\[redacted\]/)
})

test("F-02b 最后一次重试已消费的 token 全错误路径仍脱敏", async (t) => {
  const consumed = []
  const runtime = await webRuntimeWithTokens(t, async (_url, init) => {
    consumed.push(new Headers(init.headers).get("eo-clt-sacsft"))
    return new Response(JSON.stringify({ error_msg: `synthetic 500 ${consumed.at(-1)}` }), { status: 500 })
  })
  const response = await forward(runtime, syntheticAuth())
  assert.equal(response.status, 503)
  const text = await response.text()
  assert.equal(consumed.length, 2)
  for (const token of consumed) assert.ok(!text.includes(token))
})

test("F-02c Web SSE HTTP 200 错误事件不泄漏已消费 token", async (t) => {
  let consumed = ""
  const runtime = await webRuntimeWithTokens(t, async (_url, init) => {
    consumed = new Headers(init.headers).get("eo-clt-sacsft")
    return sse(`data: ${JSON.stringify({ error_code: 400, error_msg: `synthetic stream failure ${consumed}`, data: { messages: [] } })}\n\n`)
  })
  const response = await forward(runtime, syntheticAuth(), { stream: true })
  const text = await response.text()
  assert.ok(consumed)
  assert.ok(!text.includes(consumed))
  assert.match(text, /"code":"upstream_error"/)
})

test("F-03a 两个独立 runtime 消费同一磁盘 token 池不得重放", async (t) => {
  const cacheRoot = temporaryRoot(t)
  const noFetch = async () => { throw new Error("token pool must already be sufficient") }
  const a = runtimeFor(t, noFetch, { cacheRoot })
  const b = runtimeFor(t, noFetch, { cacheRoot })
  const accountA = a.accountFor(syntheticAuth())
  const accountB = b.accountFor(syntheticAuth())
  accountA.cache = {
    deviceId: "synthetic-device",
    tokens: Array.from({ length: 6 }, (_, index) => ({ dvidn: "synthetic-device", actkn: "synthetic-actkn", snver: "v", sacsft: `synthetic-shared-${index}` })),
  }
  assert.equal(accountA.file, accountB.file)
  assert.equal(writeCache(accountA.file, accountA.cache), true)
  accountA.cache = null
  accountB.cache = readCache(accountB.file)
  const first = await a.acquireToken(accountA)
  const second = await b.acquireToken(accountB)
  assert.notEqual(first.token.sacsft, second.token.sacsft)
  const persisted = readCache(accountA.file)
  assert.ok(!persisted.tokens.some((token) => token.sacsft === first.token.sacsft || token.sacsft === second.token.sacsft))
})

test("F-03b register 重复 token 与重复二元组去重", () => {
  const row = {
    businessScene: "qwen_chat",
    "eo-clt-dvidn": "synthetic-device",
    "eo-clt-actkn": "synthetic-actkn",
    "eo-clt-snver": "v",
    "eo-clt-bacsft": ["synthetic-duplicate", "synthetic-duplicate", "synthetic-unique"],
  }
  const tokens = tokensFromRegister({ data: { unifyRelate: [row] } })
  assert.deepEqual(tokens.map((token) => token.sacsft), ["synthetic-duplicate", "synthetic-unique"])
  assert.equal(new Set(tokens.map((token) => `${token.dvidn}\0${token.sacsft}`)).size, tokens.length)
})

test("F-04 未知非文本 assistant 消息即使与文本并存也必须 502 且不倾倒原文", async () => {
  for (const messages of [
    [{ role: "assistant", mime_type: "application/json", content: '{"synthetic":true}', status: "complete" }],
    [{ role: "assistant", mime_type: "text/plain", content: "safe", status: "processing" }, { role: "assistant", mime_type: "application/json", content: '{"synthetic":true}', status: "complete" }],
  ]) {
    const frame = { data: JSON.stringify({ error_code: 0, data: { messages } }) }
    await assert.rejects(
      () => collect(translateQwenEvents([frame], { model: "Qwen" })),
      (error) => error.status === 502 && error.code === "upstream_error" && !error.message.includes('{"synthetic":true}'),
    )
  }
})

test("F-06 redactHeaders 覆盖 kp/deviceId/native 与 Web 全套敏感头", () => {
  const input = {
    "eo-clt-acs-kp": "synthetic-kp",
    "x-device-id": "synthetic-device-id",
    "eo-clt-dvidn": "synthetic-dvidn",
    "eo-clt-sacsft": "synthetic-sacsft",
    "x-utdid": "synthetic-utdid",
    "x-u-utdid": "synthetic-utdid",
    "x-u-kps-wg": "synthetic-kps-wg",
    "x-u-sign-wg": "synthetic-sign-wg",
    "x-u-vcode": "synthetic-vcode",
    accept: "application/json",
  }
  const safe = redactHeaders(input)
  for (const name of Object.keys(input).filter((name) => name !== "accept")) assert.equal(safe[name], "[redacted]", name)
  assert.equal(safe.accept, "application/json")
  for (const value of Object.values(input).slice(0, -1)) assert.doesNotMatch(JSON.stringify(safe), new RegExp(value))
})

test("F-07 5xx/429 超大错误体保持 503/429 分类", async (t) => {
  for (const [upstream, expected, code] of [[500, 503, "upstream_unavailable"], [429, 429, "rate_limited"]]) {
    const runtime = runtimeFor(t, async () => new Response("x".repeat(LIMITS.errorBytes + 1), { status: upstream }))
    const response = await forward(runtime, nativeAuth())
    assert.equal(response.status, expected)
    const body = await response.json()
    assert.equal(body.error.code, code)
    assert.equal(body.error.status, expected)
    assert.ok(body.error.message.length < 1000)
  }
})

test("F-08 慢速 drip 错误体受总 deadline 限制，不能靠持续字节续期", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] })
  const encoder = new TextEncoder()
  const runtime = runtimeFor(t, async () => {
    const body = new ReadableStream({
      async start(controller) {
        for (let index = 0; index < 400; index += 1) {
          await new Promise((resolve) => setTimeout(resolve, 100))
          controller.enqueue(encoder.encode("x"))
        }
        controller.close()
      },
    })
    return new Response(body, { status: 400 })
  })
  const pending = forward(runtime, nativeAuth())
  for (let index = 0; index < 450; index += 1) {
    t.mock.timers.tick(100)
    await new Promise((resolve) => setImmediate(resolve))
  }
  const response = await pending
  assert.equal(response.status, 504)
  const body = await response.json()
  assert.equal(body.error.code, "upstream_timeout")
})
