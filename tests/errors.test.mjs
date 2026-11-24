import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createQwenRuntime } from "../src/runtime.mjs"
import { LIMITS } from "../src/constants.mjs"
import { syntheticAuth, registerPayload, chatRequest } from "./helpers.mjs"

const SDK_CHAT = "https://chat2.qianwen.com/v1/chat/completions"

function runtimeFor(t, fetchImpl) {
  const cacheRoot = mkdtempSync(join(tmpdir(), "qwenapp-errors-test-"))
  t.after(() => rmSync(cacheRoot, { recursive: true, force: true }))
  return createQwenRuntime({ fetchImpl, cacheRoot, sleep: async () => {} })
}

function runtimeWithQueue(t, queue) {
  let chatCalls = 0
  const runtime = runtimeFor(t, async (url) => {
    if (String(url).includes("/security/external/access/register")) return new Response(JSON.stringify(registerPayload(12, "errors")))
    const item = queue[Math.min(chatCalls, queue.length - 1)]
    chatCalls += 1
    if (item instanceof Error) throw item
    if (typeof item === "function") return item()
    const { status, body, headers } = item
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } })
  })
  return { runtime, calls: () => chatCalls }
}

function forward(runtime) {
  return runtime.forward(async () => syntheticAuth(), SDK_CHAT, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(chatRequest({ stream: false })),
  })
}

async function expectError(response, { status, code, signIn, message }) {
  assert.equal(response.status, status)
  const body = await response.json()
  assert.equal(body.error.status, status)
  assert.equal(body.error.code, code)
  assert.equal(body.error.type, code)
  assert.ok(typeof body.error.message === "string" && body.error.message.length > 0)
  if (message) assert.match(body.error.message, message)
  if (signIn !== undefined) assert.equal(response.headers.get("x-magpie-sign-in"), signIn)
  return body
}

test("401 只有明确登录失效才失效账号，正文中的 Cookie 被脱敏", async (t) => {
  const { runtime, calls } = runtimeWithQueue(t, [{ status: 401, body: { error_msg: "unauthorized: session expired; ticket=synthetic-ticket" } }])
  const body = await expectError(await forward(runtime), {
    status: 401,
    code: "session_expired",
    signIn: "expired",
    message: /登录态已失效/,
  })
  assert.equal(calls(), 1)
  assert.ok(!JSON.stringify(body).includes("synthetic-ticket"))
})

test("非登录证据 401 不误伤账号，返回 502 + kept", async (t) => {
  const { runtime } = runtimeWithQueue(t, [{ status: 401, body: { error_msg: "synthetic signature mismatch" } }])
  await expectError(await forward(runtime), { status: 502, code: "upstream_error", signIn: "kept", message: /没有明确登录失效证据/ })
})

test("403/404 模型错误保留账号，普通 404 不伪装 model_not_found", async (t) => {
  const forbidden = runtimeWithQueue(t, [{ status: 403, body: { error_msg: "model unavailable for synthetic model" } }])
  const forbiddenBody = await expectError(await forward(forbidden.runtime), { status: 403, code: "upstream_error", signIn: "kept", message: /model unavailable/ })
  assert.notEqual(forbiddenBody.error.code, "session_expired")

  const missing = runtimeWithQueue(t, [{ status: 404, body: { error_msg: "model unavailable for synthetic model" } }])
  const missingBody = await expectError(await forward(missing.runtime), { status: 404, code: "model_not_found", signIn: "kept", message: /model unavailable/ })
  assert.notEqual(missingBody.error.code, "session_expired")

  const { runtime } = runtimeWithQueue(t, [{ status: 404, body: { error_msg: "synthetic endpoint missing" } }])
  await expectError(await forward(runtime), { status: 502, code: "upstream_error", message: /未据此停用模型/ })
})

test("429 限流有界重试，最终 status/code/message 完整", async (t) => {
  const { runtime, calls } = runtimeWithQueue(t, [
    { status: 429, body: { error_msg: "synthetic rate limit first" }, headers: { "retry-after": "0" } },
    { status: 429, body: { error_msg: "synthetic rate limit final" }, headers: { "retry-after": "0" } },
  ])
  await expectError(await forward(runtime), { status: 429, code: "rate_limited", message: /rate limit final/ })
  assert.equal(calls(), 2)
})

test("5xx 与网络失败映射 503 upstream_unavailable，并有界重试", async (t) => {
  const http = runtimeWithQueue(t, [
    { status: 500, body: { error_msg: "synthetic internal" } },
    { status: 502, body: { error_msg: "synthetic bad gateway" } },
  ])
  await expectError(await forward(http.runtime), { status: 503, code: "upstream_unavailable", message: /bad gateway/ })
  assert.equal(http.calls(), 2)

  const network = runtimeWithQueue(t, [new TypeError("synthetic socket closed"), new TypeError("synthetic socket closed")])
  await expectError(await forward(network.runtime), { status: 503, code: "upstream_unavailable", message: /网络请求失败/ })
  assert.equal(network.calls(), 2)
})

test("响应头超时映射 504 upstream_timeout，不重映射为 404/502", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] })
  let chatCalls = 0
  const runtime = runtimeFor(t, async (url, init) => {
    if (String(url).includes("/security/external/access/register")) return new Response(JSON.stringify(registerPayload(8, "timeout")))
    chatCalls += 1
    return new Promise((_, reject) => {
      init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true })
    })
  })
  const pending = forward(runtime)
  for (let attempt = 0; attempt < 3; attempt += 1) {
    t.mock.timers.tick(LIMITS.connectMs)
    await new Promise((resolve) => setImmediate(resolve))
  }
  await expectError(await pending, { status: 504, code: "upstream_timeout", message: /超过/ })
  assert.equal(chatCalls, 2)
})

test("EX013 参数与 EX015 签名错误绝不误报模型不存在或账号失效", async (t) => {
  const parameter = runtimeWithQueue(t, [{ status: 400, body: { error_code: "EX013", error_msg: "EX013 invalid timestamp parameter" } }])
  const parameterBody = await expectError(await forward(parameter.runtime), { status: 400, code: "invalid_request", message: /EX013/ })
  assert.notEqual(parameterBody.error.code, "model_not_found")

  const signature = runtimeWithQueue(t, [{ status: 403, body: { error_code: "EX015", error_msg: "EX015 signature verification failed" } }])
  const signatureBody = await expectError(await forward(signature.runtime), { status: 403, code: "upstream_error", signIn: "kept", message: /EX015/ })
  assert.notEqual(signatureBody.error.code, "model_not_found")
  assert.notEqual(signatureBody.error.code, "session_expired")
})

test("客户端 tools 在进入网络前明确 400 unsupported_tools", async (t) => {
  let fetches = 0
  const runtime = runtimeFor(t, async () => { fetches += 1; throw new Error("must not fetch") })
  const response = await runtime.forward(async () => syntheticAuth(), SDK_CHAT, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model: "Qwen",
      messages: [{ role: "user", content: "synthetic" }],
      tools: [{ type: "function", function: { name: "synthetic" } }],
    }),
  })
  await expectError(response, { status: 400, code: "unsupported_tools" })
  assert.equal(fetches, 0)
})
