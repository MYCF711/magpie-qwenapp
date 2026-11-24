import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { buildChatBody } from "../src/protocol.mjs"
import { buildChat2ValueToSign, officialWsgSign } from "../src/wsg.mjs"
import { createQwenRuntime } from "../src/runtime.mjs"
import { successAuth } from "../src/cookie.mjs"
import { SYNTHETIC_COOKIE, syntheticAuth, chatRequest } from "./helpers.mjs"

const SDK_CHAT = "https://chat2.qianwen.com/v1/chat/completions"
const NATIVE = {
  serviceTicket: "synthetic-service-ticket",
  kpsWg: "synthetic-kps-wg",
  uId: "1000000000000000001",
  nickname: "synthetic-nickname",
  utdid: "012345" + "6789ab" + "cdef" + "01234567",
  ucParams: {},
}

function nativeAuth() {
  return successAuth({ cookie: SYNTHETIC_COOKIE, native: NATIVE })
}

function runtimeFor(t, fetchImpl) {
  const cacheRoot = mkdtempSync(join(tmpdir(), "qwenapp-official-parity-"))
  t.after(() => rmSync(cacheRoot, { recursive: true, force: true }))
  return createQwenRuntime({ fetchImpl, cacheRoot, sleep: async () => {} })
}

function nativeSse(content = "synthetic ok") {
  return new Response([
    `data: ${JSON.stringify({ object: "ModelRequestProxy", choices: [{ index: 0, delta: { content, reasoning_content: "" }, finish_reason: "null" }] })}`,
    "",
    `data: ${JSON.stringify({ object: "ModelRequestProxy", choices: [{ index: 0, delta: { content: "", reasoning_content: "" }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })}`,
    "",
    "data:[DONE]",
    "",
  ].join("\n"), { headers: { "content-type": "text/event-stream" } })
}

function conversation() {
  return { session_id: "synthetic-session", topic_id: "synthetic-topic", parent_req_id: "" }
}

test("O-01a native biz_data JSON字符串解析为对象，对象保留，非法JSON明确400", () => {
  const base = { model: "qwen4-max", messages: [{ role: "user", content: "synthetic" }] }
  const fromString = buildChatBody({ ...base, qwenapp: { native: true, biz_data: '{"source":"synthetic"}' } }, conversation(), "synthetic-req")
  assert.deepEqual(fromString.biz_data, { source: "synthetic" })
  assert.equal(typeof fromString.biz_data, "object")

  const object = { source: "synthetic", nested: { enabled: true } }
  const fromObject = buildChatBody({ ...base, qwenapp: { native: true, biz_data: object } }, conversation(), "synthetic-req")
  assert.deepEqual(fromObject.biz_data, object)
  assert.throws(
    () => buildChatBody({ ...base, qwenapp: { native: true, biz_data: "{not-json" } }, conversation(), "synthetic-req"),
    (error) => error.status === 400 && error.code === "invalid_request",
  )

  const web = buildChatBody({ ...base, qwenapp: { route: "web", biz_data: '{"source":"synthetic"}' } }, conversation(), "synthetic-req")
  assert.equal(web.biz_data, '{"source":"synthetic"}')
})

test("O-01b native ch 进入实际URL并参与WSG签名，默认仍省略", async (t) => {
  const requests = []
  const runtime = runtimeFor(t, async (url, init) => {
    requests.push({ url: new URL(url), bodyText: init.body })
    return nativeSse()
  })
  for (const ch of ["synthetic-channel", undefined]) {
    const body = chatRequest({ stream: false })
    if (ch) body.qwenapp = { ch }
    const response = await runtime.forward(async () => nativeAuth(), SDK_CHAT, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
    assert.equal(response.status, 200)
    await response.arrayBuffer()
  }
  assert.equal(requests.length, 2)
  assert.equal(requests[0].url.searchParams.get("ch"), "synthetic-channel")
  assert.equal(requests[1].url.searchParams.has("ch"), false)
  for (const { url, bodyText } of requests) {
    const query = Object.fromEntries([...url.searchParams.entries()].filter(([key]) => key !== "sign"))
    const valueToSign = buildChat2ValueToSign({ pathname: "/v1/chat/completions", query, bodyText })
    assert.equal(url.searchParams.get("sign"), officialWsgSign(valueToSign))
  }
})

test("O-02a 静态回退仅 qwen4-max 声明 toolcall=true", async (t) => {
  const runtime = runtimeFor(t, async () => { throw new TypeError("synthetic offline catalog failure") })
  const models = await runtime.models(nativeAuth())
  assert.deepEqual(Object.fromEntries(Object.entries(models).map(([id, model]) => [id, model.capabilities.toolcall])), {
    Qwen: false,
    "qwen4-max": true,
    "qwen3.8-flash": false,
    "qwen3.8-max": false,
    "qwen3.7-max": false,
  })
})

test("O-02b 未知 live 模型不自动获得工具能力", async (t) => {
  const runtime = runtimeFor(t, async () => new Response(JSON.stringify({ data: { models: [
    { model: "qwen4-max", name: "Qwen4 Max", show: true, defaultModel: true },
    { model: "qwen-unknown-synthetic", name: "Synthetic Unknown", show: true },
  ] } }), { headers: { "content-type": "application/json" } }))
  const models = await runtime.models(nativeAuth())
  assert.equal(models["qwen4-max"].capabilities.toolcall, true)
  assert.equal(models["qwen-unknown-synthetic"].capabilities.toolcall, false)
})

test("O-03 未知 usage 不上报数值 used:0，只接受 error/empty 或 textOnly", async (t) => {
  const runtime = runtimeFor(t, async () => { throw new Error("usage must not require network") })
  const usage = await runtime.usage(syntheticAuth())
  assert.doesNotMatch(JSON.stringify(usage), /"used"\s*:\s*0/)
  const errorEmpty = typeof usage.error === "string" && usage.error.length > 0 && Array.isArray(usage.windows) && usage.windows.length === 0
  const textOnly = Array.isArray(usage.windows) && usage.windows.length > 0 && usage.windows.every((window) => window.textOnly === true && !Object.hasOwn(window, "used"))
  assert.ok(errorEmpty || textOnly, JSON.stringify(usage))
})
