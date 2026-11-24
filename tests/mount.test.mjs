import test from "node:test"
import assert from "node:assert/strict"
import * as entry from "../index.mjs"
import { PROVIDER } from "../src/constants.mjs"
import { parseCredential } from "../src/cookie.mjs"
import { syntheticAuth, registerPayload, sseResponse, chatRequest } from "./helpers.mjs"

const { QwenAppAuthPlugin } = entry
const STATIC_MODEL_IDS = ["Qwen", "qwen3.7-max", "qwen3.8-flash", "qwen3.8-max", "qwen4-max"]

test("入口只有一个插件工厂，挂载八项调用钩和账号身份字段", async () => {
  assert.deepEqual(Object.entries(entry).filter(([, value]) => typeof value === "function").map(([key]) => key), ["QwenAppAuthPlugin"])
  assert.equal(typeof entry._internal, "object")
  const plugin = await QwenAppAuthPlugin()
  assert.equal(typeof plugin.config, "function")
  assert.equal(typeof plugin.auth.refresh, "function")
  assert.equal(typeof plugin.auth.loader, "function")
  assert.equal(typeof plugin.auth.usage, "function")
  assert.equal(typeof plugin.auth.checkin, "function")
  assert.equal(typeof plugin.provider.models, "function")
  assert.equal(typeof plugin["chat.headers"], "function")
  assert.ok(plugin.auth.methods.length > 0)
  assert.ok(plugin.auth.methods.every((method) => typeof method.authorize === "function"))
  const windows = plugin.auth.methods.find((method) => method.label.includes("导入"))
  assert.equal(windows.prompts.some((prompt) => prompt.key === "native_device"), false, "设备字段应由导入器自动派生")

  const paste = plugin.auth.methods.find((method) => method.label.includes("粘贴"))
  const result = await paste.authorize({ cookie: syntheticAuth().key, note: "synthetic-visible-name" })
  assert.equal(result.type, "success")
  assert.equal(result.accountId, "synthetic-visible-name")
  assert.match(result.uid, /^[a-f0-9]{32}$/)
  assert.equal(result.metadata.accountFingerprint, result.uid)
})

test("config.models 非空，保留其它 provider 与已有 qwenapp 配置", async () => {
  const plugin = await QwenAppAuthPlugin()
  const cfg = { provider: { other: { name: "untouched" } }, sentinel: { keep: true } }
  plugin.config(cfg)
  assert.equal(cfg.sentinel.keep, true)
  assert.deepEqual(cfg.provider.other, { name: "untouched" })
  assert.ok(Object.keys(cfg.provider[PROVIDER].models).length > 0)
  for (const model of Object.values(cfg.provider[PROVIDER].models)) {
    assert.ok(model.id)
    assert.equal(model.capabilities.toolcall, false)
    assert.deepEqual(Object.keys(model.capabilities.input).sort(), ["audio", "image", "pdf", "text", "video"])
  }

  const existing = { name: "caller-owned", models: { custom: { id: "custom" } } }
  const second = { provider: { [PROVIDER]: existing } }
  plugin.config(second)
  assert.equal(second.provider[PROVIDER], existing)
  assert.deepEqual(second.provider[PROVIDER].models, { custom: { id: "custom" } })
})

test("主 gateway /v1/models 静态目录保留 Qwen/qwen4-max 并含3个实测模型", async () => {
  const plugin = await QwenAppAuthPlugin()
  const cfg = {}
  plugin.config(cfg)
  const models = cfg.provider[PROVIDER].models
  assert.deepEqual(Object.keys(models).sort(), STATIC_MODEL_IDS)
  const gatewayResponse = {
    object: "list",
    data: Object.values(models).map((model) => ({
      id: model.id,
      object: "model",
      owned_by: PROVIDER,
    })),
  }
  assert.deepEqual(gatewayResponse.data.map((model) => model.id).sort(), STATIC_MODEL_IDS)
  assert.equal(gatewayResponse.data.length, 5)
  for (const id of STATIC_MODEL_IDS) {
    assert.equal(models[id].id, id)
    assert.equal(models[id].api.id, id)
    assert.equal(models[id].status, "active")
    assert.ok(models[id].name.length > 0)
  }
})

test("粘贴 authorize 不等待网络，失败结果也不泄漏 Cookie", async (t) => {
  const original = globalThis.fetch
  globalThis.fetch = () => { throw new Error("authorize must not fetch") }
  t.after(() => { globalThis.fetch = original })
  const plugin = await QwenAppAuthPlugin()
  const paste = plugin.auth.methods.find((method) => method.label.includes("粘贴"))
  const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error("authorize blocked")), 100))
  const result = await Promise.race([
    paste.authorize({ cookie: syntheticAuth().key, note: "synthetic" }),
    timeout,
  ])
  assert.equal(result.type, "success")
  const failed = await paste.authorize({ cookie: "tongyi_sso_ticket=synthetic-only" })
  assert.equal(failed.type, "failed")
  assert.doesNotMatch(failed.error, /synthetic-only/)
})

test("auth.refresh 返回合并字段而不是替换账号", async () => {
  const plugin = await QwenAppAuthPlugin()
  const auth = {
    ...syntheticAuth(),
    accountId: "caller-name",
    refresh: "synthetic-refresh-slot",
    expires: 123456,
    custom: { retained: true },
    metadata: { retained: "yes" },
  }
  const merged = await plugin.auth.refresh(auth)
  assert.equal(merged.accountId, "caller-name")
  assert.equal(merged.refresh, "synthetic-refresh-slot")
  assert.equal(merged.expires, 123456)
  assert.deepEqual(merged.custom, { retained: true })
  assert.equal(merged.metadata.retained, "yes")
  assert.equal(merged.metadata.kind, "qianwen-cookie")
  assert.equal(merged.key, auth.key)
  assert.equal(await plugin.auth.refresh({}), undefined)
})

test("loader.fetch 每次重新 getAuth，请求只使用当次账号", async (t) => {
  const original = globalThis.fetch
  const first = syntheticAuth("first")
  const second = syntheticAuth("second")
  second.key = second.key.replace("synthetic-ticket;", "synthetic-ticket-second;")
  const third = syntheticAuth("third")
  third.key = third.key.replace("synthetic-ticket;", "synthetic-ticket-third;")
  const auths = [first, second, third]
  const chatCookies = []
  globalThis.fetch = async (url, init) => {
    if (String(url).includes("/security/external/access/register")) return new Response(JSON.stringify(registerPayload(4)))
    chatCookies.push(new Headers(init.headers).get("cookie"))
    return sseResponse("data: [DONE]\n\n")
  }
  t.after(() => { globalThis.fetch = original })

  const plugin = await QwenAppAuthPlugin()
  let calls = 0
  const loader = await plugin.auth.loader(async () => auths[calls++])
  assert.equal(calls, 1)
  for (let index = 0; index < 2; index += 1) {
    const response = await loader.fetch(`${loader.baseURL}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(chatRequest({ stream: false })),
    })
    assert.equal(response.status, 200, await response.text())
  }
  assert.equal(calls, 3)
  assert.deepEqual(chatCookies, [parseCredential(second.key).cookie, parseCredential(third.key).cookie])
  assert.notEqual(chatCookies[0], chatCookies[1])
})
