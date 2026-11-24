#!/usr/bin/env node
import assert from "node:assert/strict"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { spawn, spawnSync } from "node:child_process"
import { createCipheriv, createHash, randomBytes } from "node:crypto"
import { pathToFileURL } from "node:url"
import { scanErrorCodes } from "./check-error-codes.mjs"
import { scanUserAgents } from "./check-ua.mjs"
import { decryptCookieValue } from "../src/desktop-import.mjs"
import { signChat, chatUrl, buildChatBody, normalizeMessages, translateQwenEvents } from "../src/protocol.mjs"
import { wsgEncrypt, wsgSign, officialWsgSign } from "../src/wsg.mjs"
import { ConversationStore } from "../src/conversation.mjs"
import { assertTrustedUrl, headerSafe } from "../src/security.mjs"
import { successAuth } from "../src/cookie.mjs"
import { writeCache } from "../src/cache.mjs"
import { createQwenRuntime, tokensFromRegister } from "../src/runtime.mjs"
import { parseSse, foldOpenAI } from "../src/openai-sse.mjs"
import { CHAT_URL, OFFICIAL_UA, PROVIDER, QUERY_PARAM_KEYS } from "../src/constants.mjs"
import { createSmsLoginMethod } from "../src/sms-login.mjs"
import { MemoryCookieJar, buildNativeCredential, loginPayloadError, officialLoginSuccess, parseLoginPage } from "../src/sms-protocol.mjs"

const ROOT = path.resolve(process.argv[2] || ".")
const checks = []
const pass = (name) => { checks.push({ name }); console.log(`  ✓ ${name}`) }
const section = (name) => console.log(`\n${name}`)

function runNode(source, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", source], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    })
    let stdout = ""
    let stderr = ""
    child.stdout.on("data", (chunk) => { stdout += chunk })
    child.stderr.on("data", (chunk) => { stderr += chunk })
    child.once("error", reject)
    child.once("close", (code) => resolve({ code, stdout: stdout.trim(), stderr }))
  })
}

function json(file) { return JSON.parse(fs.readFileSync(path.join(ROOT, file), "utf8")) }
function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if ([".git", ".private", ".tmp-quantum-profile", "node_modules", "reference", "recon", "tests"].includes(entry.name)) return []
    const target = path.join(directory, entry.name)
    return entry.isDirectory() ? walk(target) : [target]
  })
}

section("静态契约")
const pkg = json("package.json")
assert.equal(pkg.name, "magpie-qwenapp")
assert.equal(pkg.version, "0.2.0-beta.1")
assert.match(pkg.description, /SMS Beta/i)
assert.equal(pkg.type, "module")
assert.equal(pkg.license, "MIT")
assert.equal(pkg.main, "./index.mjs")
assert.ok(Array.isArray(pkg.files) && pkg.files.length > 0)
for (const required of ["README.md", "official", "icon-official.png"]) assert.ok(pkg.files.includes(required), `package.files 缺少 ${required}`)
assert.ok(!pkg.dependencies || Object.keys(pkg.dependencies).length === 0)
assert.ok(pkg.keywords.includes("magpie") && pkg.keywords.includes("opencode") && pkg.keywords.includes("provider"))
pass("包身份、ESM、MIT、零运行时依赖")

const registry = json("registry-entry.json")
assert.ok(!Object.hasOwn(registry, "version"), "registry-entry.json 不应硬编码版本")
assert.equal(registry.package, pkg.name)
assert.deepEqual(registry.providers, [PROVIDER])
assert.ok(registry.summary.zh && registry.summary.en)
assert.match(pkg.magpie.name, /[\u3400-\u9fff]/)
assert.match(pkg.magpie.name, /[A-Za-z]/)
pass("registry 与双语显示名")

const license = fs.readFileSync(path.join(ROOT, "LICENSE"), "utf8")
assert.match(license, /Permission is hereby granted,\s*free of charge/i)
assert.ok(!license.includes("YOUR NAME"))
const icon = fs.readFileSync(path.join(ROOT, "icon-official.png"))
const iconUri = `data:image/png;base64,${icon.toString("base64")}`
assert.equal(pkg.magpie.icon, iconUri)
assert.ok(iconUri.length <= (3 << 19))
assert.match(OFFICIAL_UA, /^Mozilla\/5\.0 .*Chrome\/\d+\.0\.0\.0 Safari\/537\.36 TONGYI_DESKTOP\//)
pass("LICENSE、官方图标与桌面 UA")

for (const file of [path.join(ROOT, "index.mjs"), ...walk(path.join(ROOT, "src")), ...walk(path.join(ROOT, "scripts"))]) {
  if (!/\.mjs$/.test(file)) continue
  const result = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" })
  assert.equal(result.status, 0, result.stderr || `${file} 语法检查失败`)
}
pass("全部入口、src 与检查脚本 node --check")

const sourceFiles = [path.join(ROOT, "index.mjs"), ...walk(path.join(ROOT, "src"))]
for (const file of sourceFiles) {
  const text = fs.readFileSync(file, "utf8")
  assert.ok(!/plugin-market\.json|startSelfRegister|buildSystemPrompt|personaPrompt|qwen_cowork_config/.test(text), `${file} 含禁止的宿主写入或 CMS 注入`)
  assert.ok(!/[Cc]:[\\/]Users[\\/][^<]/.test(text), `${file} 含本机用户路径`)
  assert.ok(!/eyJhbGciOiJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{20,}/.test(text), `${file} 含疑似 JWT`)
}
assert.equal(scanErrorCodes(ROOT).filter((row) => !row.ok).length, 0)
assert.equal(scanUserAgents(ROOT).filter((row) => row.level === "fail").length, 0)
pass("秘密、CMS 注入、错误词表与 UA 静态扫描")

section("九钩装配")
const entry = await import(pathToFileURL(path.join(ROOT, "index.mjs")).href)
const functions = Object.values(entry).filter((value) => typeof value === "function")
assert.equal(functions.length, 1)
const hooks = await functions[0]({ client: {}, directory: ROOT })
assert.deepEqual(Object.keys(hooks).sort(), ["auth", "chat.headers", "config", "provider"])
assert.equal(hooks.auth.provider, PROVIDER)
assert.equal(hooks.provider.id, PROVIDER)
assert.equal(hooks.auth.icon, iconUri)
assert.equal(hooks.auth.methods.length, 3)
assert.ok(hooks.auth.methods.every((method) => method.type === "api" && typeof method.authorize === "function"))
assert.equal(typeof hooks.auth.methods[0].ask, "function")
assert.ok(hooks.auth.methods[0].prompts.length >= 2)
for (const key of ["refresh", "loader", "usage", "checkin"]) assert.equal(typeof hooks.auth[key], "function")
const cfg = {}
await hooks.config(cfg)
const configured = cfg.provider[PROVIDER]
assert.equal(configured.name, pkg.magpie.name)
for (const id of ["Qwen", "qwen4-max", "qwen3.8-flash", "qwen3.8-max", "qwen3.7-max"]) {
  assert.ok(configured.models[id], `静态回退目录缺少 ${id}`)
}
assert.equal(Object.keys(configured.models).length, 5)
for (const model of Object.values(configured.models)) {
  assert.equal(model.capabilities.toolcall, false)
  assert.equal(typeof model.capabilities.input.image, "boolean")
  assert.ok(!("prompt" in model))
}
const loaded = await hooks.auth.loader(async () => successAuth("tongyi_sso_ticket=test-ticket; tongyi_sso_ticket_hash=test-hash; XSRF-TOKEN=test-xsrf"))
assert.equal(loaded.apiKey, "")
assert.equal(loaded.baseURL, "https://chat2.qianwen.com/v1")
assert.equal(typeof loaded.fetch, "function")
await hooks["chat.headers"]({ model: { providerID: PROVIDER }, sessionID: "session" }, { headers: {} })
const usage = await hooks.auth.usage(async () => null)
assert.deepEqual(usage.windows, [])
const knownAccountUsage = await hooks.auth.usage(async () => successAuth("tongyi_sso_ticket=usage-ticket; tongyi_sso_ticket_hash=usage-hash; XSRF-TOKEN=usage-xsrf"))
assert.deepEqual(knownAccountUsage.windows, [])
assert.match(knownAccountUsage.error, /额度未知/)
assert.ok(!JSON.stringify(knownAccountUsage).includes('"used":0'))
const checkin = await hooks.auth.checkin()
assert.equal(checkin.outcome, "inactive")
pass("单工厂、九钩、静态模型、空 chat.headers 与无 Bearer")

section("手机短信登录（全离线 mock）")
const smsCalls = []
let smsClock = 1_000
let smsIds = 0
const loginHtml = `<script>window.viewConfig={"defaultView":"sms","smsCodeLength":6,"api":{"sendSmsApi":"/havanaone/loginLegacy/sms/sendSms.do?bizEntrance=tongyi&bizName=tongyi","smsLoginApi":"/havanaone/loginLegacy/sms/login.do?bizEntrance=tongyi&bizName=tongyi"}};window.viewData={"loginFormData":{"_csrf":"synthetic-form-csrf"},"contextToken":"synthetic-context-token"};</script>`
const smsResponse = (payload, cookies = []) => {
  const headers = new Headers({ "content-type": "application/json" })
  for (const cookie of cookies) headers.append("set-cookie", cookie)
  return new Response(JSON.stringify(payload), { status: 200, headers })
}
const smsMethod = createSmsLoginMethod({
  now: () => smsClock,
  uuid: () => `synthetic-flow-${++smsIds}`,
  randomBytes: (size) => Buffer.alloc(size, 7),
  fetchImpl: async (url, init) => {
    smsCalls.push({ url: String(url), init })
    const pathname = new URL(url).pathname
    if (pathname === "/havanaone/login/login.htm") {
      return new Response(loginHtml, { status: 200, headers: {
        "content-type": "text/html",
        "set-cookie": "XSRF-TOKEN=synthetic-xsrf-cookie; Domain=.qianwen.com; Path=/",
      } })
    }
    if (pathname === "/havanaone/loginLegacy/sms/sendSms.do") {
      return smsResponse({ hasError: false, content: { data: { smsToken: "synthetic-sms-token", contextToken: "synthetic-context-next" } } })
    }
    if (pathname === "/havanaone/loginLegacy/sms/login.do") {
      return smsResponse({ hasError: false, content: { data: { resultCode: 100, redirect: true, redirectUrl: "https://www.qianwen.com/desktop-app" } } }, [
        "tongyi_sso_ticket=synthetic-login-ticket; Domain=.qianwen.com; Path=/",
        "tongyi_sso_ticket_hash=synthetic-login-hash; Domain=.qianwen.com; Path=/",
      ])
    }
    if (pathname === "/api/account/v2/info") {
      return smsResponse({ success: true, data: { service_ticket: "synthetic-service-ticket", kps_wg: "synthetic-kps-wg", uId: "synthetic-user-id", nickname: "synthetic-nickname" } })
    }
    throw new Error("unexpected synthetic URL")
  },
})
assert.equal((await smsMethod.ask({})).key, "mobile")
const codePrompt = await smsMethod.ask({ mobile: "13800000000" })
assert.equal(codePrompt.key, "sms_code")
assert.equal(codePrompt.type, "password")
assert.equal(smsCalls.length, 2)
const sendForm = new URLSearchParams(smsCalls[1].init.body)
assert.equal(sendForm.get("loginId"), "13800000000")
assert.equal(sendForm.get("loginId2"), "")
assert.equal(sendForm.get("loginId"), "13800000000")
assert.equal(officialLoginSuccess({}, { redirect: true, redirectUrl: "https://www.qianwen.com/desktop-app" }), true)
assert.equal(officialLoginSuccess({ hasError: true }, { redirect: true, redirectUrl: "https://www.qianwen.com/desktop-app" }), false)
assert.equal(officialLoginSuccess({}, { isCheckCodeShowed: true, redirect: true, redirectUrl: "https://www.qianwen.com/desktop-app" }), false)
assert.equal(officialLoginSuccess({}, { redirect: true, redirectUrl: "https://www.qianwen.com.evil.example/" }), false)
for (const data of [
  { parentRedirect: true, parentRedirectUrl: "https://www.qianwen.com/desktop-app" },
  { iframeRedirect: true, iframeRedirectUrl: "https://www.qianwen.com/desktop-app" },
  { replace: true, replaceUrl: "https://www.qianwen.com/desktop-app" },
  { st: "synthetic-login-state" },
]) assert.equal(officialLoginSuccess({}, data), true)
assert.equal(officialLoginSuccess({}, { resultCode: 100, redirectUrl: "https://www.qianwen.com/desktop-app" }), false)
for (const flag of [true, "true", 1, "1", {}, []]) {
  assert.equal(loginPayloadError({ hasError: flag }, {}), true)
  assert.equal(officialLoginSuccess({ hasError: flag }, { redirect: true, redirectUrl: "https://www.qianwen.com/desktop-app" }), false)
}
for (const flag of [false, "false", 0, "0"]) assert.equal(loginPayloadError({ hasError: flag }, {}), false)
for (const flag of [false, "false", 0, "0", {}]) assert.equal(loginPayloadError({ success: flag }, {}), true)
assert.throws(() => parseLoginPage(loginHtml.replaceAll("bizEntrance=tongyi", "bizEntrance=other")), /bizEntrance/)
assert.equal(sendForm.get("_csrf"), "synthetic-form-csrf")
assert.equal(sendForm.get("smsCode"), null)
assert.equal(sendForm.get("codeLength"), "6")
assert.equal(new Headers(smsCalls[1].init.headers).get("x-xsrf-token"), "synthetic-xsrf-cookie")
assert.notEqual(sendForm.get("_csrf"), new Headers(smsCalls[1].init.headers).get("x-xsrf-token"))
const cooling = await smsMethod.ask({ mobile: "13800000000", sms_code: "0" })
assert.match(cooling.message, /冷却/)
assert.equal(smsCalls.length, 2, "冷却期内不得重发")
smsClock += 60_000
assert.equal((await smsMethod.ask({ mobile: "13800000000", sms_code: "0" })).key, "sms_code")
assert.equal(smsCalls.length, 3)
assert.equal(await smsMethod.ask({ mobile: "13800000000", sms_code: "000000" }), null)
const verifyWire = smsCalls.find((call) => new URL(call.url).pathname === "/havanaone/loginLegacy/sms/login.do")
const verifyForm = new URLSearchParams(verifyWire.init.body)
assert.equal(verifyForm.get("contextToken"), "synthetic-context-token")
assert.equal(verifyForm.get("_csrf"), "synthetic-form-csrf")
assert.equal(verifyForm.get("codeLength"), null)
const beforeAuthorizeCalls = smsCalls.length
const smsAuth = await smsMethod.authorize({ mobile: "13800000000", sms_code: "000000" })
assert.equal(smsAuth.type, "success")
assert.equal(smsCalls.length, beforeAuthorizeCalls, "authorize 必须零网络")
const smsCredential = JSON.parse(smsAuth.key)
assert.equal(smsCredential.native.serviceTicket, "synthetic-service-ticket")
assert.equal(smsCredential.native.kpsWg, "synthetic-kps-wg")
assert.equal(smsCredential.native.uId, "synthetic-user-id")
assert.ok(smsCredential.native.utdid && smsCredential.native.uidWsg && smsCredential.native.ucParams.ut)
assert.ok(!smsCredential.cookie.includes("synthetic-service-ticket"))
assert.ok(!JSON.stringify(smsAuth).includes("13800000000"))
assert.ok(!JSON.stringify(smsAuth).includes("000000"))
assert.equal((await smsMethod.authorize({})).type, "failed")
assert.equal(smsCalls.length, beforeAuthorizeCalls)
const fallbackJar = new MemoryCookieJar()
fallbackJar.set("tongyi_sso_ticket", "synthetic-cookie-service-ticket")
fallbackJar.set("tongyi_sso_ticket_hash", "synthetic-cookie-hash")
const fallbackCredential = buildNativeCredential({ jar: fallbackJar, info: { data: { kps_wg: "synthetic-kps", uId: "synthetic-uid", nickname: "" } }, randomBytes: (size) => Buffer.alloc(size, 8) })
assert.equal(fallbackCredential.native.serviceTicket, "synthetic-cookie-service-ticket")
const aliasJar = new MemoryCookieJar()
for (const [name, value] of Object.entries({ tongyi_sso_ticket: "synthetic-ticket", tongyi_sso_ticket_hash: "synthetic-hash", kpsWg: "synthetic-cookie-kps", uId: "synthetic-cookie-uid", nickname: "synthetic-cookie-nick" })) aliasJar.set(name, value)
assert.throws(() => buildNativeCredential({ jar: aliasJar, info: { success: true, data: {} } }), /kpsWg|uId|nickname/)
// kpsWg 不是服务端字段：有 serviceTicket + uId 时按已证公式本地派生（真实账号逐字节对拍一致）。
const derivedKps = buildNativeCredential({ jar: fallbackJar, info: { data: { uId: "synthetic-uid", nickname: "" } } })
assert.equal(derivedKps.native.kpsWg, wsgEncrypt(`token=${derivedKps.native.serviceTicket}&uid=${derivedKps.native.uId}&nickname=${derivedKps.native.nickname}`))
assert.match(derivedKps.native.kpsWg, /^O\//)
// 缺 uId 时仍必须拒绝，不能只靠 Cookie 伪造。
assert.throws(() => buildNativeCredential({ jar: fallbackJar, info: { data: { nickname: "" } } }), /kpsWg|uId|native 字段/)
assert.throws(() => buildNativeCredential({ jar: fallbackJar, info: { success: "false", data: { service_ticket: "synthetic-service", kps_wg: "synthetic-kps", uId: "synthetic-uid", nickname: "" } } }), /NOT_LOGIN|Web 会话|登录/)
const selectedCookieJar = new MemoryCookieJar()
selectedCookieJar.set("XSRF-TOKEN", "synthetic-root-xsrf", { domain: ".qianwen.com", path: "/" })
selectedCookieJar.set("XSRF-TOKEN", "synthetic-specific-xsrf", { domain: "passport.qianwen.com", path: "/havanaone", hostOnly: true })
const selectedCookieUrl = "https://passport.qianwen.com/havanaone/loginLegacy/sms/sendSms.do?bizEntrance=tongyi&bizName=tongyi"
assert.equal(selectedCookieJar.get("XSRF-TOKEN", selectedCookieUrl), "synthetic-specific-xsrf")
assert.equal((selectedCookieJar.cookieHeader(selectedCookieUrl).match(/XSRF-TOKEN=/g) || []).length, 1)
assert.match(selectedCookieJar.cookieHeader(selectedCookieUrl), /synthetic-specific-xsrf/)
let httpErrorIds = 0
const httpErrorMethod = createSmsLoginMethod({
  now: () => 1_000,
  uuid: () => `synthetic-http-error-${++httpErrorIds}`,
  fetchImpl: async (url) => {
    if (new URL(url).pathname === "/havanaone/login/login.htm") {
      return new Response(loginHtml, { status: 200, headers: { "content-type": "text/html", "set-cookie": "XSRF-TOKEN=synthetic-xsrf-cookie; Domain=.qianwen.com; Path=/" } })
    }
    return new Response(JSON.stringify({ content: { data: {
      titleMsg: "synthetic-fresh-http-error-token",
      smsToken: "synthetic-fresh-http-error-token",
      contextToken: "synthetic-fresh-http-context-token",
    } } }), { status: 400, headers: { "content-type": "application/json" } })
  },
})
await httpErrorMethod.ask({})
const httpErrorPrompt = await httpErrorMethod.ask({ mobile: "13800000000" })
assert.ok(!httpErrorPrompt.message.includes("synthetic-fresh-http-error-token"))
assert.ok(!httpErrorPrompt.message.includes("synthetic-fresh-http-context-token"))
pass("手机号→发送→OTP→info→完整 native；冷却、一次性 authorize、秘密隔离与 ticket 回退")

let limitedClock = Date.UTC(2026, 0, 1, 0, 0, 0)
let limitedIds = 0
let limitedSends = 0
const limitedMethod = createSmsLoginMethod({
  now: () => limitedClock,
  uuid: () => `synthetic-limited-${++limitedIds}`,
  fetchImpl: async (url) => {
    const pathname = new URL(url).pathname
    if (pathname === "/havanaone/login/login.htm") {
      return new Response(loginHtml, { status: 200, headers: { "content-type": "text/html", "set-cookie": "XSRF-TOKEN=synthetic-xsrf-cookie; Domain=.qianwen.com; Path=/" } })
    }
    if (pathname === "/havanaone/loginLegacy/sms/sendSms.do") {
      limitedSends += 1
      if (limitedSends === 1) {
        return new Response(JSON.stringify({ content: { data: { titleMsg: "synthetic limited" } } }), {
          status: 429,
          headers: { "content-type": "application/json", "retry-after": new Date(limitedClock + 120_000).toUTCString() },
        })
      }
      return smsResponse({ content: { data: { smsToken: "synthetic-limited-sms-token" } } })
    }
    throw new Error("unexpected limited URL")
  },
})
await limitedMethod.ask({})
const limitedPrompt = await limitedMethod.ask({ mobile: "13800000000" })
assert.match(limitedPrompt.message, /120/)
assert.equal(limitedSends, 1)
await limitedMethod.ask({})
const crossFlowBlocked = await limitedMethod.ask({ mobile: "13800000000" })
assert.match(crossFlowBlocked.message, /冷却|等待/)
assert.equal(limitedSends, 1, "新 flow 不得重置 429 冷却")
limitedClock += 120_000
assert.equal((await limitedMethod.ask({ mobile: "13800000000" })).key, "sms_code")
assert.equal(limitedSends, 2)
pass("Retry-After HTTP-date 保留真实秒数，跨 flow 共享冷却，send/login codeLength 分流")

section("Windows Cookie 与协议纯函数")
const host = "www.qianwen.com"
const key = randomBytes(32)
const nonce = randomBytes(12)
const plaintext = Buffer.concat([createHash("sha256").update(host).digest(), Buffer.from("synthetic-cookie-value")])
const cipher = createCipheriv("aes-256-gcm", key, nonce)
const encrypted = Buffer.concat([Buffer.from("v10"), nonce, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
assert.equal(decryptCookieValue(encrypted, host, key), "synthetic-cookie-value")
assert.throws(() => decryptCookieValue(encrypted, "chat2-api.qianwen.com", key), /host_key SHA-256/)
pass("v10 AES-GCM 强制校验并剥离 SHA256(host_key) 前缀")

const vector = signChat({ deviceId: "device-1", ticketHash: "ticket-hash", sacsft: "sacsft", bodyStr: "{\"x\":1}", timestamp: "1700000000000" })
assert.equal(vector.bodyHmac, "cgvpdnlKmXTcOGXjPrXds/yK15Dyz7zTF4p7noxhQJY=")
assert.equal(vector.sign, "yZRy13TP5DBhMczQlmS5N+QusvYS3W2TCYgc40xqxS0=")
const signed = chatUrl({ deviceId: "device-1", ticketHash: "ticket-hash", sacsft: "sacsft", bodyStr: "{}", timestamp: 1700000000000, nonce: "nonce" })
assert.deepEqual([...new URL(signed.url).searchParams.keys()], QUERY_PARAM_KEYS.split(","))
assert.equal(new URL(signed.url).searchParams.get("tz"), "Asia/Shanghai")
assert.match(signed.url, /tz=Asia%2FShanghai/)
const withChannel = chatUrl({ deviceId: "device-1", ticketHash: "ticket-hash", sacsft: "sacsft", bodyStr: "{}", timestamp: 1700000000000, nonce: "nonce", ch: "channel" })
assert.equal(new URL(withChannel.url).searchParams.get("ch"), "channel")
assert.equal(wsgSign("value", "secret"), "3bf7330b72d384df41adf440e1d8aeb543ab73eecb8a")
assert.equal(officialWsgSign("MAGPIE_WSG_TEST"), "3bf77f8c856cd9381606555b5cd9f49a9e353aa35d06")
const liveRegister = tokensFromRegister({ status: 0, data: { "eo-clt-dvidn": "live-device", "eo-clt-actkn": "root-actkn", unifyRelate: [
  { businessScene: "qwen_web_capsule", "eo-clt-bacsft": ["fallback"] },
  { businessScene: "qwen_chat", "eo-clt-actkn": "chat-actkn", "eo-clt-snver": "lv", "eo-clt-bacsft": ["token-1", "token-2"] },
] } })
assert.equal(liveRegister.length, 2)
assert.equal(liveRegister[0].dvidn, "live-device")
assert.equal(liveRegister[0].actkn, "chat-actkn")
const nestedRegister = tokensFromRegister({ root: { unifyRelate: { qwen_chat: { qwen_web_capsule: [{ root: { "eo-clt-dvidn": "nested-device", "eo-clt-actkn": "nested-actkn", "eo-clt-snver": "nested-snver", "eo-clt-bacsft": ["nested-token"] } }] } } } })
assert.equal(nestedRegister[0].sacsft, "nested-token")
pass("HMAC-WSG 固定向量、query/ch 与 live/嵌套 register 结构")

const original = { model: "qwen3.8-flash", messages: [{ role: "system", content: "调用方 system" }, { role: "user", content: "你好" }] }
const normalized = normalizeMessages(original)
assert.deepEqual(normalized.map((message) => [message.role, message.content]), [["system", "调用方 system"], ["user", "你好"]])
assert.ok(normalized.every((message) => message.mime_type === "text/plain" && message.status === "complete" && typeof message.meta_data.ori_query === "string"))
assert.throws(() => normalizeMessages({ messages: original.messages, tools: [{ type: "function", function: { name: "x" } }] }), (error) => error.status === 400 && error.code === "unsupported_tools")
const branch = { session_id: "session", topic_id: "topic", parent_req_id: "" }
const body = buildChatBody({ ...original, qwenapp: { scene: "native", sub_scene: "direct", from: "custom", ch: "channel", biz_data: { source: "caller" } } }, branch, "req")
assert.equal(body.scene, "native")
assert.equal(body.sub_scene, "direct")
assert.equal(body.from, "custom")
assert.equal(body.ch, undefined)
assert.equal(body.biz_data, "{\"source\":\"caller\"}")
assert.equal(body.req_id, "req")
const nativeBody = buildChatBody({ ...original, qwenapp: { route: "native" } }, branch, "native-req")
assert.equal(nativeBody.fr, "win")
assert.equal(nativeBody.stream, true)
assert.equal(nativeBody.from, undefined)
assert.equal(nativeBody.sub_scene, undefined)
assert.equal(nativeBody.biz_data, undefined)
assert.equal(nativeBody.ext.raw_query, "你好")
for (const key of ["skill_call_list", "connector_call_list", "tool_call_list"]) assert.equal(nativeBody.ext[key], "")
assert.equal(nativeBody.messages[0].content, "调用方 system")
assert.throws(() => buildChatBody({ ...original, qwenapp: { route: "native", biz_data: "{" } }, branch, "bad-biz"),
  (error) => error.status === 400 && error.code === "invalid_request")
assert.ok(!JSON.stringify(body).includes("小酒窝"))
assert.ok(!JSON.stringify(nativeBody).includes("小酒窝"))
pass("保留调用方 system、unsupported_tools、Web/cowork 独立路由字段")

const conversations = new ConversationStore({ capacity: 2 })
const first = conversations.resolve({ messages: normalized })
const same = conversations.resolve({ messages: normalized })
assert.equal(first.session_id, same.session_id)
const other = conversations.resolve({ messages: normalizeMessages({ messages: [original.messages[0], { role: "user", content: "另一个对话" }] }) })
assert.notEqual(first.session_id, other.session_id)
assert.ok(conversations.size <= 2)
pass("完整消息链分支与有界会话映射")

assert.equal(assertTrustedUrl(CHAT_URL, "chat").hostname, "chat2.qianwen.com")
for (const bad of ["http://chat2.qianwen.com/api/v2/chat", "https://user:pass@chat2.qianwen.com/api/v2/chat", "https://evil.example/api/v2/chat", "https://chat2.qianwen.com.evil.example/api/v2/chat"]) {
  assert.throws(() => assertTrustedUrl(bad, "chat"))
}
const safe = headerSafe({ accept: "text/event-stream", "content-type": "application/json", cookie: "secret", authorization: "Bearer secret", "x-forwarded-for": "127.0.0.1" })
assert.equal(safe.get("accept"), "text/event-stream")
assert.equal(safe.get("cookie"), null)
assert.equal(safe.get("authorization"), null)
assert.equal(safe.get("x-forwarded-for"), null)
pass("固定 HTTPS origin/path 与 headerSafe 默认 allowlist")

section("SSE 状态机")
const parsed = parseSse("data: {\"data\":\r\ndata: {\"messages\":[]}}\r\n\r\n")
assert.equal(parsed.length, 1)
assert.match(parsed[0].data, /\n/)
const frames = [
  { event: "message", data: JSON.stringify({ data: { messages: [{ mime_type: "multi_load/iframe", content: "M", status: "processing" }] } }) },
  { event: "message", data: JSON.stringify({ data: { messages: [{ mime_type: "multi_load/iframe", content: "MAGPIE", status: "complete" }], extra_info: { chat_odps: { total_usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 } } } } }) },
  { event: "complete", data: JSON.stringify({ data: { messages: [] } }) },
]
const chunks = []
for await (const item of translateQwenEvents((async function* () { yield* frames })(), { model: "qwen-test" })) chunks.push(item)
assert.equal(chunks.filter((item) => item.choices[0].delta.content).map((item) => item.choices[0].delta.content).join(""), "MAGPIE")
assert.deepEqual(chunks.at(-1).usage, { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 })
const folded = await foldOpenAI(chunks, { model: "qwen-test" })
assert.equal(folded.choices[0].message.content, "MAGPIE")
assert.equal(folded.usage.total_tokens, 5)
const bare = []
for await (const item of translateQwenEvents((async function* () { yield { data: "true" }; yield { data: "[DONE]" } })(), { model: "qwen-test" })) bare.push(item)
assert.equal(bare.at(-1).choices[0].finish_reason, "stop")
pass("CRLF、多行 data、裸 true/[DONE]、快照增量、usage 与非流折叠")

section("离线端到端（无真实账号/网络）")
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "qwenapp-check-"))
try {
  const auth = successAuth("tongyi_sso_ticket=test-ticket; tongyi_sso_ticket_hash=test-hash; XSRF-TOKEN=test-xsrf")
  const requests = []
  let upstreamCompleted = false
  const fetchImpl = async (url, init) => {
    requests.push({ url: String(url), init })
    if (requests.length === 1) return new Response("{\"error_msg\":\"busy\"}", { status: 500, headers: { "content-type": "application/json" } })
    let timer
    const stream = new ReadableStream({
      start(controller) {
        const encode = (value) => new TextEncoder().encode(value)
        controller.enqueue(encode(`data:${JSON.stringify({ data: { messages: [{ mime_type: "multi_load/iframe", content: "M", status: "processing" }] } })}\n\n`))
        timer = setTimeout(() => {
          controller.enqueue(encode(`data:${JSON.stringify({ data: { messages: [{ mime_type: "multi_load/iframe", content: "MAGPIE", status: "complete" }], extra_info: { chat_odps: { total_usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 } } } } })}\n\n`))
          controller.enqueue(encode(`event:complete\ndata:${JSON.stringify({ data: { messages: [] } })}\n\n`))
          controller.close()
          upstreamCompleted = true
        }, 25)
      },
      cancel() { clearTimeout(timer) },
    })
    return new Response(stream, { status: 200, headers: { "content-type": "text/event-stream" } })
  }
  const runtime = createQwenRuntime({ fetchImpl, cacheRoot: temp, sleep: async () => {} })
  const account = runtime.accountFor(auth)
  account.cache = {
    deviceId: "device",
    fingerprint: "fingerprint",
    tokens: [1, 2, 3, 4].map((n) => ({ dvidn: `dvidn-${n}`, actkn: `actkn-${n}`, snver: `snver-${n}`, sacsft: `sacsft-${n}` })),
  }
  assert.equal(writeCache(account.file, account.cache), true)
  const response = await runtime.forward(async () => auth, "https://chat2.qianwen.com/v1/chat/completions", {
    method: "POST",
    body: JSON.stringify({ ...original, stream: true, qwenapp: { scene: "native", biz_data: { test: true } } }),
  })
  assert.equal(response.status, 200)
  assert.match(response.headers.get("content-type"), /text\/event-stream/)
  const reader = response.body.getReader()
  const first = await reader.read()
  assert.equal(first.done, false)
  assert.equal(upstreamCompleted, false, "首块必须在上游完整结束前可读")
  let text = new TextDecoder().decode(first.value)
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    text += new TextDecoder().decode(value)
  }
  assert.equal(requests.length, 2, "500 应有限重试一次")
  const bodies = requests.map((request) => JSON.parse(request.init.body))
  assert.notEqual(bodies[0].req_id, bodies[1].req_id, "POST 重试必须使用新 req_id")
  assert.equal(bodies[1].messages[0].content, "调用方 system")
  assert.equal(bodies[1].scene, "native")
  assert.equal(bodies[1].biz_data, "{\"test\":true}")
  assert.ok(requests.every((request) => request.init.redirect === "error"))
  assert.ok(requests.every((request) => request.init.headers["user-agent"] === OFFICIAL_UA))
  assert.ok(requests.every((request) => request.init.headers.cookie === JSON.parse(auth.key).cookie))
  const output = text.split(/\n\n/).map((block) => block.replace(/^data:/, "").trim()).filter((block) => block && block !== "[DONE]").map((block) => JSON.parse(block))
  assert.equal(output.filter((item) => item.choices?.[0]?.delta?.content).map((item) => item.choices[0].delta.content).join(""), "MAGPIE")
  assert.equal(output.at(-1).usage.total_tokens, 5)
  assert.match(text, /data: \[DONE\]/)
  pass("真实 ReadableStream 首块、500 重试新 req_id/新签名、独立 token 消费与最终 usage")
} finally {
  fs.rmSync(temp, { recursive: true, force: true })
}

section("原生 cowork 离线端到端")
const nativeCookie = "tongyi_sso_ticket=native-cookie-ticket; tongyi_sso_ticket_hash=native-cookie-hash; XSRF-TOKEN=native-xsrf"
const nativeAuth = successAuth({ cookie: nativeCookie, native: {
  serviceTicket: "native-service-ticket",
  kpsWg: "native-kps",
  uId: "native-user-id",
  nickname: "native-nickname",
  uidWsg: "native-uid-wsg-must-not-be-ut",
  utdid: "native-transport-utdid",
  ucParams: { ut: "native-public-uc-ut", sn: "native-public-sn" },
} })
const nativeRequests = []
const offlineModels = await createQwenRuntime({ fetchImpl: async () => { throw new TypeError("synthetic offline") } }).models(nativeAuth)
assert.equal(offlineModels["qwen4-max"].capabilities.toolcall, true)
for (const id of ["Qwen", "qwen3.8-flash", "qwen3.8-max", "qwen3.7-max"]) {
  assert.equal(offlineModels[id].capabilities.toolcall, false)
}
const nativeRuntime = createQwenRuntime({ fetchImpl: async (url, init) => {
  nativeRequests.push({ url: String(url), init })
  const text = "data:{\"choices\":[{\"delta\":{\"content\":\"NATIVE_OK\"}}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":3,\"total_tokens\":7}}\n\n" +
    "data:{\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata:[DONE]\n\n"
  return new Response(text, { status: 200, headers: { "content-type": "text/event-stream" } })
} })
const nativeResponse = await nativeRuntime.forward(async () => nativeAuth, "https://chat2.qianwen.com/v1/chat/completions", {
  method: "POST",
  body: JSON.stringify({ model: "qwen4-max", messages: original.messages, stream: true, qwenapp: { ch: "native-channel", biz_data: "{\"source\":\"native-check\"}" } }),
})
assert.equal(nativeResponse.status, 200)
const nativeOutputText = await nativeResponse.text()
assert.equal(nativeRequests.length, 1, "原生路由不应先调用 register")
const nativeUrl = new URL(nativeRequests[0].url)
assert.equal(nativeUrl.searchParams.get("ut"), "native-public-uc-ut")
assert.equal(nativeUrl.searchParams.get("ch"), "native-channel")
assert.match(nativeUrl.searchParams.get("sign"), /^3bf7[0-9a-f]{40}$/)
const nativeWireBody = JSON.parse(nativeRequests[0].init.body)
assert.equal(nativeWireBody.fr, "win")
assert.deepEqual(nativeWireBody.biz_data, { source: "native-check" })
assert.equal(nativeWireBody.messages[0].content, "调用方 system")
assert.ok(nativeWireBody.request_id && nativeWireBody.ext)
assert.equal(nativeWireBody.req_id, undefined)
const nativeHeaders = nativeRequests[0].init.headers
assert.equal(nativeHeaders.cookie, nativeCookie)
assert.ok(!nativeHeaders.cookie.includes("native-service-ticket"))
assert.equal(nativeHeaders["x-u-kps-wg"], "native-kps")
assert.equal(nativeHeaders["x-utdid"], "native-transport-utdid")
assert.ok(nativeHeaders["x-u-sign-wg"] && nativeHeaders["x-u-vcode"])
assert.equal(nativeHeaders["eo-clt-sacsft"], undefined)
const nativeOutput = nativeOutputText.split(/\n\n/).map((block) => block.replace(/^data:/, "").trim()).filter((block) => block && block !== "[DONE]").map((block) => JSON.parse(block))
assert.equal(nativeOutput.filter((item) => item.choices?.[0]?.delta?.content).map((item) => item.choices[0].delta.content).join(""), "NATIVE_OK")
assert.equal(nativeOutput.find((item) => item.usage)?.usage?.total_tokens, 7)
pass("完整 credential 默认 native、WSG/signWg、公开 UC/UTDID、Cookie 隔离与 OpenAI SSE")

const truncatedNative = await createQwenRuntime({ fetchImpl: async () => new Response(
  'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n',
  { status: 200, headers: { "content-type": "text/event-stream" } },
) }).forward(async () => nativeAuth, "https://chat2.qianwen.com/v1/chat/completions", {
  method: "POST",
  body: JSON.stringify({ model: "qwen4-max", messages: original.messages, stream: false }),
})
assert.equal(truncatedNative.status, 504)
assert.equal((await truncatedNative.json()).error.code, "upstream_timeout")
pass("native EOF 无 finish/[DONE] 时明确 504，不伪造成功")

section("跨进程 token 消费互斥")
const processTemp = fs.mkdtempSync(path.join(os.tmpdir(), "qwenapp-process-lock-"))
try {
  const processAuth = successAuth("tongyi_sso_ticket=synthetic-process-ticket; tongyi_sso_ticket_hash=synthetic-process-hash; XSRF-TOKEN=synthetic-process-xsrf")
  const setup = createQwenRuntime({ cacheRoot: processTemp, fetchImpl: async () => { throw new Error("unexpected register") } })
  const processAccount = setup.accountFor(processAuth)
  processAccount.cache = {
    deviceId: "process-device",
    tokens: Array.from({ length: 8 }, (_, index) => ({
      dvidn: "process-device",
      actkn: "process-actkn",
      snver: "lv",
      sacsft: `process-token-${index}`,
    })),
  }
  assert.equal(writeCache(processAccount.file, processAccount.cache), true)
  const childSource = `
    const { createQwenRuntime } = await import(process.env.QWEN_RUNTIME_URL)
    const { successAuth } = await import(process.env.QWEN_COOKIE_URL)
    const auth = successAuth('tongyi_sso_ticket=synthetic-process-ticket; tongyi_sso_ticket_hash=synthetic-process-hash; XSRF-TOKEN=synthetic-process-xsrf')
    const runtime = createQwenRuntime({
      cacheRoot: process.env.QWEN_CACHE_ROOT,
      cacheLock: { staleMs: 80, waitMs: 5000 },
      fetchImpl: async () => { throw new Error('unexpected register') },
    })
    const result = await runtime.acquireToken(runtime.accountFor(auth))
    process.stdout.write(result.token.sacsft)
  `
  const childEnv = {
    QWEN_RUNTIME_URL: pathToFileURL(path.join(ROOT, "src", "runtime.mjs")).href,
    QWEN_COOKIE_URL: pathToFileURL(path.join(ROOT, "src", "cookie.mjs")).href,
    QWEN_CACHE_ROOT: processTemp,
  }
  const [left, right] = await Promise.all([runNode(childSource, childEnv), runNode(childSource, childEnv)])
  assert.equal(left.code, 0, left.stderr)
  assert.equal(right.code, 0, right.stderr)
  assert.notEqual(left.stdout, right.stdout, "两个进程不得消费同一 token")
  fs.writeFileSync(`${processAccount.file}.lock`, JSON.stringify({ owner: "stale", pid: 999999 }), { mode: 0o600 })
  const old = new Date(Date.now() - 10_000)
  fs.utimesSync(`${processAccount.file}.lock`, old, old)
  const recovered = await runNode(childSource, childEnv)
  assert.equal(recovered.code, 0, recovered.stderr)
  assert.equal(new Set([left.stdout, right.stdout, recovered.stdout]).size, 3, "stale 回收后仍须消费新 token")
  pass("真实双进程 wx 锁、锁内重读、无重放与 stale 锁回收")
} finally {
  fs.rmSync(processTemp, { recursive: true, force: true })
}

console.log(`\n全部 ${checks.length} 组检查通过。未访问真实账号、未安装插件、未修改全局配置。\n`)
