import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { generateKeyPairSync } from "node:crypto"
import { createSmsLoginMethod } from "../src/sms-login.mjs"
import { LOGIN_PAGE_URL, SEND_SMS_PATH, SMS_LOGIN_PATH, ACCOUNT_INFO_URL } from "../src/sms-protocol.mjs"
import { parseCredential } from "../src/cookie.mjs"
import { OFFICIAL_UA } from "../src/constants.mjs"
import { QwenAppAuthPlugin } from "../index.mjs"

const MOBILE = "19900000000"
const OTP = ["654", "321"].join("")
const fixture = (name) => readFileSync(new URL(`../reference/fixtures/${name}`, import.meta.url), "utf8")
const jsonFixture = (name) => JSON.parse(fixture(name))

function cookies(headers, values) {
  for (const value of values) headers.append("set-cookie", value)
  return headers
}

function pageResponse() {
  return new Response(fixture("login-page.html"), {
    headers: cookies(new Headers({ "content-type": "text/html" }), [
      "XSRF-TOKEN=synthetic-cookie-xsrf; Path=/havanaone; HttpOnly",
      "_samesite_flag_=synthetic-flag; Domain=.qianwen.com; Path=/; Secure",
    ]),
  })
}

function jsonResponse(payload, { status = 200, headers = new Headers(), retryAfter = "" } = {}) {
  headers.set("content-type", "application/json")
  if (retryAfter) headers.set("retry-after", retryAfter)
  return new Response(JSON.stringify(payload), { status, headers })
}

function sendResponse(data = {}) {
  const payload = jsonFixture("login-send-success.json")
  payload.content.data = { ...payload.content.data, ...data }
  return jsonResponse(payload)
}

function verifyResponse({ data = {}, cookieTicket = "synthetic-cookie-ticket", hasError = false } = {}) {
  const payload = jsonFixture("login-verify-success.json")
  payload.hasError = hasError
  payload.content.data = { ...payload.content.data, ...data }
  return jsonResponse(payload, {
    headers: cookies(new Headers(), [
      `tongyi_sso_ticket=${cookieTicket}; Domain=.qianwen.com; Path=/; HttpOnly`,
      "tongyi_sso_ticket_hash=synthetic-ticket-hash; Domain=.qianwen.com; Path=/; HttpOnly",
      "XSRF-TOKEN=synthetic-chat-xsrf; Domain=.qianwen.com; Path=/",
    ]),
  })
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

function setup(t) {
  const clock = { now: 1_700_000_000_000 }
  let ids = 0
  const calls = []
  const responders = {
    page: async () => pageResponse(),
    send: async () => sendResponse(),
    login: async () => verifyResponse(),
    info: async () => jsonResponse(jsonFixture("login-info-with-kps.json")),
  }
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(String(input))
    const call = {
      url,
      method: init.method || "GET",
      headers: new Headers(init.headers || {}),
      body: init.body,
      form: new URLSearchParams(init.body || ""),
      signal: init.signal,
    }
    calls.push(call)
    if (url.href === LOGIN_PAGE_URL) return responders.page(call)
    if (url.origin === "https://passport.qianwen.com" && url.pathname === SEND_SMS_PATH) return responders.send(call)
    if (url.origin === "https://passport.qianwen.com" && url.pathname === SMS_LOGIN_PATH) return responders.login(call)
    if (url.href === ACCOUNT_INFO_URL) return responders.info(call)
    throw new Error(`unexpected synthetic URL: ${url.origin}${url.pathname}`)
  }
  const method = createSmsLoginMethod({
    fetchImpl,
    now: () => clock.now,
    uuid: () => `synthetic-uuid-${++ids}`,
    randomBytes: () => Buffer.from("synthetic12B"),
  })
  const count = (kind) => calls.filter((call) => {
    if (kind === "page") return call.url.href === LOGIN_PAGE_URL
    if (kind === "info") return call.url.href === ACCOUNT_INFO_URL
    return call.url.pathname === (kind === "send" ? SEND_SMS_PATH : SMS_LOGIN_PATH)
  }).length
  return { method, calls, responders, clock, count, advance: (ms) => { clock.now += ms } }
}

async function start(method) {
  const prompt = await method.ask({})
  assert.equal(prompt.key, "mobile")
  return prompt
}

async function send(method) {
  await start(method)
  return method.ask({ mobile: MOBILE })
}

async function verified(method) {
  const codePrompt = await send(method)
  assert.equal(codePrompt.key, "sms_code")
  assert.equal(await method.ask({ mobile: MOBILE, sms_code: OTP }), null)
}

function noSecrets(value, { otp = OTP, tokens = [] } = {}) {
  const text = typeof value === "string" ? value : JSON.stringify(value)
  assert.ok(!text.includes(MOBILE), "手机号不得回显")
  assert.ok(!text.includes(otp), "OTP不得回显")
  for (const token of tokens) assert.ok(!text.includes(token), "token不得回显")
}

test("SMS方法契约：type api + 动态ask，手机号/OTP本地校验不发网络", async (t) => {
  const h = setup(t)
  assert.equal(h.method.type, "api")
  assert.equal(typeof h.method.ask, "function")
  assert.equal(typeof h.method.authorize, "function")
  assert.deepEqual(h.method.prompts.map((prompt) => prompt.key), ["mobile", "sms_code"])
  assert.equal(h.method.prompts[1].type, "password")
  assert.equal(h.method.prompts[0].validate(MOBILE), undefined)
  assert.ok(h.method.prompts[0].validate("00000000000"))
  assert.equal(h.method.prompts[1].validate("0"), undefined)
  assert.equal(h.method.prompts[1].validate(OTP), undefined)
  assert.ok(h.method.prompts[1].validate("123"))

  const mobilePrompt = await start(h.method)
  assert.equal(mobilePrompt.type, "text")
  assert.equal(h.calls.length, 0)
  const invalid = await h.method.ask({ mobile: "00000000000" })
  assert.equal(invalid.key, "mobile")
  assert.equal(h.calls.length, 0)
  const codePrompt = await h.method.ask({ mobile: MOBILE })
  assert.equal(codePrompt.key, "sms_code")
  const before = h.calls.length
  const invalidOtp = await h.method.ask({ mobile: MOBILE, sms_code: "123" })
  assert.equal(invalidOtp.key, "sms_code")
  assert.equal(h.calls.length, before)
})

test("L-02 send含codeLength=6而login不包含codeLength", async (t) => {
  const h = setup(t)
  await send(h.method)
  const sendCall = h.calls.find((call) => call.url.pathname === SEND_SMS_PATH)
  assert.equal(sendCall.form.get("codeLength"), "6")
  assert.equal(await h.method.ask({ mobile: MOBILE, sms_code: OTP }), null)
  const loginCall = h.calls.find((call) => call.url.pathname === SMS_LOGIN_PATH)
  assert.equal(loginCall.form.has("codeLength"), false)
  assert.equal((await h.method.authorize({})).type, "success")
})

test("O-04a RSA分支send/login同时携带空loginId与非空loginId2", async (t) => {
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
  const jwk = publicKey.export({ format: "jwk" })
  const modulus = Buffer.from(jwk.n, "base64url").toString("hex")
  const exponent = Buffer.from(jwk.e, "base64url").toString("hex")
  const html = fixture("login-page.html").replace(
    '"smsCodeLength": 6,',
    `"smsCodeLength": 6, "rsaModulusSec": "${modulus}", "rsaExponentSec": "${exponent}",`,
  )
  const h = setup(t)
  h.responders.page = async () => {
    const base = pageResponse()
    return new Response(html, { headers: base.headers })
  }
  await send(h.method)
  const sendCall = h.calls.find((call) => call.url.pathname === SEND_SMS_PATH)
  assert.equal(sendCall.form.has("loginId"), true)
  assert.equal(sendCall.form.get("loginId"), "")
  assert.equal(sendCall.form.has("loginId2"), true)
  assert.ok(sendCall.form.get("loginId2").length > 100)
  assert.equal(await h.method.ask({ mobile: MOBILE, sms_code: OTP }), null)
  const loginCall = h.calls.find((call) => call.url.pathname === SMS_LOGIN_PATH)
  assert.equal(loginCall.form.has("loginId"), true)
  assert.equal(loginCall.form.get("loginId"), "")
  assert.equal(loginCall.form.get("loginId2").length > 100, true)
  assert.equal((await h.method.authorize({})).type, "success")
})

test("SMS完整流程：双CSRF/Cookie/smsToken/contextToken、native保存、authorize零网络且防重放", async (t) => {
  const h = setup(t)
  const codePrompt = await send(h.method)
  assert.equal(codePrompt.type, "password")
  assert.equal(h.count("page"), 1)
  assert.equal(h.count("send"), 1)
  const sendCall = h.calls.find((call) => call.url.pathname === SEND_SMS_PATH)
  assert.equal(sendCall.method, "POST")
  assert.equal(sendCall.headers.get("user-agent"), OFFICIAL_UA)
  assert.equal(sendCall.headers.get("x-xsrf-token"), "synthetic-cookie-xsrf")
  assert.match(sendCall.headers.get("cookie"), /XSRF-TOKEN=synthetic-cookie-xsrf/)
  assert.equal(sendCall.form.get("_csrf"), "synthetic-form-csrf-value")
  assert.notEqual(sendCall.form.get("_csrf"), sendCall.headers.get("x-xsrf-token"))
  assert.equal(sendCall.form.get("loginId"), MOBILE)
  assert.equal(sendCall.form.has("loginId"), true)
  assert.equal(sendCall.form.has("loginId2"), true)
  assert.equal(sendCall.form.get("loginId2"), "")
  assert.equal(sendCall.form.get("phoneCode"), "86")
  assert.equal(sendCall.form.get("countryCode"), "CN")
  assert.equal(sendCall.form.get("codeLength"), "6")
  assert.equal(sendCall.form.get("contextToken"), "synthetic-context-token")

  assert.equal(await h.method.ask({ mobile: MOBILE, sms_code: OTP }), null)
  const loginCall = h.calls.find((call) => call.url.pathname === SMS_LOGIN_PATH)
  assert.equal(loginCall.form.get("smsCode"), OTP)
  assert.equal(loginCall.form.get("loginId"), MOBILE)
  assert.equal(loginCall.form.has("loginId2"), true)
  assert.equal(loginCall.form.get("loginId2"), "")
  assert.equal(loginCall.form.get("smsToken"), "synthetic-sms-token")
  assert.equal(loginCall.form.get("contextToken"), "synthetic-context-token")
  assert.equal(loginCall.form.get("keepLogin"), "false")
  const infoCall = h.calls.find((call) => call.url.href === ACCOUNT_INFO_URL)
  assert.equal(infoCall.method, "GET")
  assert.match(infoCall.headers.get("cookie"), /tongyi_sso_ticket=synthetic-cookie-ticket/)
  assert.equal(h.calls.every((call) => call.headers.get("user-agent") === OFFICIAL_UA), true)

  const beforeAuthorize = h.calls.length
  assert.equal(await h.method.ask({ mobile: MOBILE, sms_code: OTP }), null, "verified ask重放不得再联网")
  assert.equal(h.calls.length, beforeAuthorize)
  const result = await h.method.authorize({ mobile: MOBILE, sms_code: OTP })
  assert.equal(result.type, "success")
  assert.equal(h.calls.length, beforeAuthorize)
  const parsed = parseCredential(result.key)
  assert.equal(parsed.native.serviceTicket, "synthetic-service-ticket")
  assert.equal(parsed.native.kpsWg, "synthetic-kps-wg")
  assert.equal(parsed.native.uId, "1000000000000000001")
  assert.equal(parsed.native.nickname, "synthetic-nickname")
  noSecrets({ accountId: result.accountId, metadata: result.metadata, uid: result.uid }, { tokens: ["synthetic-sms-token", "synthetic-context-token"] })

  const plainAnswers = [
    { type: "text", key: "mobile", value: MOBILE },
    { type: "password", key: "sms_code", value: OTP },
  ].filter((answer) => answer.type === "select")
  assert.deepEqual(plainAnswers, [])
  const hostRecord = { type: "api", key: result.key, metadata: result.metadata }
  assert.equal(hostRecord.type, "api")
  assert.equal(Object.hasOwn(hostRecord, "uid"), false)
  assert.equal(Object.hasOwn(hostRecord, "accountId"), false)
  noSecrets(hostRecord, { tokens: ["synthetic-sms-token", "synthetic-context-token", "synthetic-form-csrf-value", "synthetic-cookie-xsrf"] })

  const replay = await h.method.authorize({ mobile: MOBILE, sms_code: OTP })
  assert.equal(replay.type, "failed")
  noSecrets(replay)
  assert.equal(h.calls.length, beforeAuthorize)
})

test("SMS手机号形状nickname改为本次登录手机号的脱敏形式，不进入metadata/accountId", async (t) => {
  const h = setup(t)
  h.responders.info = async () => {
    const payload = jsonFixture("login-info-with-kps.json")
    payload.data.userNick = MOBILE
    return jsonResponse(payload)
  }
  await verified(h.method)
  const result = await h.method.authorize({ mobile: MOBILE, sms_code: OTP })
  assert.equal(result.type, "success")
  assert.notEqual(result.accountId, MOBILE)
  // 账号名用本次登录手机号的脱敏形式，既可与其它账号区分，又不泄露完整号码。
  assert.equal(result.accountId, "199****0000")
  assert.match(result.accountId, /^\d{3}\*{4}\d{4}$/)
  noSecrets({ accountId: result.accountId, metadata: result.metadata })
})

test("SMS发送HTTP200但无smsToken或要求风险验证码都不能成功/换票", async (t) => {
  for (const data of [
    { smsToken: "", titleMsg: "synthetic send missing token" },
    { isCheckCodeShowed: true, titleMsg: "synthetic captcha" },
  ]) {
    const h = setup(t)
    h.responders.send = async () => sendResponse(data)
    const prompt = await send(h.method)
    assert.equal(prompt.key, "mobile")
    assert.equal(h.count("login"), 0)
    const result = await h.method.authorize({ mobile: MOBILE })
    assert.equal(result.type, "failed")
    noSecrets(result)
  }
})

test("SMS发送错误正文中的手机号/smsToken被脱敏", async (t) => {
  const h = setup(t)
  const token = "synthetic-send-response-secret"
  h.responders.send = async () => sendResponse({ hasError: true, smsToken: token, titleMsg: `synthetic failure ${MOBILE} ${token}` })
  const prompt = await send(h.method)
  assert.equal(prompt.key, "mobile")
  noSecrets(prompt, { tokens: [token] })
  const result = await h.method.authorize({ mobile: MOBILE })
  assert.equal(result.type, "failed")
  noSecrets(result, { tokens: [token] })
})

test("O-02 login外层错误/风险/恶意redirect不得进入info或native保存", async (t) => {
  const cases = [
    { hasError: true, data: { resultCode: 100 }, secret: "synthetic-outer-error" },
    { data: { isCheckCodeShowed: true }, secret: "synthetic-risk" },
    { data: { redirect: true, redirectUrl: "https://evil.invalid/desktop-app?ticket=synthetic-redirect-secret" }, secret: "synthetic-redirect-secret" },
    { data: { redirect: true, redirectUrl: "https://www.qianwen.com.evil.invalid/desktop-app" }, secret: "synthetic-host-suffix" },
    { data: { redirect: true, redirectUrl: "http://www.qianwen.com/desktop-app" }, secret: "synthetic-http-redirect" },
  ]
  for (const item of cases) {
    const h = setup(t)
    h.responders.login = async () => verifyResponse(item)
    await send(h.method)
    const prompt = await h.method.ask({ mobile: MOBILE, sms_code: OTP })
    if (prompt !== null) {
      assert.equal(prompt.key, "sms_code")
      noSecrets(prompt, { tokens: [item.secret] })
    }
    assert.equal(h.count("info"), 0, JSON.stringify(item.data))
    const result = await h.method.authorize({ mobile: MOBILE, sms_code: OTP })
    assert.equal(result.type, "failed")
    assert.equal(Object.hasOwn(result, "key"), false)
    noSecrets(result, { tokens: [item.secret] })
  }
})

test("SMS OTP错误最多5次，提示脱敏且最终关闭flow", async (t) => {
  const h = setup(t)
  h.responders.login = async () => jsonResponse({ hasError: true, content: { data: { hasError: true, titleMsg: `synthetic invalid ${MOBILE} ${OTP} synthetic-sms-token` } } })
  await send(h.method)
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const prompt = await h.method.ask({ mobile: MOBILE, sms_code: OTP })
    if (attempt < 5) {
      assert.equal(prompt.key, "sms_code")
      noSecrets(prompt, { tokens: ["synthetic-sms-token"] })
    } else assert.equal(prompt, null)
  }
  assert.equal(h.count("login"), 5)
  assert.equal(h.count("info"), 0)
  const before = h.calls.length
  const result = await h.method.authorize({ mobile: MOBILE, sms_code: OTP })
  assert.equal(result.type, "failed")
  noSecrets(result, { tokens: ["synthetic-sms-token"] })
  assert.equal(h.calls.length, before)
})

test("SMS state过期或ticket已消费立即关闭，不能继续OTP重放", async (t) => {
  for (const message of ["synthetic state expired", "synthetic ticket consumed"]) {
    const h = setup(t)
    h.responders.login = async () => jsonResponse({ hasError: true, content: { data: { hasError: true, titleMsg: message } } })
    await send(h.method)
    assert.equal(await h.method.ask({ mobile: MOBILE, sms_code: OTP }), null, message)
    assert.equal(h.count("login"), 1)
    assert.equal(await h.method.ask({ mobile: MOBILE, sms_code: OTP }), null)
    assert.equal(h.count("login"), 1)
    const result = await h.method.authorize({ mobile: MOBILE, sms_code: OTP })
    assert.equal(result.type, "failed")
    noSecrets(result)
  }
})

test("SMS重发遵守60秒冷却、最多3次并原子轮换token/context", async (t) => {
  const h = setup(t)
  h.responders.send = async () => sendResponse({ smsToken: `synthetic-sms-token-${h.count("send")}` })
  await send(h.method)
  let prompt = await h.method.ask({ mobile: MOBILE, sms_code: "0" })
  assert.equal(prompt.key, "sms_code")
  assert.match(prompt.message, /60 秒/)
  assert.equal(h.count("send"), 1)

  h.advance(60_000)
  prompt = await h.method.ask({ mobile: MOBILE, sms_code: "0" })
  assert.match(prompt.message, /已重发/)
  assert.equal(h.count("send"), 2)
  h.advance(60_000)
  await h.method.ask({ mobile: MOBILE, sms_code: "0" })
  assert.equal(h.count("send"), 3)
  h.advance(60_000)
  assert.equal(await h.method.ask({ mobile: MOBILE, sms_code: "0" }), null)
  assert.equal(h.count("send"), 3)
  const result = await h.method.authorize({ mobile: MOBILE, sms_code: "0" })
  assert.equal(result.type, "failed")
})

test("O-05 重发只更新smsToken，响应不得轮换页面contextToken/_csrf", async (t) => {
  const h = setup(t)
  h.responders.send = async () => sendResponse({
    smsToken: `synthetic-sms-token-${h.count("send")}`,
    contextToken: `synthetic-rotated-context-${h.count("send")}`,
    _csrf: `synthetic-rotated-csrf-${h.count("send")}`,
  })
  await send(h.method)
  h.advance(60_000)
  await h.method.ask({ mobile: MOBILE, sms_code: "0" })
  assert.equal(await h.method.ask({ mobile: MOBILE, sms_code: OTP }), null)
  const login = h.calls.find((call) => call.url.pathname === SMS_LOGIN_PATH)
  assert.equal(login.form.get("smsToken"), "synthetic-sms-token-2")
  assert.equal(login.form.get("contextToken"), "synthetic-context-token")
  assert.equal(login.form.get("_csrf"), "synthetic-form-csrf-value")
})

test("SMS初始发送429必须尊重Retry-After，不能靠重复提交mobile绕过", async (t) => {
  const h = setup(t)
  h.responders.send = async () => jsonResponse({ content: { data: { titleMsg: `synthetic rate limit ${MOBILE}` } } }, { status: 429, retryAfter: "120" })
  const prompt = await send(h.method)
  assert.equal(prompt.key, "mobile")
  noSecrets(prompt)
  assert.equal(h.count("send"), 1)
  h.advance(61_000)
  const cooling = await h.method.ask({ mobile: MOBILE })
  assert.equal(cooling.key, "mobile")
  assert.match(cooling.message, /冷却|等待|120|59/)
  assert.equal(h.count("send"), 1)
  h.advance(60_000)
  await h.method.ask({ mobile: MOBILE })
  assert.equal(h.count("send"), 2)
})

test("L-01a send HTTP-date Retry-After=120秒且新flow不能绕过，届满才允许第二次send", async (t) => {
  const h = setup(t)
  let limited = true
  h.responders.send = async () => {
    if (limited) {
      limited = false
      return jsonResponse({ content: { data: { titleMsg: `synthetic date limit ${MOBILE}` } } }, { status: 429, retryAfter: new Date(h.clock.now + 120_000).toUTCString() })
    }
    return sendResponse()
  }
  const limitedPrompt = await send(h.method)
  assert.equal(limitedPrompt.key, "mobile")
  assert.match(limitedPrompt.message, /120 秒/)
  noSecrets(limitedPrompt)
  assert.equal(h.count("send"), 1)

  const beforeNewFlow = h.calls.length
  await start(h.method)
  const blocked = await h.method.ask({ mobile: MOBILE })
  assert.equal(blocked.key, "mobile")
  assert.match(blocked.message, /冷却|等待|120/)
  assert.equal(h.calls.length, beforeNewFlow)
  h.advance(119_000)
  await h.method.ask({ mobile: MOBILE })
  assert.equal(h.calls.length, beforeNewFlow)
  h.advance(1_000)
  const accepted = await h.method.ask({ mobile: MOBILE })
  assert.equal(accepted.key, "sms_code")
  assert.equal(h.count("send"), 2)
})

test("L-01b verify 429冷却跨新flow仍禁止send，不能换state清掉", async (t) => {
  const h = setup(t)
  await send(h.method)
  h.advance(60_000)
  h.responders.login = async () => jsonResponse({ content: { data: { titleMsg: "synthetic verify cross-flow limit" } } }, { status: 429, retryAfter: "120" })
  const limited = await h.method.ask({ mobile: MOBILE, sms_code: OTP })
  assert.equal(limited.key, "sms_code")
  assert.equal(h.count("login"), 1)
  const beforeNewFlow = h.calls.length
  await start(h.method)
  const blocked = await h.method.ask({ mobile: MOBILE })
  assert.equal(blocked.key, "mobile")
  assert.match(blocked.message, /冷却|等待|120/)
  assert.equal(h.calls.length, beforeNewFlow)
  h.advance(120_000)
  const accepted = await h.method.ask({ mobile: MOBILE })
  assert.equal(accepted.key, "sms_code")
  assert.equal(h.count("send"), 2)
})

test("O-03 verify 429 Retry-After同时约束立即verify与resend，120秒后才放行", async (t) => {
  for (const action of ["verify", "resend"]) {
    const h = setup(t)
    await send(h.method)
    h.advance(60_000)
    let limited = true
    h.responders.login = async () => {
      if (limited) { limited = false; return jsonResponse({ content: { data: { titleMsg: `synthetic verify limit ${MOBILE}` } } }, { status: 429, retryAfter: "120" }) }
      return verifyResponse()
    }
    const limitedPrompt = await h.method.ask({ mobile: MOBILE, sms_code: OTP })
    assert.equal(limitedPrompt.key, "sms_code")
    noSecrets(limitedPrompt)
    assert.equal(h.count("login"), 1)

    const immediateResend = await h.method.ask({ mobile: MOBILE, sms_code: "0" })
    assert.equal(immediateResend.key, "sms_code")
    assert.match(immediateResend.message, /冷却|等待|120/)
    assert.equal(h.count("send"), 1, action)
    const immediateVerify = await h.method.ask({ mobile: MOBILE, sms_code: OTP })
    assert.equal(immediateVerify.key, "sms_code")
    assert.equal(h.count("login"), 1, action)

    h.advance(119_000)
    await h.method.ask({ mobile: MOBILE, sms_code: "0" })
    await h.method.ask({ mobile: MOBILE, sms_code: OTP })
    assert.equal(h.count("send"), 1, action)
    assert.equal(h.count("login"), 1, action)
    h.advance(1_000)
    if (action === "resend") {
      const resent = await h.method.ask({ mobile: MOBILE, sms_code: "0" })
      assert.match(resent.message, /已重发/)
      assert.equal(h.count("send"), 2)
      assert.equal(await h.method.ask({ mobile: MOBILE, sms_code: OTP }), null)
    } else {
      assert.equal(await h.method.ask({ mobile: MOBILE, sms_code: OTP }), null)
      assert.equal(h.count("login"), 2)
      assert.equal(h.count("send"), 1)
    }
    assert.equal((await h.method.authorize({})).type, "success")
  }
})

async function settleTimeout(t, promise) {
  for (let index = 0; index < 3; index += 1) {
    t.mock.timers.tick(15_000)
    await new Promise((resolve) => setImmediate(resolve))
  }
  return promise
}

function hangingResponse(_call, signal) {
  return new Promise((_, reject) => {
    if (signal.aborted) reject(signal.reason)
    else signal.addEventListener("abort", () => reject(signal.reason), { once: true })
  })
}

test("SMS发送/重发/验证各有15秒deadline，错误不泄漏输入", async (t) => {
  for (const stage of ["send", "resend", "verify"]) {
    t.mock.timers.enable({ apis: ["setTimeout"] })
    const h = setup(t)
    await send(h.method)
    let pending
    if (stage === "send") {
      const fresh = setup(t)
      fresh.responders.send = (call) => hangingResponse(call, call.signal)
      await start(fresh.method)
      pending = fresh.method.ask({ mobile: MOBILE })
      const prompt = await settleTimeout(t, pending)
      assert.equal(prompt.key, "mobile")
      noSecrets(prompt)
      t.mock.timers.reset()
      continue
    }
    if (stage === "resend") {
      h.responders.send = (call) => hangingResponse(call, call.signal)
      h.advance(60_000)
      pending = h.method.ask({ mobile: MOBILE, sms_code: "0" })
    } else {
      h.responders.login = (call) => hangingResponse(call, call.signal)
      pending = h.method.ask({ mobile: MOBILE, sms_code: OTP })
    }
    const prompt = await settleTimeout(t, pending)
    assert.equal(prompt.key, "sms_code")
    noSecrets(prompt, { tokens: ["synthetic-sms-token"] })
    t.mock.timers.reset()
  }
})

test("SMS 10分钟总寿命到期后不再验证或保存", async (t) => {
  const h = setup(t)
  await send(h.method)
  h.advance(600_001)
  assert.equal(await h.method.ask({ mobile: MOBILE, sms_code: OTP }), null)
  assert.equal(h.count("login"), 0)
  const result = await h.method.authorize({ mobile: MOBILE, sms_code: OTP })
  assert.equal(result.type, "failed")
  assert.match(result.error, /10 分钟|过期|未完成/)
  noSecrets(result)
})

test("SMS旧代次迟到发送不得覆盖新flow", async (t) => {
  const h = setup(t)
  const oldSend = deferred()
  let first = true
  h.responders.send = async () => {
    if (first) { first = false; return oldSend.promise }
    return sendResponse({ smsToken: "synthetic-new-sms-token" })
  }
  await start(h.method)
  const oldPending = h.method.ask({ mobile: MOBILE })
  await new Promise((resolve) => setImmediate(resolve))
  await start(h.method)
  oldSend.resolve(sendResponse({ smsToken: "synthetic-old-sms-token" }))
  assert.equal(await oldPending, null)
  await h.method.ask({ mobile: MOBILE })
  assert.equal(await h.method.ask({ mobile: MOBILE, sms_code: OTP }), null)
  const login = h.calls.find((call) => call.url.pathname === SMS_LOGIN_PATH)
  assert.equal(login.form.get("smsToken"), "synthetic-new-sms-token")
  assert.notEqual(login.form.get("smsToken"), "synthetic-old-sms-token")
  assert.equal((await h.method.authorize({ mobile: MOBILE, sms_code: OTP })).type, "success")
})

test("SMS旧代次迟到验证不得覆盖新verified快照", async (t) => {
  const h = setup(t)
  const oldLogin = deferred()
  let first = true
  h.responders.login = async () => {
    if (first) { first = false; return oldLogin.promise }
    return verifyResponse({ cookieTicket: "synthetic-new-cookie-ticket" })
  }
  await send(h.method)
  const oldPending = h.method.ask({ mobile: MOBILE, sms_code: OTP })
  await new Promise((resolve) => setImmediate(resolve))
  await start(h.method)
  oldLogin.resolve(verifyResponse({ cookieTicket: "synthetic-old-cookie-ticket" }))
  assert.equal(await oldPending, null)
  await h.method.ask({ mobile: MOBILE })
  assert.equal(await h.method.ask({ mobile: MOBILE, sms_code: OTP }), null)
  const result = await h.method.authorize({ mobile: MOBILE, sms_code: OTP })
  assert.equal(result.type, "success")
  assert.match(result.key, /synthetic-service-ticket/)
  assert.doesNotMatch(result.key, /synthetic-old-cookie-ticket/)
  assert.equal((await h.method.authorize({ mobile: MOBILE, sms_code: OTP })).type, "failed")
})

test("SMS authorize取消消费快照且零网络，重放不能成功", async (t) => {
  const h = setup(t)
  await verified(h.method)
  const before = h.calls.length
  const controller = new AbortController()
  controller.abort()
  const cancelled = await h.method.authorize({ mobile: MOBILE, sms_code: OTP }, { signal: controller.signal })
  assert.equal(cancelled.type, "failed")
  assert.match(cancelled.error, /取消/)
  assert.equal(h.calls.length, before)
  assert.equal((await h.method.authorize({ mobile: MOBILE, sms_code: OTP })).type, "failed")
  assert.equal(h.calls.length, before)
})

test("SMS缺userId只能失败，纯Web Cookie不得被authorize保存", async (t) => {
  const h = setup(t)
  h.responders.info = async () => {
    const payload = jsonFixture("login-info-with-kps.json")
    delete payload.data.userId
    return jsonResponse(payload)
  }
  await send(h.method)
  assert.equal(await h.method.ask({ mobile: MOBILE, sms_code: OTP }), null)
  const before = h.calls.length
  const result = await h.method.authorize({ mobile: MOBILE, sms_code: OTP })
  assert.equal(result.type, "failed")
  assert.match(result.error, /native|Web 会话/)
  assert.equal(Object.hasOwn(result, "key"), false)
  noSecrets(result)
  assert.equal(h.calls.length, before)
})

test("SMS无快照authorize立即失败且零网络；index第三方法无QR/浏览器/API Key问题", async (t) => {
  const h = setup(t)
  const result = await h.method.authorize({ mobile: MOBILE, sms_code: OTP })
  assert.equal(result.type, "failed")
  assert.equal(h.calls.length, 0)
  noSecrets(result)

  const originalFetch = globalThis.fetch
  globalThis.fetch = () => { throw new Error("plugin factory/authorize shape must not fetch") }
  t.after(() => { globalThis.fetch = originalFetch })
  const plugin = await QwenAppAuthPlugin()
  const sms = plugin.auth.methods.find((method) => method.label.includes("短信"))
  assert.ok(sms)
  assert.equal(sms.type, "api")
  assert.ok(sms.prompts.length > 0)
  assert.equal(typeof sms.ask, "function")
  assert.equal(typeof sms.authorize, "function")
  assert.equal(sms.prompts.some((prompt) => /api.?key/i.test(`${prompt.key} ${prompt.message}`)), false)
  assert.doesNotMatch(JSON.stringify(sms.prompts), /QR|二维码|browser|浏览器|oauth/i)
  assert.equal((await sms.authorize({ mobile: MOBILE, sms_code: OTP })).type, "failed")
})
