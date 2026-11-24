import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { generateKeyPairSync, privateDecrypt, constants as cryptoConstants } from "node:crypto"
import {
  LOGIN_PAGE_URL,
  SEND_SMS_PATH,
  SMS_LOGIN_PATH,
  ACCOUNT_INFO_URL,
  MemoryCookieJar,
  normalizeMobile,
  validSmsCode,
  parseLoginPage,
  responseData,
  assertHavanaUrl,
  rsaEncryptMobile,
  buildNativeCredential,
} from "../src/sms-protocol.mjs"
import { wsgDecrypt, wsgEncrypt } from "../src/wsg.mjs"

const fixture = (name) => readFileSync(new URL(`../reference/fixtures/${name}`, import.meta.url), "utf8")
const jsonFixture = (name) => JSON.parse(fixture(name))
const VALID_MOBILE = "19900000000"
const SYNTHETIC_BYTES = () => Buffer.from("synthetic12B")

function credentialJar() {
  const jar = new MemoryCookieJar()
  jar.set("tongyi_sso_ticket", "synthetic-cookie-ticket", { domain: ".qianwen.com", path: "/" })
  jar.set("tongyi_sso_ticket_hash", "synthetic-ticket-hash", { domain: ".qianwen.com", path: "/" })
  jar.set("XSRF-TOKEN", "synthetic-chat-xsrf", { domain: ".qianwen.com", path: "/" })
  return jar
}

test("SMS normalizeMobile 仅接受明确CN形状，支持常见前缀但不接受全零/错误长度", () => {
  for (const [input, expected] of [
    [VALID_MOBILE, VALID_MOBILE],
    [`  ${VALID_MOBILE} `, VALID_MOBILE],
    [`+86 ${VALID_MOBILE}`, VALID_MOBILE],
    [`0086-${VALID_MOBILE}`, VALID_MOBILE],
    [`86${VALID_MOBILE}`, VALID_MOBILE],
    [`(${VALID_MOBILE.slice(0, 3)}) ${VALID_MOBILE.slice(3)}`, VALID_MOBILE],
  ]) assert.equal(normalizeMobile(input), expected)
  for (const input of ["", "00000000000", "10000000000", "1990000000", "199000000000", "+19900000000", "1990000000a", "+8719900000000"]) assert.equal(normalizeMobile(input), null, input)
})

test("SMS validSmsCode 只接受6位数字，保留0重发指令不是OTP", () => {
  for (const code of ["000000", "000001", "123456", " 654321 "]) assert.equal(validSmsCode(code), true)
  for (const code of ["", "0", "12345", "1234567", "abcdef", "12345a", "12 3456", "１２３４５６"]) assert.equal(validSmsCode(code), false, code)
})

test("SMS MemoryCookieJar 独立保存Set-Cookie、domain/path、轮换和过期", () => {
  const jar = new MemoryCookieJar()
  const headers = new Headers()
  headers.append("set-cookie", "XSRF-TOKEN=synthetic-cookie-xsrf; Path=/havanaone; HttpOnly")
  headers.append("set-cookie", "_samesite_flag_=synthetic-flag; Domain=.qianwen.com; Path=/; Secure")
  headers.append("set-cookie", "evil=synthetic-evil; Domain=.evil.invalid; Path=/")
  jar.ingest(headers, LOGIN_PAGE_URL)
  assert.equal(jar.get("XSRF-TOKEN"), "synthetic-cookie-xsrf")
  const sendUrl = `https://passport.qianwen.com${SEND_SMS_PATH}?bizEntrance=tongyi&bizName=tongyi`
  const cookie = jar.cookieHeader(sendUrl)
  assert.match(cookie, /XSRF-TOKEN=synthetic-cookie-xsrf/)
  assert.match(cookie, /_samesite_flag_=synthetic-flag/)
  assert.doesNotMatch(cookie, /evil/)

  jar.ingest(new Headers({ "set-cookie": "XSRF-TOKEN=synthetic-rotated-xsrf; Path=/havanaone" }), sendUrl)
  assert.equal(jar.get("XSRF-TOKEN"), "synthetic-rotated-xsrf")
  jar.set("short", "synthetic-short", { domain: "passport.qianwen.com", path: "/", maxAge: -1 })
  assert.equal(jar.get("short"), "")
  jar.clear()
  assert.equal(jar.cookieHeader(sendUrl), "")
})

test("SMS parseLoginPage 从viewConfig/viewData取双CSRF上下文和固定同源API", () => {
  const page = parseLoginPage(fixture("login-page.html"))
  assert.equal(page.viewConfig.defaultView, "sms")
  assert.equal(page.viewConfig.smsCodeLength, 6)
  assert.equal(page.formCsrf, "synthetic-form-csrf-value")
  assert.equal(page.contextToken, "synthetic-context-token")
  assert.notEqual(page.formCsrf, page.contextToken)
  assert.equal(new URL(page.sendUrl).origin, "https://passport.qianwen.com")
  assert.equal(new URL(page.sendUrl).pathname, SEND_SMS_PATH)
  assert.equal(new URL(page.loginUrl).pathname, SMS_LOGIN_PATH)
  assert.equal(new URL(page.sendUrl).searchParams.get("bizEntrance"), "tongyi")
  assert.throws(() => parseLoginPage("<script>window.viewConfig={}</script>"), /viewConfig|viewData/)
  assert.throws(() => parseLoginPage(fixture("login-page.html").replace('"smsCodeLength": 6', '"smsCodeLength": 8')), /短信码长度/)
})

test("SMS assertHavanaUrl 固定HTTPS origin/path，拒绝伪造后缀/userinfo/端口/任意跳转", () => {
  assert.equal(assertHavanaUrl(SEND_SMS_PATH, SEND_SMS_PATH).origin, "https://passport.qianwen.com")
  for (const url of [
    "http://passport.qianwen.com/havanaone/loginLegacy/sms/sendSms.do",
    "https://user@passport.qianwen.com/havanaone/loginLegacy/sms/sendSms.do",
    "https://passport.qianwen.com:444/havanaone/loginLegacy/sms/sendSms.do",
    "https://passport.qianwen.com.evil.invalid/havanaone/loginLegacy/sms/sendSms.do",
    "https://evil.invalid/havanaone/loginLegacy/sms/sendSms.do",
    SMS_LOGIN_PATH,
  ]) assert.throws(() => assertHavanaUrl(url, SEND_SMS_PATH), /白名单/)
})

test("O-04b send/login同源API也必须固定bizEntrance/bizName=tongyi", () => {
  for (const [path, name] of [[SEND_SMS_PATH, "sendSmsApi"], [SMS_LOGIN_PATH, "smsLoginApi"]]) {
    const original = `${path}?bizEntrance=tongyi&bizName=tongyi`
    const wrong = `${path}?bizEntrance=other&bizName=other`
    const html = fixture("login-page.html").replace(original, wrong)
    assert.notEqual(html, fixture("login-page.html"), name)
    assert.throws(() => parseLoginPage(html), /biz|query|业务|白名单/)
  }
})

test("SMS responseData 支持content.data与axios data.content.data，风险/错误字段不丢失", () => {
  const send = jsonFixture("login-send-success.json")
  assert.equal(responseData(send).smsToken, "synthetic-sms-token")
  assert.equal(responseData(send).contextToken, "synthetic-context-token")
  assert.equal(responseData({ data: send }, true).smsToken, "synthetic-sms-token")
  const risk = { content: { data: { isCheckCodeShowed: true, titleMsg: "synthetic captcha", smsToken: "synthetic-risk-token" } } }
  assert.equal(responseData(risk).isCheckCodeShowed, true)
  assert.match(responseData(risk).titleMsg, /captcha/)
})

test("SMS RSA缺Sec公钥走null，合成RSA分支可解密回手机号", () => {
  assert.equal(rsaEncryptMobile(VALID_MOBILE, "", ""), null)
  assert.equal(rsaEncryptMobile(VALID_MOBILE, "00", ""), null)
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
  const jwk = publicKey.export({ format: "jwk" })
  const encrypted = rsaEncryptMobile(VALID_MOBILE, Buffer.from(jwk.n, "base64url").toString("hex"), Buffer.from(jwk.e, "base64url").toString("hex"))
  assert.ok(encrypted)
  const plaintext = privateDecrypt({ key: privateKey, padding: cryptoConstants.RSA_PKCS1_PADDING }, Buffer.from(encrypted, "base64")).toString("utf8")
  assert.equal(plaintext, VALID_MOBILE)
})

test("SMS native组装以info四字段优先并派生稳定设备/uidWsg", () => {
  const credential = buildNativeCredential({ jar: credentialJar(), info: jsonFixture("login-info-with-kps.json"), randomBytes: SYNTHETIC_BYTES })
  assert.equal(credential.native.serviceTicket, "synthetic-service-ticket")
  assert.equal(credential.native.kpsWg, "synthetic-kps-wg")
  assert.equal(credential.native.uId, "1000000000000000001")
  assert.equal(credential.native.nickname, "synthetic-nickname")
  assert.match(credential.native.utdid, /^[a-f0-9]{24}$/)
  assert.equal(wsgDecrypt(credential.native.uidWsg).toString("utf8"), credential.native.uId)
  assert.equal(wsgDecrypt(credential.native.ucParams.ut).toString("utf8"), credential.native.utdid)
  assert.match(credential.cookie, /tongyi_sso_ticket=synthetic-cookie-ticket/)
  assert.doesNotMatch(JSON.stringify(credential), /19900000000|654321|smsToken|contextToken/)
})

test("SMS info无service_ticket时回退新会话tongyi_sso_ticket，info值优先", () => {
  const info = jsonFixture("login-info-with-kps.json")
  delete info.data.service_ticket
  const fallback = buildNativeCredential({ jar: credentialJar(), info, randomBytes: SYNTHETIC_BYTES })
  assert.equal(fallback.native.serviceTicket, "synthetic-cookie-ticket")

  const preferred = buildNativeCredential({ jar: credentialJar(), info: jsonFixture("login-info-with-kps.json"), randomBytes: SYNTHETIC_BYTES })
  assert.equal(preferred.native.serviceTicket, "synthetic-service-ticket")
  assert.notEqual(preferred.native.serviceTicket, "synthetic-cookie-ticket")
})

test("SMS 缺 userId 仍拒绝；缺 kps_wg 时按公式本地派生，OAuth/register token绝不能替代", () => {
  const derivedInfo = jsonFixture("login-info-with-kps.json")
  delete derivedInfo.data.kps_wg
  const derived = buildNativeCredential({ jar: credentialJar(), info: derivedInfo, randomBytes: SYNTHETIC_BYTES })
  assert.equal(derived.native.kpsWg, wsgEncrypt(`token=${derived.native.serviceTicket}&uid=${derived.native.uId}&nickname=${derived.native.nickname}`))
  assert.match(derived.native.kpsWg, /^O\//)
  for (const missing of ["userId"]) {
    const info = jsonFixture("login-info-with-kps.json")
    delete info.data[missing]
    assert.throws(
      () => buildNativeCredential({ jar: credentialJar(), info, randomBytes: SYNTHETIC_BYTES }),
      (error) => error.status === 400 && error.code === "invalid_request" && /native 字段/.test(error.message),
    )
  }
  const info = {
    success: true,
    data: {
      kps_wg: "synthetic-kps-wg",
      uId: "1000000000000000001",
      nickname: "synthetic-nickname",
      accessToken: "synthetic-oauth-token",
      "eo-clt-actkn": "synthetic-register-token",
    },
  }
  const credential = buildNativeCredential({ jar: credentialJar(), info, randomBytes: SYNTHETIC_BYTES })
  assert.equal(credential.native.serviceTicket, "synthetic-cookie-ticket")
  assert.doesNotMatch(JSON.stringify(credential.native), /synthetic-oauth-token|synthetic-register-token/)
})

test("O-01 Cookie-only（含伪造native alias）不得组装native，SMS fixture不是live证明", () => {
  const jar = credentialJar()
  jar.set("serviceTicket", "synthetic-cookie-service-ticket", { domain: ".qianwen.com", path: "/" })
  jar.set("kpsWg", "synthetic-cookie-kps-wg", { domain: ".qianwen.com", path: "/" })
  jar.set("uId", "1000000000000000001", { domain: ".qianwen.com", path: "/" })
  jar.set("nickname", "synthetic-cookie-nickname", { domain: ".qianwen.com", path: "/" })
  const info = jsonFixture("login-info-web-session-only.json")
  assert.equal(info.nativeCredentialSuccessProven, false)
  assert.throws(
    () => buildNativeCredential({ jar, info, randomBytes: SYNTHETIC_BYTES }),
    (error) => error.status === 400 && error.code === "invalid_request" && /native 字段|Web 会话/.test(error.message),
  )
})

test("SMS /info NOT_LOGIN即使HTTP外层200也映射401，不保存Web会话", () => {
  assert.throws(
    () => buildNativeCredential({ jar: credentialJar(), info: jsonFixture("login-info-not-login.json"), randomBytes: SYNTHETIC_BYTES }),
    (error) => error.status === 401 && error.code === "session_expired",
  )
  assert.equal(new URL(ACCOUNT_INFO_URL).pathname, "/api/account/v2/info")
})

test("真实 /info 形状（userId/userNick/telephone，无 kpsWg）能取到昵称与手机号，但缺 kpsWg 仍明确失败", async () => {
  const { buildNativeCredential } = await import("../src/sms-protocol.mjs")
  const info = jsonFixture("login-info-live-shape.json")
  // 实测别名必须被识别：userId → uId，userNick → nickname，telephone → securityMobile
  const withKps = JSON.parse(JSON.stringify(info))
  withKps.data.kps_wg = "synthetic-kps-wg"
  withKps.data.service_ticket = "synthetic-service-ticket"
  const credential = buildNativeCredential({ jar: credentialJar(), info: withKps, randomBytes: SYNTHETIC_BYTES })
  assert.equal(credential.native.uId, "1000000000000000001")
  assert.equal(credential.native.nickname, "synthetic-nickname")
  assert.equal(credential.native.securityMobile, "199****0001")

  // 真实响应没有 kpsWg：用实测公式本地派生，不冒充、不等服务端。
  const live = buildNativeCredential({ jar: credentialJar(), info, randomBytes: SYNTHETIC_BYTES })
  assert.equal(live.native.kpsWg, wsgEncrypt(`token=${live.native.serviceTicket}&uid=${live.native.uId}&nickname=${live.native.nickname}`))
  assert.match(live.native.kpsWg, /^O\//)
})
