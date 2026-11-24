import test from "node:test"
import assert from "node:assert/strict"
import { assertTrustedUrl, assertSdkChatUrl, headerSafe, redactHeaders, ALLOWED_ENDPOINTS } from "../src/security.mjs"
import { sanitizeText, errorResponse, asErrorResponse, readBounded } from "../src/errors.mjs"
import { securityCacheFile } from "../src/cache.mjs"
import { join } from "node:path"

const CHAT = "https://chat2.qianwen.com/api/v2/chat?synthetic=1"

test("HTTPS host allowlist 精确匹配，拒绝 http/userinfo/伪造后缀/IP/端口/错误 path", () => {
  assert.equal(assertTrustedUrl(CHAT, "chat").hostname, "chat2.qianwen.com")
  assert.equal(assertTrustedUrl("https://chat2.qianwen.com:443/api/v2/chat", "chat").port, "")
  const rejected = [
    "http://chat2.qianwen.com/api/v2/chat",
    "https://user:pass@chat2.qianwen.com/api/v2/chat",
    "https://chat2.qianwen.com.evil.invalid/api/v2/chat",
    "https://evilchat2.qianwen.com/api/v2/chat",
    "https://127.0.0.1/api/v2/chat",
    "https://chat2.qianwen.com:444/api/v2/chat",
    "https://chat2.qianwen.com/api/v2/other",
    "//chat2.qianwen.com/api/v2/chat",
    "https://sec.qianwen.com/security/external/access/register",
  ]
  for (const url of rejected) assert.throws(() => assertTrustedUrl(url, "chat"), (error) => error.status === 502 && error.code === "internal_error", url)
  for (const [name, endpoint] of Object.entries(ALLOWED_ENDPOINTS)) {
    assert.equal(assertTrustedUrl(endpoint.href, name).href, endpoint.href)
  }
  const native = ALLOWED_ENDPOINTS.nativeChat
  const web = ALLOWED_ENDPOINTS.chat
  assert.equal(native.pathname, "/v1/chat/completions")
  assert.equal(web.pathname, "/api/v2/chat")
  assert.throws(() => assertTrustedUrl(native.href, "chat"), /白名单/)
  assert.throws(() => assertTrustedUrl(web.href, "nativeChat"), /白名单/)
})

test("SDK URL 只接受本 provider chat completions，异常输入不触发网络", () => {
  assert.equal(assertSdkChatUrl("https://chat2.qianwen.com/v1/chat/completions").pathname, "/v1/chat/completions")
  assert.equal(assertSdkChatUrl("https://chat2.qianwen.com/chat/completions").pathname, "/chat/completions")
  for (const url of [
    "http://chat2.qianwen.com/v1/chat/completions",
    "https://user@chat2.qianwen.com/v1/chat/completions",
    "https://chat2.qianwen.com:8443/v1/chat/completions",
    "https://chat2.qianwen.com/v1/models",
    "https://example.invalid/v1/chat/completions",
  ]) assert.throws(() => assertSdkChatUrl(url), (error) => error.status === 400 || error.status === 501)
})

test("敏感请求头默认丢弃，日志头 redaction 不保留值", () => {
  const input = new Headers({
    accept: "application/json",
    "content-type": "application/json",
    cookie: "tongyi_sso_ticket=synthetic-ticket",
    authorization: "Bearer synthetic-authorization-token",
    "x-csrf-token": "synthetic-xsrf",
    "x-api-key": "synthetic-api-key",
    "user-agent": "caller-agent",
    "x-custom": "synthetic-custom",
  })
  const safe = headerSafe(input)
  assert.deepEqual([...safe.keys()].sort(), ["accept", "content-type"])
  assert.equal(safe.get("cookie"), null)
  assert.equal(safe.get("authorization"), null)
  assert.equal(safe.get("user-agent"), null)
  const redacted = redactHeaders(input)
  for (const name of ["cookie", "authorization", "x-csrf-token", "x-api-key"]) assert.equal(redacted[name], "[redacted]")
  assert.doesNotMatch(JSON.stringify(redacted), /synthetic-ticket|synthetic-authorization-token|synthetic-xsrf|synthetic-api-key/)
})

test("错误正文与日志形态脱敏，Cookie/ticket/token/Authorization 不出现", async () => {
  const secrets = ["synthetic-ticket", "synthetic-ticket-hash", "synthetic-xsrf", "synthetic-access-token"]
  const message = [
    "Cookie: tongyi_sso_ticket=synthetic-ticket; tongyi_sso_ticket_hash=synthetic-ticket-hash",
    "Authorization: Bearer synthetic-access-token",
    "https://example.invalid/?ticket=synthetic-ticket&token=synthetic-access-token",
    "XSRF-TOKEN=synthetic-xsrf <b>html</b>",
  ].join("\n")
  const safe = sanitizeText(message, secrets)
  for (const secret of secrets) assert.ok(!safe.includes(secret), secret)
  assert.doesNotMatch(safe, /<b>|Bearer synthetic/)
  const response = errorResponse(message, 401, "session_expired", { signIn: "expired", secrets })
  assert.equal(response.status, 401)
  assert.equal(response.headers.get("x-magpie-sign-in"), "expired")
  const body = await response.json()
  assert.equal(body.error.status, 401)
  assert.equal(body.error.code, "session_expired")
  assert.ok(body.error.message.length > 0)
  for (const secret of secrets) assert.ok(!JSON.stringify(body).includes(secret))

  const wrapped = asErrorResponse(Object.assign(new Error(message), { status: 503, code: "upstream_unavailable" }), secrets)
  const wrappedText = await wrapped.text()
  for (const secret of secrets) assert.ok(!wrappedText.includes(secret))
})

test("readBounded 在响应体超限处停止并取消，不返回截断成功", async () => {
  let cancelled = 0
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("12345"))
      controller.enqueue(new TextEncoder().encode("67890"))
    },
    cancel() { cancelled += 1 },
  })
  await assert.rejects(
    () => readBounded(new Response(body), { limit: 6 }),
    (error) => error.status === 502 && error.code === "upstream_error" && /上限/.test(error.message),
  )
  assert.equal(cancelled, 1)
})

test("账号缓存文件名按身份隔离并清理路径字符", () => {
  const root = join("synthetic-root", "cache")
  const first = securityCacheFile("account-A", root)
  const second = securityCacheFile("account-B", root)
  assert.notEqual(first, second)
  assert.ok(first.startsWith(root))
  assert.ok(second.startsWith(root))
  const unsafe = securityCacheFile("../../synthetic/account", root)
  assert.ok(unsafe.startsWith(root))
  assert.ok(!unsafe.includes(".."))
})
