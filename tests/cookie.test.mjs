import test from "node:test"
import assert from "node:assert/strict"
import { createCipheriv, createHash } from "node:crypto"
import { decryptCookieValue, decodeNativeAccount } from "../src/desktop-import.mjs"
import { normalizeCookie, parseCookie, parseCredential, successAuth, cookieFingerprint, authKeyOf, refreshAuth, authIdentity } from "../src/cookie.mjs"
import { deriveAesKeyIv, deriveRecordSecret, wsgDecrypt } from "../src/wsg.mjs"
import { SYNTHETIC_COOKIE } from "./helpers.mjs"

function encryptV10(hostKey, value, { key = createHash("sha256").update("synthetic-chromium-key").digest(), nonce = Buffer.from("synthetic12B") } = {}) {
  const prefix = createHash("sha256").update(hostKey, "utf8").digest()
  const plaintext = Buffer.concat([prefix, Buffer.from(value, "utf8")])
  const cipher = createCipheriv("aes-256-gcm", key, nonce)
  return Buffer.concat([
    Buffer.from("v10", "ascii"),
    nonce,
    cipher.update(plaintext),
    cipher.final(),
    cipher.getAuthTag(),
  ])
}

test("Chromium v10 AES-GCM 校验并剥离 SHA256(host_key) 32 字节前缀", () => {
  const host = ".chat2.qianwen.com"
  const encrypted = encryptV10(host, "synthetic-cookie-value")
  assert.equal(encrypted.subarray(0, 3).toString(), "v10")
  assert.equal(encrypted.length, 3 + 12 + 32 + "synthetic-cookie-value".length + 16)
  assert.equal(decryptCookieValue(encrypted, host, createHash("sha256").update("synthetic-chromium-key").digest()), "synthetic-cookie-value")
})

test("Chromium Cookie 错误 host 前缀、错误 tag、非 v10 均拒绝", () => {
  const key = createHash("sha256").update("synthetic-chromium-key").digest()
  const encrypted = encryptV10(".qianwen.com", "synthetic-cookie-value")
  assert.throws(
    () => decryptCookieValue(encrypted, ".attacker.invalid", key),
    (error) => error.status === 400 && error.code === "invalid_request" && /host_key/.test(error.message) && !error.message.includes("synthetic-cookie-value"),
  )
  const tampered = Buffer.from(encrypted)
  tampered[tampered.length - 1] ^= 1
  assert.throws(() => decryptCookieValue(tampered, ".qianwen.com", key), /AES-GCM 校验失败/)
  const wrongVersion = Buffer.from(encrypted)
  wrongVersion.write("v11", 0, "ascii")
  assert.throws(() => decryptCookieValue(wrongVersion, ".qianwen.com", key), /不支持的 v10 加密版本 v11/)
})

test("ticket/hash/XSRF 从合成 Cookie 提取，保留等号并忽略非法段", () => {
  const raw = [
    "tongyi_sso_ticket=synthetic-ticket-with=equals",
    "tongyi_sso_ticket_hash=synthetic-hash",
    "XSRF-TOKEN=synthetic-xsrf",
    "empty=",
    "not-a-cookie",
    "bad name=value",
  ].join("; ")
  const jar = parseCookie(raw)
  assert.equal(jar.tongyi_sso_ticket, "synthetic-ticket-with=equals")
  assert.equal(jar.tongyi_sso_ticket_hash, "synthetic-hash")
  assert.equal(jar["XSRF-TOKEN"], "synthetic-xsrf")
  assert.equal(jar["bad name"], undefined)
  const auth = successAuth(raw, { note: "synthetic-user" })
  assert.equal(auth.type, "success")
  assert.equal(auth.accountId, "synthetic-user")
  assert.match(auth.key, /tongyi_sso_ticket=synthetic-ticket-with=equals/)
  assert.match(auth.key, /tongyi_sso_ticket_hash=synthetic-hash/)
  assert.match(auth.key, /XSRF-TOKEN=synthetic-xsrf/)
  assert.equal(cookieFingerprint(auth.key), auth.uid)
  assert.equal(normalizeCookie(parseCredential(auth.key).cookie), parseCredential(auth.key).cookie)
})

test("缺 ticket/hash 时明确 400，不伪造空账号", () => {
  assert.throws(
    () => successAuth("XSRF-TOKEN=synthetic-xsrf"),
    (error) => error.status === 400 && error.code === "invalid_request" && !error.message.includes("synthetic-xsrf"),
  )
})

const NATIVE = Object.freeze({
  serviceTicket: "synthetic-service-ticket",
  kpsWg: "synthetic-kps-wg",
  uId: "1000000000000000001",
  nickname: "synthetic-nickname",
  uidWsg: "synthetic-uid-wsg",
  utdid: "synthetic-utdid",
  ucParams: { device: "synthetic-device" },
})

test("JSON credential 的 native 秘密不进入 Cookie 头，refresh 保留宿主字段和 native", () => {
  const auth = successAuth({ cookie: SYNTHETIC_COOKIE, native: NATIVE })
  const parsed = parseCredential(auth.key)
  assert.deepEqual(parsed.native, NATIVE)
  assert.equal(authKeyOf(auth), SYNTHETIC_COOKIE)
  assert.doesNotMatch(authKeyOf(auth), /serviceTicket|synthetic-service-ticket|synthetic-kps-wg|synthetic-uid-wsg/)
  assert.equal(auth.uid, NATIVE.uId)
  assert.equal(auth.accountId, NATIVE.nickname)
  assert.equal(auth.metadata.kind, "qianwen-native")
  assert.doesNotMatch(JSON.stringify(auth.metadata), /synthetic-service-ticket|synthetic-kps-wg|synthetic-uid-wsg|synthetic-utdid/)

  const merged = refreshAuth({ ...auth, expires: 1700000000, refresh: "synthetic-host-refresh", custom: true })
  assert.equal(merged.expires, 1700000000)
  assert.equal(merged.refresh, "synthetic-host-refresh")
  assert.equal(merged.custom, true)
  assert.deepEqual(parseCredential(merged.key).native, NATIVE)
  assert.equal(parseCredential(merged.key).cookie, SYNTHETIC_COOKIE)

  const otherCookie = SYNTHETIC_COOKIE.replace("synthetic-ticket;", "synthetic-ticket-other;")
  const other = successAuth({ cookie: otherCookie, native: { ...NATIVE, uId: NATIVE.uId } })
  assert.notEqual(authIdentity(auth), authIdentity(other), "相同 uid 也不能让不同 Cookie 共用账号缓存")
})

test("Windows 原生账号导入自动生成稳定设备与派生 uc.ut/uidWsg，无需 native_device", () => {
  const key = createHash("sha256").update("synthetic-native-account-key").digest()
  const nonce = Buffer.from("synthetic12B")
  const fields = [
    NATIVE.serviceTicket,
    NATIVE.kpsWg,
    NATIVE.uId,
    NATIVE.nickname,
    "", "", "", "", "", "", "",
  ]
  const cipher = createCipheriv("aes-256-gcm", key, nonce)
  const v10 = Buffer.concat([
    Buffer.from("v10"),
    nonce,
    cipher.update(JSON.stringify({ fields }), "utf8"),
    cipher.final(),
    cipher.getAuthTag(),
  ])
  const recordSecret = deriveRecordSecret()
  const keyIv = deriveAesKeyIv(recordSecret)
  const outerCipher = createCipheriv("aes-128-cbc", keyIv, keyIv)
  const prefix = Buffer.alloc(2)
  prefix.writeUInt16BE(15351)
  const outer = Buffer.concat([prefix, outerCipher.update(v10), outerCipher.final()]).toString("base64")
  const native = decodeNativeAccount(`1700000000123|${outer}`, { key })
  assert.equal(native.serviceTicket, NATIVE.serviceTicket)
  assert.equal(native.kpsWg, NATIVE.kpsWg)
  assert.equal(native.uId, NATIVE.uId)
  assert.equal(native.nickname, NATIVE.nickname)
  assert.match(native.utdid, /^[a-f0-9]{24}$/)
  assert.deepEqual(Object.keys(native.ucParams), ["ut"])
  assert.equal(wsgDecrypt(native.ucParams.ut).toString("utf8"), native.utdid)
  assert.equal(wsgDecrypt(native.uidWsg).toString("utf8"), NATIVE.uId)

  const auth = successAuth({ cookie: SYNTHETIC_COOKIE, native })
  const refreshed = refreshAuth(auth)
  assert.deepEqual(parseCredential(refreshed.key).native, native)
  assert.equal(parseCredential(refreshed.key).native.utdid, native.utdid)
  assert.equal(parseCredential(refreshed.key).native.uidWsg, native.uidWsg)
  assert.deepEqual(parseCredential(refreshed.key).native.ucParams, native.ucParams)
})
