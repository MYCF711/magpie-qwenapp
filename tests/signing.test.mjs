import test from "node:test"
import assert from "node:assert/strict"
import { createHash, createHmac } from "node:crypto"
import { readFileSync } from "node:fs"
import { signChat, chatUrl, chatHeaders, nativeChatUrl, nativeChatHeaders } from "../src/protocol.mjs"
import { QUERY_PARAM_KEYS, SIGN_VERSION } from "../src/constants.mjs"
import { WSG_RECORD, deriveRecordSecret, deriveAesKeyIv, officialWsgSign, wsgSign, createWsgSigner, buildSignWg, wsgDecrypt, wsgEncrypt, buildChat2ValueToSign } from "../src/wsg.mjs"
import { parseCookie } from "../src/cookie.mjs"
import { SYNTHETIC_COOKIE } from "./helpers.mjs"

function hmac(key, text) {
  return createHmac("sha256", key).update(text, "utf8").digest("base64")
}

const SIGN_INPUT = Object.freeze({
  deviceId: "synthetic-device",
  ticketHash: "synthetic-ticket-hash",
  sacsft: "synthetic-sacsft",
  bodyStr: "{\"synthetic\":true,\"text\":\"你好\"}",
  timestamp: "1700000000123",
  nonce: "synthetic-nonce",
})

test("Baxia 双重 HMAC-SHA256：body 先签名，再按固定拼接顺序签名", () => {
  const actual = signChat(SIGN_INPUT)
  const key = `${SIGN_INPUT.sacsft}:${SIGN_INPUT.timestamp}`
  const bodyHmac = hmac(key, SIGN_INPUT.bodyStr)
  const signText = `${SIGN_INPUT.deviceId}${SIGN_VERSION}${SIGN_INPUT.ticketHash}${QUERY_PARAM_KEYS}${bodyHmac}`
  const expected = hmac(key, signText)
  assert.equal(actual.bodyKey, key)
  assert.equal(actual.bodyHmac, bodyHmac)
  assert.equal(actual.signText, signText)
  assert.equal(actual.sign, expected)
  assert.notEqual(actual.sign, actual.bodyHmac)
})

test("Baxia 查询参数顺序严格等于签名清单，ch 仅作额外查询参数", () => {
  const signed = chatUrl({ ...SIGN_INPUT, ch: "synthetic-ch" })
  const url = new URL(signed.url)
  const expectedKeys = [...QUERY_PARAM_KEYS.split(","), "ch"]
  assert.deepEqual([...url.searchParams.keys()], expectedKeys)
  assert.equal(url.searchParams.get("timestamp"), SIGN_INPUT.timestamp)
  assert.equal(url.searchParams.get("nonce"), SIGN_INPUT.nonce)
  assert.equal(url.searchParams.get("ut"), SIGN_INPUT.deviceId)
  assert.equal(url.searchParams.get("ve"), SIGN_VERSION)
  assert.equal(url.searchParams.get("wv"), SIGN_VERSION)
  assert.equal(url.searchParams.get("ch"), "synthetic-ch")
  assert.equal(url.searchParams.get("sign"), null)
  assert.equal(signed.sign, signChat(SIGN_INPUT).sign)
})

test("Baxia 请求头完整且与签名、token、reqId 一一对应", () => {
  const signed = signChat(SIGN_INPUT)
  const token = {
    dvidn: "synthetic-dvidn",
    sacsft: SIGN_INPUT.sacsft,
    snver: "synthetic-snver",
    actkn: "synthetic-actkn",
  }
  const headers = chatHeaders({
    jar: parseCookie(SYNTHETIC_COOKIE),
    deviceId: SIGN_INPUT.deviceId,
    ticketHash: SIGN_INPUT.ticketHash,
    reqId: "synthetic-req-id",
    token,
    timestamp: SIGN_INPUT.timestamp,
    sign: signed.sign,
    sessionId: "synthetic session/id",
  })
  assert.deepEqual(Object.keys(headers).sort(), [
    "accept", "clt-acs-caer", "clt-acs-request-params", "clt-acs-reqt", "clt-acs-sign",
    "content-type", "eo-clt-acs-kp", "eo-clt-acs-ve", "eo-clt-actkn", "eo-clt-dvidn",
    "eo-clt-sacsft", "eo-clt-snver", "origin", "referer", "x-chat-id", "x-csrf-token",
    "x-device-id", "x-platform",
  ].sort())
  assert.equal(headers["clt-acs-sign"], signed.sign)
  assert.equal(headers["clt-acs-reqt"], SIGN_INPUT.timestamp)
  assert.equal(headers["clt-acs-request-params"], QUERY_PARAM_KEYS)
  assert.equal(headers["x-device-id"], SIGN_INPUT.deviceId)
  assert.equal(headers["x-chat-id"], "synthetic-req-id")
  assert.equal(headers["x-csrf-token"], "synthetic-xsrf")
  assert.equal(headers["eo-clt-dvidn"], token.dvidn)
  assert.equal(headers["eo-clt-sacsft"], token.sacsft)
  assert.equal(headers["eo-clt-snver"], token.snver)
  assert.equal(headers["eo-clt-actkn"], token.actkn)
  assert.equal(headers["eo-clt-acs-kp"], SIGN_INPUT.ticketHash)
  assert.equal(headers["eo-clt-acs-ve"], SIGN_VERSION)
  assert.equal(headers.referer, "https://www.qianwen.com/chat/synthetic%20session%2Fid")
  assert.equal(headers.authorization, undefined)
  assert.equal(headers.cookie, undefined)
  assert.throws(() => chatHeaders({ jar: {}, token }), (error) => error.status === 400 && error.code === "invalid_request")
})

test("WSG 合成 recordSecret 向量精确等于 uint16BE(15351)+HMAC-SHA1 hex", () => {
  const secret = "synthetic-record-secret"
  const value = "synthetic-value-to-sign"
  const expectedDigest = createHmac("sha1", secret).update(value, "utf8").digest("hex")
  assert.equal(wsgSign(value, secret), `3bf7${expectedDigest}`)
  assert.equal(wsgSign(value, secret), "3bf7254371b8f9a2f1fd9510ce49d88b8c75c5a36f8a")
  assert.equal(createWsgSigner(secret)(value), "3bf7254371b8f9a2f1fd9510ce49d88b8c75c5a36f8a")
  assert.throws(() => wsgSign(value, secret, { secureNo: 65536 }), /uint16/)
})

test("WSG 官方静态 record 非用户向量与原生记录一致", () => {
  const record = JSON.parse(readFileSync(new URL("../official/wsg-record.json", import.meta.url), "utf8"))
  assert.equal(WSG_RECORD.secureNo, record.secureNo)
  assert.equal(WSG_RECORD.ciphertextHex, record.ciphertextHex)
  assert.equal(WSG_RECORD.keyIvHex, record.keyIvHex)
  const secret = deriveRecordSecret()
  assert.equal(secret.length, 28)
  assert.equal(officialWsgSign(record.testVector.valueToSign), record.testVector.sign)
  assert.equal(officialWsgSign("MAGPIE_WSG_TEST"), "3bf77f8c856cd9381606555b5cd9f49a9e353aa35d06")
  assert.equal(officialWsgSign("synthetic-value-to-sign"), "3bf745171dbdea3916907a567fdc3d05620ca04347d6")
  assert.equal(wsgSign(record.testVector.valueToSign, secret), record.testVector.sign)
})

test("signWg 第四段使用 nickname，MD5 大写 hex 向量与 AES-CBC/base64 完全一致", () => {
  const vector = JSON.parse(readFileSync(new URL("../reference/fixtures/sign-wg-uppercase.json", import.meta.url), "utf8"))
  const input = {
    ...vector.input,
    uidWsg: "synthetic-uid-wsg-must-not-be-used",
    kpsWg: "synthetic-kps-must-not-be-used",
  }
  const result = buildSignWg(input)
  const joined = `17000${input.serviceTicket}${input.uId}${input.nickname}3`
  assert.equal(vector.plaintext, createHash("md5").update(joined, "utf8").digest("hex").toUpperCase())
  assert.match(result.plaintext, /^[0-9A-F]{32}$/)
  assert.equal(result.plaintext, vector.plaintext)
  assert.equal(result.signWg, vector.signWg)
  assert.equal(wsgDecrypt(result.signWg).toString("utf8"), vector.plaintext)
  assert.equal(buildSignWg({ ...input, uidWsg: "synthetic-other-uid", kpsWg: "synthetic-other-kps" }).signWg, result.signWg)
  assert.notEqual(buildSignWg({ ...input, nickname: "synthetic-other-nickname" }).signWg, result.signWg)
  assert.equal(Buffer.from(result.signWg, "base64").readUInt16BE(0), 15351)
  const recordSecret = deriveRecordSecret()
  const lowerMd5 = createHash("md5").update(recordSecret).digest("hex")
  assert.equal(deriveAesKeyIv(recordSecret).toString("ascii"), lowerMd5.slice(0, 16), "recordSecret→AES keyIv 仍必须 lowercase")
})

test("chat2 value_to_sign 排除 sign、排序并编码查询，body MD5 顺序固定", () => {
  const bodyText = '{"synthetic":"你好"}'
  const value = buildChat2ValueToSign({
    method: "post",
    pathname: "/api/v2/chat",
    query: { z: "最后", a: "space value", sign: "synthetic-excluded", empty: "", nil: null },
    bodyText,
  })
  const md5 = createHash("md5").update(bodyText, "utf8").digest("hex")
  assert.equal(value, `POST/api/v2/chata=space%20value&z=${encodeURIComponent("最后")}${md5}quark`)
})

test("原生 cowork URL/请求头使用 WSG 与 nickname signWg，缺 native 明确 400", () => {
  const utdid = "012345" + "6789ab" + "cdef" + "01234567"
  const recordSecret = deriveRecordSecret()
  const native = {
    serviceTicket: "synthetic-service-ticket",
    kpsWg: "synthetic-kps-wg",
    uId: "1000000000000000001",
    nickname: "synthetic-nickname",
    utdid,
    ucParams: { ut: wsgEncrypt(utdid, recordSecret) },
  }
  const bodyStr = '{"synthetic":true}'
  const shape = JSON.parse(readFileSync(new URL("../reference/fixtures/native-empirical-shape.json", import.meta.url), "utf8"))
  const signed = nativeChatUrl({ native, bodyStr })
  const url = new URL(signed.url)
  assert.equal(url.origin, shape.origin)
  assert.equal(url.pathname, shape.pathname)
  assert.deepEqual([...url.searchParams.keys()], shape.queryKeys)
  assert.equal(url.searchParams.get("nonce").length, shape.nonceLength)
  assert.match(url.searchParams.get("nonce"), /^[A-Za-z0-9]{16}$/)
  assert.match(url.searchParams.get("timestamp"), new RegExp(`^\\d{${shape.timestampLength}}$`))
  assert.equal(url.searchParams.get("sign"), signed.sign)
  assert.equal(wsgDecrypt(url.searchParams.get("ut")).toString("utf8"), utdid)
  assert.match(signed.sign, /^3bf7[a-f0-9]{40}$/)
  const canonicalQuery = Object.fromEntries([...url.searchParams.entries()].filter(([key]) => key !== "sign"))
  assert.equal(signed.valueToSign, buildChat2ValueToSign({ pathname: shape.pathname, query: canonicalQuery, bodyText: bodyStr }))
  assert.equal(signed.sign, officialWsgSign(signed.valueToSign))

  const headers = nativeChatHeaders({ native, vcode: "1700000000123" })
  assert.equal(headers["x-utdid"], native.utdid)
  assert.equal(headers["x-u-kps-wg"], native.kpsWg)
  assert.equal(headers["x-u-vcode"], "1700000000123")
  assert.equal(wsgDecrypt(headers["x-u-sign-wg"]).toString("utf8"), buildSignWg({ ...native, vcode: "1700000000123" }).plaintext)
  assert.throws(() => nativeChatUrl({ native: null, bodyStr }), (error) => error.status === 400 && error.code === "invalid_request")
  assert.throws(() => nativeChatHeaders({ native: null }), (error) => error.status === 400 && error.code === "invalid_request")
})
