import { createCipheriv, createDecipheriv, createHash, createHmac } from "node:crypto"

// 非个人常量，来自用户提供的 5.2.7.307 脱敏实测记录。只嵌密文与 key=IV，不嵌解密后的 secret。
export const WSG_RECORD = Object.freeze({
  secureNo: 15351,
  ciphertextHex: "a8741635997d88bd470151b37c7b08c30f025def078702183ad3fbe1c6244df1",
  keyIvHex: "64306661383966313961663466653463",
})

export function deriveRecordSecret(record = WSG_RECORD) {
  const ciphertext = Buffer.from(record.ciphertextHex, "hex")
  const keyIv = Buffer.from(record.keyIvHex, "hex")
  if (ciphertext.length !== 32 || keyIv.length !== 16) throw new TypeError("WSG record 密文或 key=IV 长度不合法")
  const decipher = createDecipheriv("aes-128-cbc", keyIv, keyIv)
  const secret = Buffer.concat([decipher.update(ciphertext), decipher.final()])
  const text = secret.toString("ascii")
  if (secret.length !== 28 || !/^[\x21-\x7e]{28}$/.test(text)) throw new TypeError("WSG record secret 形状不合法")
  return text
}

export function deriveAesKeyIv(recordSecret) {
  return Buffer.from(createHash("md5").update(recordSecret).digest("hex").slice(0, 16), "ascii")
}

function uint16be(number) {
  if (!Number.isInteger(number) || number < 0 || number > 0xffff) throw new TypeError("secureNo 必须是 uint16")
  const output = Buffer.alloc(2)
  output.writeUInt16BE(number, 0)
  return output
}

/** uint16BE(secureNo) || HMAC-SHA1(record_secret, value_to_sign)，小写 hex。 */
export function wsgSign(valueToSign, recordSecret, { secureNo = 15351 } = {}) {
  if (typeof valueToSign !== "string" || !valueToSign) throw new TypeError("wsgSign 需要非空 value_to_sign")
  if ((typeof recordSecret !== "string" && !Buffer.isBuffer(recordSecret)) || recordSecret.length === 0) {
    throw new TypeError("wsgSign 需要非空 record_secret")
  }
  const prefix = uint16be(secureNo)
  const digest = createHmac("sha1", recordSecret).update(valueToSign, "utf8").digest("hex")
  return `${prefix.toString("hex")}${digest}`
}

export function officialWsgSign(valueToSign) {
  return wsgSign(valueToSign, deriveRecordSecret(), { secureNo: WSG_RECORD.secureNo })
}

export function wsgEncrypt(plaintext, recordSecret = deriveRecordSecret(), { secureNo = 15351 } = {}) {
  const keyIv = deriveAesKeyIv(recordSecret)
  const cipher = createCipheriv("aes-128-cbc", keyIv, keyIv)
  const encrypted = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()])
  return Buffer.concat([uint16be(secureNo), encrypted]).toString("base64")
}

export function wsgDecrypt(value, recordsByNumber = { 15351: deriveRecordSecret() }) {
  const input = Buffer.isBuffer(value) ? value : Buffer.from(String(value), "base64")
  if (input.length < 18 || input.length % 16 !== 2) throw new TypeError("WSG ciphertext 长度不合法")
  const number = input.readUInt16BE(0)
  const secret = recordsByNumber[number] ?? recordsByNumber.get?.(number)
  if (!secret) throw new TypeError(`不支持的 WSG secureNo：${number}`)
  const keyIv = deriveAesKeyIv(secret)
  const decipher = createDecipheriv("aes-128-cbc", keyIv, keyIv)
  return Buffer.concat([decipher.update(input.subarray(2)), decipher.final()])
}

/** X-U-SIGN-WG：第四段是 nickname，不是 uidWsg；kpsWg 不参与 MD5。 */
export function buildSignWg({ serviceTicket, uId, nickname, vcode = String(Date.now()), recordSecret = deriveRecordSecret(), secureNo = 15351 }) {
  const code = String(vcode)
  if (code.length <= 5) throw new TypeError("vcode 至少需要 6 个字符")
  for (const [name, value] of Object.entries({ serviceTicket, uId })) {
    if (typeof value !== "string" || !value) throw new TypeError(`${name} 是原生认证必需字段`)
  }
  if (typeof nickname !== "string") throw new TypeError("nickname 必须是字符串（可以为空）")
  const joined = `${code.slice(0, 5)}${serviceTicket}${uId}${nickname}${code.slice(-1)}`
  const plaintext = createHash("md5").update(joined, "utf8").digest("hex").toUpperCase()
  return { vcode: code, plaintext, signWg: wsgEncrypt(plaintext, recordSecret, { secureNo }) }
}

export function buildChat2ValueToSign({ method = "POST", pathname = "/api/v2/chat", query, bodyText }) {
  const md5 = createHash("md5").update(bodyText ?? "", "utf8").digest("hex")
  const canonical = Object.entries(query || {})
    .filter(([key, value]) => key !== "sign" && value !== "" && value !== undefined && value !== null)
    .map(([key, value]) => [key, String(value)])
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&")
  return `${String(method).toUpperCase()}${pathname}${canonical}${md5}quark`
}

export function createWsgSigner(recordSecret, options) {
  return (valueToSign) => wsgSign(valueToSign, recordSecret, options)
}
