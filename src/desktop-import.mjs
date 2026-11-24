import { copyFileSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs"
import { join } from "node:path"
import { homedir, tmpdir } from "node:os"
import { execFileSync } from "node:child_process"
import { createDecipheriv, createHash, randomBytes } from "node:crypto"
import { normalizeCookie, normalizeNative, successAuth } from "./cookie.mjs"
import { QwenError, CODES } from "./errors.mjs"
import { wsgDecrypt, wsgEncrypt } from "./wsg.mjs"

const COOKIE_NAMES = ["tongyi_sso_ticket", "tongyi_sso_ticket_hash", "XSRF-TOKEN", "bx-umidtoken", "eo-clt-sftcnt"]
const ACCOUNT_FIELDS = ["serviceTicket", "kpsWg", "uId", "nickname", "avatar_url", "register_time", "security_mobile", "is_realname", "is_realname_by_mobile", "avatar_base64", "displayUserId"]

export function qianwenDataDir(env = process.env) {
  const local = env.LOCALAPPDATA || join(homedir(), "AppData", "Local")
  return join(local, "Qianwen", "User Data")
}

export function dpapiDecrypt(cipher) {
  if (process.platform !== "win32") {
    throw new QwenError("Windows 客户端 Cookie 导入仅支持 Windows", { status: 400, code: CODES.invalidRequest })
  }
  const b64 = Buffer.from(cipher).toString("base64")
  const script = "Add-Type -AssemblyName System.Security; " +
    "[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect(" +
    `[Convert]::FromBase64String('${b64}'), $null, 'CurrentUser'))`
  let output
  try {
    output = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
      encoding: "utf8",
      timeout: 20_000,
      windowsHide: true,
    })
  } catch (cause) {
    throw new QwenError("Windows DPAPI 解密失败；请确认当前用户与千问客户端登录用户一致，或改用粘贴 Cookie", {
      status: 400,
      code: CODES.invalidRequest,
      cause,
    })
  }
  return Buffer.from(output.trim(), "base64")
}

export function localStateKey(localStateFile) {
  const state = JSON.parse(readFileSync(localStateFile, "utf8"))
  const wrapped = Buffer.from(String(state?.os_crypt?.encrypted_key || ""), "base64")
  if (wrapped.subarray(0, 5).toString() !== "DPAPI") {
    throw new QwenError("Local State 没有 DPAPI 包裹的 Chromium AES key", { status: 400, code: CODES.invalidRequest })
  }
  const key = dpapiDecrypt(wrapped.subarray(5))
  if (key.length !== 32) {
    throw new QwenError("Local State 解出的 AES key 不是 32 字节", { status: 400, code: CODES.invalidRequest })
  }
  return key
}

/** 账号文件内层 v10 不带有 host_key 前缀；Cookie 复用此原语后再校验自己的前缀。 */
export function decryptV10Raw(encrypted, key) {
  const data = Buffer.from(encrypted || [])
  const version = data.subarray(0, 3).toString("ascii")
  if (version !== "v10") {
    throw new QwenError(`不支持的 v10 加密版本 ${version || "unknown"}`, { status: 400, code: CODES.invalidRequest })
  }
  if (data.length < 3 + 12 + 16) {
    throw new QwenError("v10 密文长度不足", { status: 400, code: CODES.invalidRequest })
  }
  const nonce = data.subarray(3, 15)
  const body = data.subarray(15, data.length - 16)
  const tag = data.subarray(data.length - 16)
  const decipher = createDecipheriv("aes-256-gcm", key, nonce)
  decipher.setAuthTag(tag)
  try { return Buffer.concat([decipher.update(body), decipher.final()]) } catch (cause) {
    throw new QwenError("AES-GCM 校验失败，请重新导入或改用粘贴 Cookie", {
      status: 400,
      code: CODES.invalidRequest,
      cause,
    })
  }
}

/** Cookie plaintext = SHA256(host_key) 32B + UTF-8 value；不做 App-Bound 二次 DPAPI。 */
export function decryptCookieValue(encrypted, hostKey, key) {
  const plaintext = decryptV10Raw(encrypted, key)
  const expected = createHash("sha256").update(String(hostKey), "utf8").digest()
  if (plaintext.length < 32 || !plaintext.subarray(0, 32).equals(expected)) {
    throw new QwenError("Cookie 明文的 host_key SHA-256 前缀不匹配，已拒绝导入", {
      status: 400,
      code: CODES.invalidRequest,
    })
  }
  return plaintext.subarray(32).toString("utf8")
}

export function mapAccountFields(fields) {
  if (!Array.isArray(fields) || fields.length !== ACCOUNT_FIELDS.length) {
    throw new QwenError("原生账号 fields 向量形状不合法", { status: 400, code: CODES.invalidRequest })
  }
  const row = Object.fromEntries(ACCOUNT_FIELDS.map((name, index) => [name, String(fields[index] ?? "")]))
  return {
    serviceTicket: row.serviceTicket,
    kpsWg: row.kpsWg,
    uId: row.uId,
    nickname: row.nickname,
    // 仅用于生成本地显示名（脱敏手机号 / 可读昵称）；仍只存在 auth.key，不进入日志或缓存。
    securityMobile: row.security_mobile,
    displayUserId: row.displayUserId,
  }
}

/** timestamp|base64(uint16BE + AES-CBC(v10)) → v10 AES-GCM → JSON.fields。 */
export function decodeNativeAccount(text, { key, nativeDevice = {} } = {}) {
  const source = String(text || "")
  const separator = source.indexOf("|")
  const timestamp = separator >= 0 ? source.slice(0, separator) : ""
  if (!/^\d+$/.test(timestamp) || !key) {
    throw new QwenError("原生账号文件 envelope 或 AES key 不合法", { status: 400, code: CODES.invalidRequest })
  }
  let result
  try {
    const outer = Buffer.from(source.slice(separator + 1), "base64")
    const v10 = wsgDecrypt(outer)
    result = JSON.parse(decryptV10Raw(v10, key).toString("utf8"))
  } catch (cause) {
    if (cause instanceof QwenError) throw cause
    throw new QwenError("原生账号文件解密或 JSON 解析失败", { status: 400, code: CODES.invalidRequest, cause })
  }
  for (const key of ["serviceTicket", "kpsWg", "uId", "nickname"]) {
    if (nativeDevice && Object.hasOwn(nativeDevice, key)) {
      throw new QwenError(`nativeDevice 不允许覆盖解密账号字段 ${key}`, { status: 400, code: CODES.invalidRequest })
    }
  }
  const account = mapAccountFields(result?.fields)
  const suppliedUc = nativeDevice?.ucParams && typeof nativeDevice.ucParams === "object" ? nativeDevice.ucParams : {}
  let utdid = String(nativeDevice?.utdid || nativeDevice?.unetUtdid || "")
  let ut = typeof suppliedUc.ut === "string" ? suppliedUc.ut : ""
  if (!utdid && ut) {
    try { utdid = wsgDecrypt(ut).toString("utf8") } catch (cause) {
      throw new QwenError("nativeDevice.ucParams.ut 无法解密为 UTDID", { status: 400, code: CODES.invalidRequest, cause })
    }
  }
  if (!utdid) utdid = randomBytes(12).toString("hex")
  if (!ut) ut = wsgEncrypt(utdid)
  const uidWsg = String(nativeDevice?.uidWsg || wsgEncrypt(account.uId))
  return normalizeNative({
    uidWsg,
    utdid,
    ucParams: { ...suppliedUc, ut },
    ...account,
  })
}

export function importNativeAccount({ dataDir = qianwenDataDir(), key, nativeDevice = {} } = {}) {
  const directory = join(dataDir, "qianwen_user_info")
  let files
  try { files = readdirSync(directory, { withFileTypes: true }).filter((entry) => entry.isFile()).map((entry) => join(directory, entry.name)) } catch (cause) {
    throw new QwenError("未找到千问原生账号目录；可改用粘贴 Cookie 的 Web 兼容登录", {
      status: 400,
      code: CODES.invalidRequest,
      cause,
    })
  }
  if (files.length !== 1) {
    throw new QwenError(`原生账号目录应有且仅有一个账号文件，实际为 ${files.length} 个`, {
      status: 409,
      code: CODES.concurrencyConflict,
    })
  }
  return decodeNativeAccount(readFileSync(files[0], "ascii"), { key, nativeDevice })
}

function cookieRows(db) {
  const placeholders = COOKIE_NAMES.map(() => "?").join(",")
  return db.prepare(`SELECT host_key, name, value, encrypted_value FROM cookies WHERE name IN (${placeholders})`).all(...COOKIE_NAMES)
}

function matchingHost(host) {
  const value = String(host || "").toLowerCase().replace(/^\./, "")
  return value === "qianwen.com" || value.endsWith(".qianwen.com")
}

function selectCookieRows(rows, decrypt) {
  const jar = {}
  const xsrf = []
  for (const row of rows) {
    if (!matchingHost(row.host_key)) continue
    const encrypted = Buffer.from(row.encrypted_value || [])
    const value = encrypted.length ? decrypt(row.encrypted_value, row.host_key) : String(row.value || "")
    if (!value) continue
    if (row.name === "XSRF-TOKEN") {
      const host = String(row.host_key || "").toLowerCase().replace(/^\./, "")
      if (host === "qianwen.com" || host === "www.qianwen.com" || host === "chat2-api.qianwen.com") xsrf.push({ host, value })
    } else {
      jar[row.name] = value
    }
  }
  const preferred = xsrf.find((row) => row.host === "www.qianwen.com") ||
    xsrf.find((row) => row.host === "qianwen.com") ||
    xsrf.find((row) => row.host === "chat2-api.qianwen.com")
  if (preferred) jar["XSRF-TOKEN"] = preferred.value
  return jar
}

function deviceInput(value) {
  if (!value) return {}
  if (typeof value === "object" && !Array.isArray(value)) return value
  try {
    const parsed = JSON.parse(String(value))
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not object")
    return parsed
  } catch (cause) {
    throw new QwenError("原生设备参数必须是 JSON 对象（uidWsg/utdid/ucParams）", {
      status: 400,
      code: CODES.invalidRequest,
      cause,
    })
  }
}

export async function importWindowsCookies({ dataDir = qianwenDataDir(), note = "", nativeDevice = {} } = {}) {
  if (process.platform !== "win32") {
    throw new QwenError("未检测到 Windows；请使用“粘贴 Cookie”登录方式", { status: 400, code: CODES.invalidRequest })
  }
  const localState = join(dataDir, "Local State")
  const source = join(dataDir, "Default", "Network", "Cookies")
  if (!existsSync(localState) || !existsSync(source)) {
    throw new QwenError("未找到千问 Windows 客户端登录 Cookie，请先在客户端登录，或改用粘贴 Cookie", {
      status: 400,
      code: CODES.invalidRequest,
    })
  }
  const temp = mkdtempSync(join(tmpdir(), "qwenapp-cookie-"))
  let db
  try {
    const copy = join(temp, "Cookies")
    try {
      copyFileSync(source, copy)
      for (const suffix of ["-wal", "-shm"]) {
        const sidecar = `${source}${suffix}`
        if (existsSync(sidecar)) copyFileSync(sidecar, `${copy}${suffix}`)
      }
    } catch (cause) {
      throw new QwenError("千问客户端正在锁定 Cookie 数据库；请完全退出千问客户端后重试，或改用粘贴 Cookie", {
        status: 409,
        code: CODES.concurrencyConflict,
        cause,
      })
    }
    const key = localStateKey(localState)
    let DatabaseSync
    try { ({ DatabaseSync } = await import("node:sqlite")) } catch (cause) {
      throw new QwenError("当前 Node.js 缺少 node:sqlite；请使用 Node 22.19+ 或改用粘贴 Cookie", {
        status: 500,
        code: CODES.internalError,
        cause,
      })
    }
    try { db = new DatabaseSync(copy, { readOnly: true }) } catch (cause) {
      throw new QwenError("无法打开 Cookie 数据库副本；请完全退出千问客户端后重试，或改用粘贴 Cookie", {
        status: 409,
        code: CODES.concurrencyConflict,
        cause,
      })
    }
    let rows
    try { rows = cookieRows(db) } catch (cause) {
      throw new QwenError("读取 Cookie 数据库失败（可能正被客户端锁库）；请退出客户端后重试", {
        status: 409,
        code: CODES.concurrencyConflict,
        cause,
      })
    }
    const jar = selectCookieRows(rows, (encrypted, host) => decryptCookieValue(encrypted, host, key))
    const native = importNativeAccount({ dataDir, key, nativeDevice: deviceInput(nativeDevice) })
    return successAuth({ cookie: normalizeCookie(jar), native }, { note })
  } finally {
    try { db?.close() } catch {}
    try { rmSync(temp, { recursive: true, force: true }) } catch {}
  }
}
