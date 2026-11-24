#!/usr/bin/env node
// 离线交付物隐私扫描：只报告文件与规则，不回显命中内容。
import { readdirSync, readFileSync, statSync } from "node:fs"
import { basename, extname, join, relative, resolve, sep } from "node:path"

const root = resolve(process.argv[2] || ".")
const MAX_FILE_BYTES = 4 * 1024 * 1024
const TEXT_EXTENSIONS = new Set([
  ".bash", ".cjs", ".conf", ".config", ".css", ".env", ".html", ".ini", ".js", ".json", ".key",
  ".log", ".md", ".mjs", ".pem", ".properties", ".ps1", ".psm1", ".py", ".sh", ".sql", ".sse",
  ".toml", ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml", ".zsh",
])
const PLACEHOLDER = /(?:^|[^a-z])(?:dummy|example|fake|native|nested|placeholder|process|redacted|synthetic|test|usage|xxxx|000000)(?:[^a-z]|$)/i
const CODE_EXPRESSION = /^(?:(?:token|account|jar|auth|config|process|env|row|native)\.[A-Za-z_$][\w$]*|deriveRecordSecret|generated_utdid|native_account)$/
const SYNTHETIC_FILE_MARKER = /qwenapp-synthetic-fixture/i

function displayPath(path) {
  return (relative(root, path) || basename(path)).replaceAll("\\", "/")
}

function placeholderAllowed(path, text) {
  const name = displayPath(path)
  const explicitFixture = /^(?:tests|reference\/fixtures|review)\//.test(name) || /^scripts\/check[^/]*\.mjs$/.test(name)
  return explicitFixture || SYNTHETIC_FILE_MARKER.test(text.slice(0, 512))
}

function excluded(path) {
  const parts = path.split(sep)
  if (parts.some((part) => part === ".git" || part === ".agents" || part === ".private" || part === "node_modules")) return true
  const at = parts.indexOf("reference")
  // reference 根本身要继续遍历，才能到达允许扫描的 reference/fixtures；
  // 其直属证据文件与其它子目录仍在各自路径上被排除。
  if (at >= 0 && at === parts.length - 1) return false
  if (at >= 0 && parts[at + 1] !== "fixtures") return true
  return parts.some((part) => /(?:^|[-_.])recon(?:[-_.]|$)/i.test(part))
}

function filesUnder(directory, out = []) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    if (excluded(path)) continue
    if (entry.isDirectory()) filesUnder(path, out)
    else if (entry.isFile()) out.push(path)
  }
  return out
}

function cookieRule() {
  const names = [
    ["tongyi", "sso", "ticket"].join("_"),
    ["tongyi", "sso", "ticket", "hash"].join("_"),
    ["XSRF", "TOKEN"].join("-"),
    ["bx", "umidtoken"].join("-"),
    ["eo", "clt", "actkn"].join("-"),
    ["eo", "clt", "sacsft"].join("-"),
  ]
  return {
    name: "cookie-credential",
    regex: new RegExp(`(?:${names.join("|")})["']?\\s*[:=]\\s*["']?([A-Za-z0-9._~+/-]{12,}={0,2})`, "gi"),
    value: (match) => match[1],
  }
}

function assignmentValue(match) {
  return match[1] || match[2] || match[3] || ""
}

function namedAssignmentRule(name, names, { quotedOnly = false } = {}) {
  const valuePattern = quotedOnly
    ? `(?:"([^"\\r\\n]{12,})"|'([^'\\r\\n]{12,})')`
    : `(?:"([^"\\r\\n]{12,})"|'([^'\\r\\n]{12,})'|([A-Za-z0-9._~+/=-]{12,}))`
  return {
    name,
    regex: new RegExp(`(?<![A-Za-z0-9_])["']?(?:${names.join("|")})["']?\\s*[:=]\\s*${valuePattern}`, "gi"),
    value: assignmentValue,
  }
}

function assignmentRule() {
  const names = [
    ["access", "token"].join("_"), ["refresh", "token"].join("_"), ["record", "secret"].join("_"),
    ["api", "key"].join("_"), ["client", "secret"].join("_"), ["auth", "token"].join("_"),
    ["session", "token"].join("_"), "accessToken", "refreshToken", "recordSecret", "apiKey",
    "clientSecret", "authToken", "sessionToken", "password", "passwd", ["sms", "token"].join("_"), ["context", "token"].join("_"),
  ]
  return namedAssignmentRule("secret-assignment", names)
}

function nativeRule() {
  const names = [
    "serviceTicket", ["service", "ticket"].join("_"), "kpsWg", ["kps", "wg"].join("_"),
    "uidWsg", ["uid", "wsg"].join("_"), "utdid", "unetUtdid",
  ]
  return namedAssignmentRule("native-credential", names, { quotedOnly: true })
}

function nativeUcRule() {
  return {
    name: "native-uc-credential",
    regex: /["']?ucParams["']?\s*:\s*\{[^{}]{0,4096}?["']?ut["']?\s*:\s*["']([A-Za-z0-9_+/=-]{16,})["']/gi,
    value: (match) => match[1],
  }
}

function loginTokenRule() {
  return namedAssignmentRule("login-token", ["smsToken", "contextToken", "loginId2", ["_cs", "rf"].join("")], { quotedOnly: true })
}

function otpRule() {
  return {
    name: "sms-otp",
    regex: /(?<![A-Za-z0-9_])["']?(?:smsCode|sms_code|otp|otp_code|verification_code)["']?\s*[:=]\s*["']?(\d{6})(?!\d)/gi,
    value: (match) => match[1],
  }
}

function phoneRule() {
  return {
    name: "phone-number",
    regex: /(?<!\d)(?:\+?86[- ]?)?(1[3-9]\d{9})(?!\d)/g,
    value: (match) => match[0],
  }
}

function loginUrlSecretRule() {
  return {
    name: "login-url-secret",
    regex: /[?&](?:ticket|state|smsToken|contextToken)=([A-Za-z0-9._~+/=-]{8,})/gi,
    value: (match) => match[1],
  }
}

function pemRule() {
  const begin = ["-----BEGIN ", "PRIVATE KEY-----"].join("")
  return {
    name: "private-key",
    regex: new RegExp(begin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace("PRIVATE", "(?:RSA |EC |OPENSSH |DSA )?PRIVATE"), "g"),
    value: () => "present",
  }
}

const RULES = [
  pemRule(),
  {
    name: "jwt",
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    value: (match) => match[0],
  },
  {
    name: "bearer-token",
    regex: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}/gi,
    value: (match) => match[0].slice(7).trim(),
  },
  cookieRule(),
  nativeRule(),
  nativeUcRule(),
  loginTokenRule(),
  otpRule(),
  phoneRule(),
  loginUrlSecretRule(),
  assignmentRule(),
]

function likelyText(path) {
  const base = basename(path)
  return TEXT_EXTENSIONS.has(extname(base).toLowerCase()) || base === ".env" || base.startsWith(".env.") || !base.includes(".")
}

function findingsIn(path, text) {
  const findings = []
  for (const rule of RULES) {
    rule.regex.lastIndex = 0
    for (let match = rule.regex.exec(text); match; match = rule.regex.exec(text)) {
      const value = String(rule.value(match) || "")
      if (CODE_EXPRESSION.test(value) || (PLACEHOLDER.test(value) && placeholderAllowed(path, text))) continue
      findings.push({ file: displayPath(path), line: text.slice(0, match.index).split(/\r\n|\r|\n/).length, rule: rule.name })
      break
    }
  }
  return findings
}

function scan() {
  const rootStat = statSync(root)
  const files = rootStat.isFile() ? [root] : filesUnder(root)
  const findings = []
  for (const file of files) {
    if (!likelyText(file)) continue
    if (statSync(file).size > MAX_FILE_BYTES) {
      findings.push({ file: displayPath(file), line: 1, rule: "file-too-large" })
      continue
    }
    let text
    try { text = readFileSync(file, "utf8") } catch {
      findings.push({ file: displayPath(file), line: 1, rule: "read-failed" })
      continue
    }
    if (text.includes("\0")) {
      findings.push({ file: displayPath(file), line: 1, rule: "binary-not-scanned" })
      continue
    }
    findings.push(...findingsIn(file, text))
  }
  return findings
}

try {
  const findings = scan()
  for (const finding of findings) process.stdout.write(`${finding.file}:${finding.line}: ${finding.rule}\n`)
  process.stdout.write(`privacy-scan: ${findings.length} finding(s)\n`)
  if (findings.length) process.exitCode = 1
} catch (error) {
  process.stderr.write(`privacy-scan: ${error?.message || error}\n`)
  process.exitCode = 2
}
