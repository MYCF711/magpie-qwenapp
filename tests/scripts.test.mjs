import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)))
const VERIFY = join(ROOT, "scripts", "verify-live.mjs")
const SCAN = join(ROOT, "scripts", "privacy-scan.mjs")

function cleanEnv() {
  const env = { ...process.env }
  for (const key of Object.keys(env)) if (key.startsWith("QIANWEN_")) delete env[key]
  return env
}

function run(script, args = [], env = cleanEnv()) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: ROOT,
    env,
    encoding: "utf8",
    timeout: 15_000,
    windowsHide: true,
  })
}

function temporaryDirectory(t) {
  const directory = mkdtempSync(join(tmpdir(), "qwenapp-privacy-test-"))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  return directory
}

test("verify-live 默认与 QIANWEN_LIVE=true 都只打印帮助，不读显式坏路径", () => {
  for (const live of [undefined, "0", "true", "yes"]) {
    const env = cleanEnv()
    if (live !== undefined) env.QIANWEN_LIVE = live
    env.QIANWEN_COOKIE = "synthetic-cookie-that-must-not-be-used"
    env.QIANWEN_COOKIE_FILE = join(ROOT, "definitely-not-present.credentials")
    const result = run(VERIFY, [], env)
    assert.equal(result.status, 0, result.stderr)
    assert.match(result.stdout, /Qianwen live verification \(opt-in\)/)
    assert.match(result.stdout, /QIANWEN_LIVE=1/)
    assert.doesNotMatch(result.stdout + result.stderr, /live verification failed|ENOENT|https?:\/\//)
  }
})

test("privacy-scan 检出真实形状 Cookie/token/private key，且不回显秘密", (t) => {
  const directory = temporaryDirectory(t)
  const cookieSecret = ["A9f2Q7", "Lm4Vx8", "Zp1Qr6", "T5w3Hy"].join("")
  const tokenSecret = ["N8v3Kc", "6Rq2Xy", "9Lm4Zt", "7Pw5Hs"].join("")
  const privateHeader = ["-----BEGIN ", "PRIVATE KEY-----"].join("")
  writeFileSync(join(directory, "cookie.txt"), `tongyi_sso_ticket=${cookieSecret}; other=value\n`)
  writeFileSync(join(directory, "token.json"), `${JSON.stringify("access_token")}: ${JSON.stringify(tokenSecret)}\n`)
  writeFileSync(join(directory, "key.txt"), `${privateHeader}\nsynthetic-body-not-a-key\n`)
  const result = run(SCAN, [directory])
  assert.equal(result.status, 1, result.stdout + result.stderr)
  assert.match(result.stdout, /cookie-credential/)
  assert.match(result.stdout, /secret-assignment/)
  assert.match(result.stdout, /private-key/)
  assert.ok(!result.stdout.includes(cookieSecret))
  assert.ok(!result.stdout.includes(tokenSecret))
  assert.ok(!result.stdout.includes(privateHeader))
})

test("F-05 privacy-scan 覆盖 native 字段与 .env/.py/.ps1/.pem，输出文件/行号且不回显", (t) => {
  const directory = temporaryDirectory(t)
  const nativeValues = {
    serviceTicket: ["R4v9H2", "k7Q5x8M1p6"].join(""),
    kpsWg: ["T8m3Q7", "v2L5c9X4z6"].join(""),
    uidWsg: ["W6n1P9", "s4K7r2V8y3"].join(""),
    utdid: ["012345", "6789ab", "cdef", "01234567"].join(""),
  }
  for (const [index, [field, value]] of Object.entries(nativeValues).entries()) {
    writeFileSync(join(directory, `native-${index}.json`), JSON.stringify({ [field]: value }))
  }
  const ucSecret = ["O9x2K5", "v8Q1m4R7t3Y6"].join("")
  writeFileSync(join(directory, "native-uc.json"), JSON.stringify({ ucParams: { ut: ucSecret } }))
  const envSecret = ["H5j8N2", "q7W4z9C6v1"].join("")
  writeFileSync(join(directory, ".env"), `ACCESS_TOKEN=${envSecret}\n`)
  const pySecret = ["P3x7M2", "k9V6q4R8t1"].join("")
  writeFileSync(join(directory, "secret.py"), `api_key = '${pySecret}'\n`)
  const psSecret = ["S9c4L7", "n2X6v1Q8m3"].join("")
  writeFileSync(join(directory, "secret.ps1"), `$clientSecret = '${psSecret}'\n`)
  const privateHeader = ["-----BEGIN ", "PRIVATE KEY-----"].join("")
  writeFileSync(join(directory, "secret.pem"), `${privateHeader}\nsynthetic-body\n`)
  writeFileSync(join(directory, "expression.py"), 'service_ticket = native_account["fields"][0]\n')

  const result = run(SCAN, [directory])
  assert.equal(result.status, 1, result.stdout + result.stderr)
  for (let index = 0; index < 4; index += 1) assert.match(result.stdout, new RegExp(`native-${index}\\.json:1: native-credential`))
  assert.match(result.stdout, /native-uc\.json:1: native-uc-credential/)
  assert.match(result.stdout, /\.env:1: secret-assignment/)
  assert.match(result.stdout, /secret\.py:1: secret-assignment/)
  assert.match(result.stdout, /secret\.ps1:1: secret-assignment/)
  assert.match(result.stdout, /secret\.pem:1: private-key/)
  assert.doesNotMatch(result.stdout, /expression\.py/)
  for (const secret of [...Object.values(nativeValues), ucSecret, envSecret, pySecret, psSecret, privateHeader]) assert.ok(!result.stdout.includes(secret))
})

test("F-05 占位豁免仅限 fixture/test 路径或唯一合成标记，test 子串不豁免生产文件", (t) => {
  const directory = temporaryDirectory(t)
  mkdirSync(join(directory, "tests"), { recursive: true })
  writeFileSync(join(directory, "tests", "fixture.env"), "ACCESS_TOKEN=example-access-token-value\n")
  writeFileSync(join(directory, "marked.env"), "# qwenapp-synthetic-fixture\nACCESS_TOKEN=example-access-token-value\n")
  let result = run(SCAN, [directory])
  assert.equal(result.status, 0, result.stdout + result.stderr)

  const production = ["production-test-", "R8v2K7m4Q9x6"].join("")
  writeFileSync(join(directory, "production.env"), `ACCESS_TOKEN=${production}\n`)
  result = run(SCAN, [directory])
  assert.equal(result.status, 1)
  assert.match(result.stdout, /production\.env:1: secret-assignment/)
  assert.ok(!result.stdout.includes(production))

  const realShape = ["Z8v2K7", "m4Q9x6R3t5"].join("")
  writeFileSync(join(directory, "tests", "not-a-placeholder.env"), `ACCESS_TOKEN=${realShape}\n`)
  result = run(SCAN, [directory])
  assert.equal(result.status, 1)
  assert.match(result.stdout, /not-a-placeholder\.env:1: secret-assignment/)
  assert.ok(!result.stdout.includes(realShape))
})

test("F-05 超过4MiB的文件必须失败而不是跳过，且不输出文件内容", (t) => {
  const directory = temporaryDirectory(t)
  const secret = ["B7v2K9", "m4Q6x1R8t3"].join("")
  writeFileSync(join(directory, "oversize.json"), `{"access_token":"${secret}"}\n${"x".repeat(4 * 1024 * 1024)}`)
  const result = run(SCAN, [directory])
  assert.equal(result.status, 1, result.stdout + result.stderr)
  assert.match(result.stdout, /oversize\.json:1: file-too-large/)
  assert.ok(!result.stdout.includes(secret))
  assert.doesNotMatch(result.stdout, /xxxxxx/)
})

test("T14 privacy-scan 覆盖手机号/OTP/smsToken/contextToken/CSRF/loginId2/URL ticket且不回显", (t) => {
  const directory = temporaryDirectory(t)
  const phone = ["199", "00000000"].join("")
  const otp = ["654", "321"].join("")
  const tokenValues = {
    smsToken: ["Sms9K2", "v7Q4x8M1p6"].join(""),
    contextToken: ["Ctx8N3", "q6W2z9C5v1"].join(""),
    _csrf: ["Csrf7M", "2k9V6q4R8t1"].join(""),
    loginId2: ["Rsa4L8", "n2X6v1Q9m3"].join(""),
  }
  writeFileSync(join(directory, "phone.json"), JSON.stringify({ mobile: phone }))
  writeFileSync(join(directory, "otp.json"), JSON.stringify({ smsCode: otp }))
  for (const [field, value] of Object.entries(tokenValues)) writeFileSync(join(directory, `${field}.json`), JSON.stringify({ [field]: value }))
  const urlSecret = ["Url5T8", "r2Y7m4Q9x6"].join("")
  writeFileSync(join(directory, "url.txt"), `https://www.qianwen.com/desktop-app?ticket=${urlSecret}`)
  const envToken = ["Env8S2", "m7Q4x9K6v1"].join("")
  writeFileSync(join(directory, "login.env"), `SMS_TOKEN=${envToken}\n`)

  const result = run(SCAN, [directory])
  assert.equal(result.status, 1, result.stdout + result.stderr)
  assert.match(result.stdout, /phone\.json:1: phone-number/)
  assert.match(result.stdout, /otp\.json:1: sms-otp/)
  for (const field of Object.keys(tokenValues)) assert.match(result.stdout, new RegExp(`${field.replace("_", "\\_")}\\.json:1: login-token`))
  assert.match(result.stdout, /url\.txt:1: login-url-secret/)
  assert.match(result.stdout, /login\.env:1: secret-assignment/)
  for (const secret of [phone, otp, ...Object.values(tokenValues), urlSecret, envToken]) assert.ok(!result.stdout.includes(secret))
})

test("F-05 package check 必须接入 privacy-scan", () => {
  const manifest = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"))
  assert.match(manifest.scripts.check, /privacy-scan\.mjs/)
})

test("privacy-scan 排除 .private、reference 证据/recon，但扫描 fixtures 与 artifacts", (t) => {
  const directory = temporaryDirectory(t)
  const secret = ["Q7m2Vx", "9Zp4Lr", "6Ty1Wc", "8Hs3Kn"].join("")
  for (const folder of [".private", join("reference", "evidence"), join("reference", "recon")]) {
    mkdirSync(join(directory, folder), { recursive: true })
    writeFileSync(join(directory, folder, "secret.txt"), `tongyi_sso_ticket=${secret}\n`)
  }
  mkdirSync(join(directory, "reference", "fixtures"), { recursive: true })
  writeFileSync(join(directory, "reference", "fixtures", "safe.sse"), "data: {\"synthetic\":true}\n\n")
  let result = run(SCAN, [directory])
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.match(result.stdout, /0 finding/)

  writeFileSync(join(directory, "reference", "fixtures", "unsafe.txt"), `tongyi_sso_ticket=${secret}\n`)
  result = run(SCAN, [directory])
  assert.equal(result.status, 1)
  assert.match(result.stdout, /unsafe\.txt:\d+: cookie-credential/)
  assert.ok(!result.stdout.includes(secret))

  mkdirSync(join(directory, "artifacts"), { recursive: true })
  writeFileSync(join(directory, "artifacts", "delivery.txt"), `tongyi_sso_ticket=${secret}\n`)
  result = run(SCAN, [directory])
  assert.equal(result.status, 1)
  assert.match(result.stdout, /delivery\.txt:\d+: cookie-credential/)
  assert.ok(!result.stdout.includes(secret))
})

test("privacy-scan 扫描交付树和自身无误报，合成占位符不告警", (t) => {
  const directory = temporaryDirectory(t)
  mkdirSync(join(directory, "tests"), { recursive: true })
  writeFileSync(join(directory, "tests", "synthetic.mjs"), [
    'const ticket = "synthetic-ticket-value"',
    'const access_token = "example-access-token-value"',
    'const bearer = "Bearer synthetic-bearer-token-value"',
    'const computed = token.sacsft',
    "",
  ].join("\n"))
  assert.equal(run(SCAN, [directory]).status, 0)
  const delivery = run(SCAN, [ROOT])
  assert.equal(delivery.status, 0, delivery.stdout + delivery.stderr)
  assert.match(delivery.stdout, /0 finding/)
})
