import test from "node:test"
import assert from "node:assert/strict"
import { accountLabelOf, authIdentity, maskMobile, refreshAuth, successAuth } from "../src/cookie.mjs"
import { securityCacheFile } from "../src/cache.mjs"

const NATIVE_BASE = {
  serviceTicket: "synthetic-service-ticket",
  kpsWg: "synthetic-kps-wg",
  nickname: "",
  uidWsg: "synthetic-uid-wsg",
  utdid: "synthetic-utdid",
}

function cookieFor(tag) {
  return [
    `tongyi_sso_ticket=synthetic-ticket-${tag}`,
    `tongyi_sso_ticket_hash=synthetic-ticket-hash-${tag}`,
    "XSRF-TOKEN=synthetic-xsrf",
  ].join("; ")
}

function nativeFor({ uid, key = "" }) {
  return { ...NATIVE_BASE, uId: uid, ...(key ? { securityMobile: key } : {}) }
}

test("maskMobile 只输出 3+4 掩码，非法/非手机号输入返回空", () => {
  assert.equal(maskMobile("19900000001"), "199****0001")
  assert.equal(maskMobile("+86 19900000001"), "199****0001")
  assert.equal(maskMobile("0086-199-0000-0001"), "199****0001")
  // 上游 security_mobile 可能已是脱敏形态，必须沿用而不是当成非法输入。
  assert.equal(maskMobile("199****0001"), "199****0001")
  for (const value of ["", "12345", "00000000000", "10000000000", "1990000000", "199000000012", "synthetic-nickname", null, undefined]) {
    assert.equal(maskMobile(value), "", String(value))
  }
})

test("accountLabelOf 优先脱敏手机号，其次可读昵称，最后 uid 后四位", () => {
  assert.equal(accountLabelOf({ mobile: "19900000001" }), "199****0001")
  assert.equal(accountLabelOf({ native: nativeFor({ uid: "1000000000000000001", key: "19900000001" }) }), "199****0001")
  assert.equal(accountLabelOf({ native: { ...NATIVE_BASE, uId: "1000000000000000001", nickname: "synthetic-nickname" } }), "synthetic-nickname")
  // 昵称本身是完整手机号时不能直接显示，退化为 uid 后四位。
  assert.equal(accountLabelOf({ native: { ...NATIVE_BASE, uId: "1000000000000000001", nickname: "19900000001" } }), "千问用户-0001")
  assert.equal(accountLabelOf({ native: { ...NATIVE_BASE, uId: "1000000000000000001" } }), "千问用户-0001")
  assert.equal(accountLabelOf({}), "千问用户")
})

test("accountLabelOf 输出绝不含完整手机号或 native 秘密", () => {
  const label = accountLabelOf({ mobile: "19900000001", native: nativeFor({ uid: "1000000000000000001", key: "19900000001" }) })
  assert.equal(label, "199****0001")
  for (const secret of ["19900000001", "synthetic-service-ticket", "synthetic-kps-wg", "synthetic-uid-wsg", "synthetic-utdid"]) {
    assert.ok(!label.includes(secret), label)
  }
})

test("三个不同账号的 accountId 互不相同且都可读", () => {
  const labels = [
    accountLabelOf({ native: nativeFor({ uid: "1000000000000000001", key: "19900000001" }) }),
    accountLabelOf({ native: nativeFor({ uid: "1000000000000000002", key: "13900000002" }) }),
    accountLabelOf({ native: { ...NATIVE_BASE, uId: "1000000000000000003", nickname: "synthetic-nickname" } }),
  ]
  assert.deepEqual(labels, ["199****0001", "139****0002", "synthetic-nickname"])
  assert.equal(new Set(labels).size, 3)
})

test("successAuth 用脱敏手机号做 accountId，完整号码不进入 key/metadata", () => {
  const native = nativeFor({ uid: "1000000000000000001", key: "19900000001" })
  const auth = successAuth({ cookie: cookieFor("a"), native })
  assert.equal(auth.accountId, "199****0001")
  assert.equal(auth.uid, "1000000000000000001")
  assert.ok(!JSON.stringify(auth.metadata).includes("19900000001"))
  assert.equal(auth.type, "success")
})

test("纯 Cookie 账号没有手机号时回退指纹，不产生空 accountId", () => {
  const auth = successAuth(cookieFor("plain"), { note: "" })
  // 纯 Cookie 凭据没有 native 字段，前三档优先级都取不到 —— 必须退回指纹，
  // 否则 magpie 会把 auth.key（一整坨 JSON credential）截断显示成 `API key …"}}}`
  assert.match(auth.accountId, /^千问用户-[0-9a-f]{4}$/)
  assert.ok(!auth.accountId.includes("{"), "accountId 不得是 auth.key 的片段")
  assert.equal(auth.uid, auth.metadata.accountFingerprint)
})

test("两个纯 Cookie 账号的显示名不同，且都不含凭据内容", () => {
  const a = successAuth(cookieFor("plain-a"))
  const b = successAuth(cookieFor("plain-b"))
  assert.notEqual(a.accountId, b.accountId)
  for (const auth of [a, b]) {
    assert.match(auth.accountId, /^千问用户-[0-9a-f]{4}$/)
    assert.ok(!auth.accountId.includes("tongyi_sso"), "显示名不得回显凭据")
  }
})

test("securityCacheFile 对不同账号（不同 Cookie）必然不同文件名", () => {
  const a = successAuth({ cookie: cookieFor("a"), native: nativeFor({ uid: "1000000000000000001" }) })
  const b = successAuth({ cookie: cookieFor("b"), native: nativeFor({ uid: "1000000000000000002" }) })
  assert.notEqual(securityCacheFile(authIdentity(a)), securityCacheFile(authIdentity(b)))
})

test("相同 uid 但不同 Cookie 也绝不共用安全缓存（账号隔离底线）", () => {
  const sharedUid = "1000000000000000001"
  const a = successAuth({ cookie: cookieFor("a"), native: nativeFor({ uid: sharedUid }) })
  const b = successAuth({ cookie: cookieFor("b"), native: nativeFor({ uid: sharedUid }) })
  assert.notEqual(authIdentity(a), authIdentity(b))
  assert.notEqual(securityCacheFile(authIdentity(a)), securityCacheFile(authIdentity(b)))
})

test("refreshAuth 为旧记录补可读名，但不覆盖宿主已设置的 accountId", () => {
  const legacy = { key: JSON.stringify({ cookie: cookieFor("legacy"), native: nativeFor({ uid: "1000000000000000001", key: "19900000001" }) }), uid: "1000000000000000001" }
  const filled = refreshAuth(legacy)
  assert.equal(filled.accountId, "199****0001")

  const named = refreshAuth({ ...legacy, accountId: "我的千问主号" })
  assert.equal(named.accountId, "我的千问主号")
})

test("refreshAuth 不把完整手机号写进 metadata", () => {
  const merged = refreshAuth({ key: JSON.stringify({ cookie: cookieFor("m"), native: nativeFor({ uid: "1000000000000000001", key: "19900000001" }) }) })
  const text = JSON.stringify({ accountId: merged.accountId, metadata: merged.metadata })
  assert.ok(!text.includes("19900000001"), text)
  assert.equal(merged.metadata.kind, "qianwen-native")
  assert.equal(merged.metadata.userId, "1000000000000000001")
})
