import test from "node:test"
import assert from "node:assert/strict"
import { isQuotaNotice, assertNotQuotaNotice, quotaResetDelaySeconds } from "../src/quota-notice.mjs"

// 实测原文（已脱敏模板标记）：千问把额度提示当助手正文下发。
const REAL_5H = "你在5小时内的累计用量已达到额度上限，我们将在 08:40 为你恢复当前任务。也可以订阅千问Go!会员，获取更多额度后，发送“继续”即可马上恢复当前任务。{{membership_payment_buttons_card_1}}"
const REAL_DAILY = "今日体验额度已达上限，明天再来吧！"

test("识别真实额度提示原文（含未渲染卡片模板）", () => {
  assert.equal(isQuotaNotice(REAL_5H), true)
  assert.equal(isQuotaNotice(REAL_DAILY), true)
})

test("常见变体也识别：不同时间/措辞", () => {
  for (const text of [
    "你在5小时内的累计用量已达额度上限，我们将在 23:10 为你恢复当前任务。",
    "累计用量已经达到额度上限，请稍后再试。",
    "体验额度已耗尽，明天再来吧。",
    "订阅千问 Go 会员获取更多额度后即可恢复",
    "额度已达上限{{membership_payment_buttons_card_2}}",
  ]) {
    assert.equal(isQuotaNotice(text), true, text)
  }
})

test("绝不误伤正常回答", () => {
  for (const text of [
    "额度上限是指账户在单位时间内可用的 token 总量。",
    "你可以通过订阅会员提升额度。",
    "5 小时窗口是常见的限流设计。",
    "这是一段很长的正常回答，里面提到了额度、用量、会员、恢复这些词，但它不是系统提示。",
    "",
    null,
    undefined,
  ]) {
    assert.equal(isQuotaNotice(text), false, String(text))
  }
})

test("超长文本不判定（防止把长回答误判为提示）", () => {
  assert.equal(isQuotaNotice(`${REAL_DAILY}${"补充说明。".repeat(200)}`), false)
})

test("命中即抛 429 rate_limited，且消息不含上游原文", () => {
  assert.throws(
    () => assertNotQuotaNotice(REAL_5H, { model: "qwen4-max", now: Date.UTC(2026, 10, 23, 19, 55, 0) }),
    (error) => {
      assert.equal(error.status, 429)
      assert.equal(error.code, "rate_limited")
      // 额度耗尽不是瞬时错误：必须不可重试，让宿主立即切账号。
      assert.equal(error.retryable, false)
      assert.match(error.message, /额度已用尽/)
      assert.ok(!error.message.includes("{{membership_payment"), "不得回显上游模板原文")
      assert.match(error.message, /预计 \d{2}:\d{2}（UTC\+8）恢复/)
      assert.equal(error.retryAfter, 17100)
      return true
    },
  )
})

test("未命中不抛错", () => {
  assert.doesNotThrow(() => assertNotQuotaNotice("你好，我是一个助手。"))
  assert.doesNotThrow(() => assertNotQuotaNotice(""))
})
test("Retry-After：5 小时额度按 08:40 恢复算出 4.75 小时", () => {
  // UTC+8 03:55 收到"将在 08:40 恢复"
  const now = Date.UTC(2026, 10, 23, 19, 55, 0)
  assert.equal(quotaResetDelaySeconds(REAL_5H, now), 17100)
})

test("Retry-After：只有“明天”时算到次日 00:00（UTC+8）", () => {
  const now = Date.UTC(2026, 10, 23, 19, 55, 0) // UTC+8 11-24 03:55
  const seconds = quotaResetDelaySeconds(REAL_DAILY, now)
  // UTC+8 墙上日期是 11-24，次日 00:00 即 UTC 11-25 00:00 减 8 小时时差。
  const nextMidnightUtc8 = Date.UTC(2026, 10, 25, 0, 0, 0) - 8 * 3600_000
  assert.equal(seconds, Math.round((nextMidnightUtc8 - now) / 1000))
  assert.ok(seconds > 0 && seconds <= 24 * 3600)
})

test("Retry-After：没有时间信息时退回 5 小时窗口", () => {
  assert.equal(quotaResetDelaySeconds("额度已达上限", Date.UTC(2026, 10, 23, 19, 55, 0)), 5 * 3600)
})

test("已过当天的恢复时刻时顺延到次日，不返回负数", () => {
  const now = Date.UTC(2026, 10, 23, 12, 0, 0) // UTC+8 20:00，早过了 08:40
  const seconds = quotaResetDelaySeconds(REAL_5H, now)
  assert.ok(seconds > 0 && seconds <= 24 * 3600, String(seconds))
  assert.equal(seconds, 12 * 3600 + 40 * 60) // 次日 08:40
})

test("错误对象带 retryAfter，asErrorResponse 会写成 Retry-After 头", async () => {
  const { asErrorResponse } = await import("../src/errors.mjs")
  let error
  try { assertNotQuotaNotice(REAL_5H, { now: Date.UTC(2026, 10, 23, 19, 55, 0) }) } catch (e) { error = e }
  const response = asErrorResponse(error)
  assert.equal(response.status, 429)
  assert.equal(response.headers.get("retry-after"), "17100")
  const body = await response.json()
  assert.equal(body.error.code, "rate_limited")
  assert.ok(!JSON.stringify(body).includes("{{membership_payment"))
})

test("额度耗尽必须不可重试：5 小时窗口内重试无意义，应立即交给宿主切换账号", () => {
  let error
  try { assertNotQuotaNotice(REAL_5H, { now: Date.UTC(2026, 10, 23, 19, 55, 0) }) } catch (e) { error = e }
  assert.equal(error.retryable, false)
  assert.equal(error.status, 429)
  assert.equal(error.code, "rate_limited")
  // 仍要带 Retry-After，供宿主/客户端安排下一次可用时刻
  assert.ok(error.retryAfter > 0)
})
