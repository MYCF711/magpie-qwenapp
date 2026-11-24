import test from "node:test"
import assert from "node:assert/strict"
import { isQuotaNotice, assertNotQuotaNotice } from "../src/quota-notice.mjs"

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
    () => assertNotQuotaNotice(REAL_5H, { model: "qwen4-max" }),
    (error) => {
      assert.equal(error.status, 429)
      assert.equal(error.code, "rate_limited")
      assert.equal(error.retryable, true)
      assert.match(error.message, /额度已用尽/)
      assert.ok(!error.message.includes("{{membership_payment"), "不得回显上游模板原文")
      assert.ok(!error.message.includes("08:40"), "不得回显上游时间")
      return true
    },
  )
})

test("未命中不抛错", () => {
  assert.doesNotThrow(() => assertNotQuotaNotice("你好，我是一个助手。"))
  assert.doesNotThrow(() => assertNotQuotaNotice(""))
})