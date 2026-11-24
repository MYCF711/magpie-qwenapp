import { CODES, QwenError } from "./errors.mjs"

/**
 * 千问把额度/会员提示当成正常助手正文下发（实测含未渲染的 `{{membership_payment_buttons_card_1}}`
 * 模板占位符）。这类内容不是模型回答，必须转成 429 错误，不能出现在正文字段里。
 *
 * 判据刻意保守：只有短文本且命中明确额度/会员话术才算，避免误伤用户追问"额度上限"的正常回答。
 */
const NOTICE_MAX_CHARS = 600

const QUOTA_PATTERNS = Object.freeze([
  // 未渲染的支付/会员卡片模板：模型不会产出这种占位符。
  /\{\{\s*membership[_a-z0-9]*\}\}/i,
  // 5 小时窗口的累计用量提示。
  /累计用量[^。]{0,20}(?:达到|已达|超出)[^。]{0,8}额度上限/,
  // 当日体验额度提示。
  /(?:体验)?额度已(?:达|耗尽|用完)[^。]{0,12}(?:上限|明天)/,
  /今日[^。]{0,6}额度已(?:达|耗尽)[^。]{0,12}上限/,
  // 会员引导话术（与额度上限同时出现才算）。
  /(?:订阅|开通)[^。]{0,10}千问\s*Go!?\s*会员[^。]{0,12}(?:额度|恢复)/,
])

const QUOTA_HINT = /额度|用量|会员|恢复/


const FIVE_HOURS_SECONDS = 5 * 60 * 60
const MAX_RESET_SECONDS = 24 * 60 * 60

/**
 * 从额度提示里推出还要等多少秒，用于 Retry-After。
 * 千问的 5 小时额度窗口耗尽后通常给一个"将在 HH:MM 恢复"，按其时区（UTC+8）算；
 * 解析不到具体时刻时退回 5 小时窗口，避免只回一个没有时间信息的 429。
 */
export function quotaResetDelaySeconds(text, nowMs = Date.now()) {
  const value = String(text ?? "")
  const clock = /(\d{1,2})\s*[:：]\s*(\d{2})/.exec(value)
  if (clock) {
    const hour = Number(clock[1])
    const minute = Number(clock[2])
    if (hour < 24 && minute < 60) {
      // 以 UTC+8 墙上时间对齐，不依赖运行机器时区。
      const utc8Now = new Date(nowMs + 8 * 3600_000)
      const midnight = Date.UTC(utc8Now.getUTCFullYear(), utc8Now.getUTCMonth(), utc8Now.getUTCDate())
      const nowOfDay = (utc8Now.getUTCHours() * 3600 + utc8Now.getUTCMinutes() * 60 + utc8Now.getUTCSeconds()) * 1000
      let diff = midnight + (hour * 3600 + minute * 60) * 1000 - (midnight + nowOfDay)
      if (diff <= 0) diff += 24 * 3600_000
      return Math.min(Math.max(Math.round(diff / 1000), 60), MAX_RESET_SECONDS)
    }
  }
  if (/明天/.test(value)) {
    const utc8Now = new Date(nowMs + 8 * 3600_000)
    const midnight = Date.UTC(utc8Now.getUTCFullYear(), utc8Now.getUTCMonth(), utc8Now.getUTCDate() + 1)
    const diff = midnight - (nowMs + 8 * 3600_000)
    return Math.min(Math.max(Math.round(diff / 1000), 60), MAX_RESET_SECONDS)
  }
  return FIVE_HOURS_SECONDS
}

/** 判断一段助手文本是否是千问的额度/会员提示而不是真实回答。 */
export function isQuotaNotice(text) {
  const value = String(text ?? "")
  if (!value || value.length > NOTICE_MAX_CHARS) return false
  if (!QUOTA_HINT.test(value)) return false
  return QUOTA_PATTERNS.some((pattern) => pattern.test(value))
}

/** 命中即抛 429 + Retry-After；调用方据此在正文产出前中止，避免伪成功。 */
export function assertNotQuotaNotice(text, { model, now = Date.now() } = {}) {
  if (!isQuotaNotice(text)) return
  const retryAfter = quotaResetDelaySeconds(text, now)
  // 5 小时额度窗口：把恢复时刻换算成 HH:MM（UTC+8），错误信息里直接告诉用户等多久。
  const utc8 = new Date(now + 8 * 3600_000 + retryAfter * 1000)
  const clock = `${String(utc8.getUTCHours()).padStart(2, "0")}:${String(utc8.getUTCMinutes()).padStart(2, "0")}`
  throw new QwenError(
    `千问账号额度已用尽${model ? `（${model}）` : ""}，预计 ${clock}（UTC+8）恢复；这是上游额度提示而不是模型回答。请等待额度恢复或更换账号`,
    // 额度耗尽不是瞬时错误：标成不可重试，让插件立即失败并把 429 交给宿主，
    // 由 magpie 的账号接管切到下一个账号，而不是在本账号里空转重试。
    { status: 429, code: CODES.rateLimited, retryable: false, retryAfter },
  )
}