#!/usr/bin/env node
// 只有 QIANWEN_LIVE=1 才会导入插件、读取凭据或发起网络请求。
import { readFile } from "node:fs/promises"
import { performance } from "node:perf_hooks"

const USAGE = `Qianwen live verification (opt-in)

Usage:
  QIANWEN_LIVE=1 QIANWEN_COOKIE='<cookie>' node scripts/verify-live.mjs
  QIANWEN_LIVE=1 QIANWEN_COOKIE_FILE='<explicit-path>' node scripts/verify-live.mjs

Optional:
  QIANWEN_MODEL=Qwen
  QIANWEN_PROMPT='Reply with exactly: ok'
  QIANWEN_STREAM=0

Default mode prints this help only. It never reads credentials or accesses the network.
Cookie sources are mutually exclusive; no credential is printed or written to disk.`

function fail(message) {
  const error = new Error(message)
  error.liveUsage = true
  return error
}

async function credentialFrom(env) {
  const inline = String(env.QIANWEN_COOKIE || "").trim()
  const file = String(env.QIANWEN_COOKIE_FILE || "").trim()
  if (inline && file) throw fail("QIANWEN_COOKIE 与 QIANWEN_COOKIE_FILE 只能选择一个")
  if (inline) return inline
  if (!file) throw fail("真实校验需要 QIANWEN_COOKIE 或显式 QIANWEN_COOKIE_FILE")
  const value = (await readFile(file, "utf8")).trim()
  if (!value) throw fail("显式凭据文件为空")
  return value
}

function completionContent(chunk) {
  const delta = chunk?.choices?.[0]?.delta
  if (typeof delta?.content === "string") return delta.content
  if (typeof delta?.reasoning_content === "string") return delta.reasoning_content
  if (typeof delta?.reasoning === "string") return delta.reasoning
  return ""
}

async function verifyStream(response, started) {
  if (!response.body) throw new Error("流式响应没有 body")
  const { readSseEvents } = await import("../src/openai-sse.mjs")
  let firstTokenMs = null
  let chunks = 0
  let done = false
  let text = ""
  for await (const frame of readSseEvents(response.body)) {
    const data = frame.data.trim()
    if (!data) continue
    if (data === "[DONE]") {
      done = true
      continue
    }
    let chunk
    try { chunk = JSON.parse(data) } catch { throw new Error("流式响应包含非 JSON data") }
    if (chunk?.error) throw new Error(String(chunk.error.message || "上游流式错误"))
    if (!chunk || chunk.object !== "chat.completion.chunk" || !Array.isArray(chunk.choices)) {
      throw new Error("流式响应不是 OpenAI chat.completion.chunk")
    }
    chunks += 1
    const part = completionContent(chunk)
    if (part) {
      if (firstTokenMs === null) firstTokenMs = Math.round(performance.now() - started)
      text += part
    }
  }
  if (!done) throw new Error("流式响应缺少 [DONE]")
  if (!text) throw new Error("流式响应没有内容 token")
  return { firstTokenMs, chunks, text }
}

async function verifyJson(response, started) {
  let completion
  try { completion = await response.json() } catch { throw new Error("非流式响应不是合法 JSON") }
  if (completion?.error) throw new Error(String(completion.error.message || "上游错误"))
  if (completion?.object !== "chat.completion" || !Array.isArray(completion.choices)) {
    throw new Error("非流式响应不是 OpenAI chat.completion")
  }
  const message = completion.choices[0]?.message
  const text = typeof message?.content === "string"
    ? message.content
    : String(message?.reasoning_content || message?.reasoning || "")
  if (!text) throw new Error("非流式响应没有内容")
  return { firstTokenMs: Math.round(performance.now() - started), chunks: 1, text, usage: completion.usage }
}

async function main() {
  if (process.env.QIANWEN_LIVE !== "1") {
    process.stdout.write(`${USAGE}\n`)
    return
  }

  let cookie = ""
  try {
    cookie = await credentialFrom(process.env)
    const [{ QwenAppAuthPlugin }, { successAuth }, { sanitizeText }] = await Promise.all([
      import("../index.mjs"),
      import("../src/cookie.mjs"),
      import("../src/errors.mjs"),
    ])
    const plugin = await QwenAppAuthPlugin()
    const auth = successAuth(cookie)
    const loader = await plugin.auth.loader(async () => auth)
    if (typeof loader.fetch !== "function") throw new Error("auth.loader 未提供 fetch")
    const stream = process.env.QIANWEN_STREAM !== "0"
    const body = {
      model: process.env.QIANWEN_MODEL || "Qwen",
      messages: [{ role: "user", content: process.env.QIANWEN_PROMPT || "Reply with exactly: ok" }],
      stream,
    }
    const started = performance.now()
    const response = await loader.fetch(`${loader.baseURL}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: stream ? "text/event-stream" : "application/json" },
      body: JSON.stringify(body),
    })
    if (!response.ok) {
      const { readBounded, extractErrorMessage } = await import("../src/errors.mjs")
      let detail = `HTTP ${response.status}`
      try {
        const text = await readBounded(response.clone(), { limit: 64 * 1024 })
        try { detail = extractErrorMessage(JSON.parse(text)) } catch { if (text.trim()) detail = text }
      } catch {}
      throw new Error(sanitizeText(detail, [cookie]))
    }
    const result = stream ? await verifyStream(response, started) : await verifyJson(response, started)
    const report = {
      ok: true,
      stream,
      firstTokenMs: result.firstTokenMs,
      totalMs: Math.round(performance.now() - started),
      chunks: result.chunks,
      ...(result.usage ? { usage: result.usage } : {}),
      content: result.text,
    }
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
  } catch (error) {
    const { sanitizeText } = await import("../src/errors.mjs")
    process.stderr.write(`live verification failed: ${sanitizeText(error?.message || error, [cookie])}\n`)
    process.exitCode = 1
  }
}

await main()
