import { createStreamReader } from "./stream-reader.mjs"
import { CODES, QwenError } from "./errors.mjs"

function cancelQuietly(reader, reason) {
  try { void reader.cancel(reason).catch(() => {}) } catch {}
}

/** 真流式空闲看门狗；totalMs 仅用于有界 JSON/错误体，SSE 默认不设置总时长。 */
export function withIdleTimeout(body, { timeoutMs = 60_000, totalMs, signal } = {}) {
  if (!body || typeof body.getReader !== "function") {
    throw new QwenError("上游响应没有可读取的流", { status: 502, code: CODES.upstreamError })
  }
  const reader = createStreamReader(body.getReader())
  const local = new AbortController()
  const onAbort = () => local.abort(signal?.reason || new DOMException("The operation was aborted.", "AbortError"))
  signal?.addEventListener("abort", onAbort, { once: true })
  if (signal?.aborted) onAbort()
  const totalTimer = Number.isFinite(totalMs) && totalMs > 0 ? setTimeout(() => {
    local.abort(new QwenError(`上游响应体总时长超过 ${totalMs}ms`, {
      status: 504,
      code: CODES.upstreamTimeout,
    }))
  }, totalMs) : null
  const cleanup = () => {
    if (totalTimer) clearTimeout(totalTimer)
    signal?.removeEventListener("abort", onAbort)
  }
  let ended = false
  return new ReadableStream({
    async pull(controller) {
      if (ended) return
      try {
        const result = await reader.read({ timeoutMs, signal: local.signal })
        if (result.done) {
          ended = true
          cleanup()
          controller.close()
        } else {
          controller.enqueue(result.value)
        }
      } catch (error) {
        ended = true
        cleanup()
        const timeout = error?.code === "ERR_STREAM_READ_TIMEOUT"
        const wrapped = timeout
          ? new QwenError(`上游流连续 ${timeoutMs}ms 没有新数据`, {
              status: 504,
              code: CODES.upstreamTimeout,
              cause: error,
            })
          : error
        controller.error(wrapped)
        cancelQuietly(reader, wrapped)
      }
    },
    cancel(reason) {
      ended = true
      cleanup()
      cancelQuietly(reader, reason)
    },
  })
}

/** 原生 OpenAI SSE 直通仍受总字节上限约束；不先收完整响应。 */
export function withByteLimit(body, { maxBytes = 32 * 1024 * 1024 } = {}) {
  if (!body || typeof body.getReader !== "function") {
    throw new QwenError("上游响应没有可读取的流", { status: 502, code: CODES.upstreamError })
  }
  const reader = body.getReader()
  let bytes = 0
  let ended = false
  return new ReadableStream({
    async pull(controller) {
      if (ended) return
      try {
        const { done, value } = await reader.read()
        if (done) {
          ended = true
          controller.close()
          return
        }
        bytes += value?.byteLength || 0
        if (bytes > maxBytes) {
          ended = true
          const error = new QwenError(`上游响应超过 ${maxBytes} 字节上限`, { status: 502, code: CODES.upstreamError })
          controller.error(error)
          cancelQuietly(reader, error)
          return
        }
        controller.enqueue(value)
      } catch (error) {
        ended = true
        controller.error(error)
        cancelQuietly(reader, error)
      }
    },
    cancel(reason) {
      ended = true
      cancelQuietly(reader, reason)
    },
  })
}
