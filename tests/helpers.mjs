import { successAuth } from "../src/cookie.mjs"

export const SYNTHETIC_COOKIE = [
  "tongyi_sso_ticket=synthetic-ticket",
  "tongyi_sso_ticket_hash=synthetic-ticket-hash",
  "XSRF-TOKEN=synthetic-xsrf",
  "bx-umidtoken=synthetic-umid",
].join("; ")

export function syntheticAuth(note = "synthetic-account") {
  return successAuth(SYNTHETIC_COOKIE, { note })
}

export function registerPayload(count = 8, prefix = "account") {
  return {
    status: 0,
    data: {
      unifyRelate: [
        {
          businessScene: "qwen_chat",
          "eo-clt-dvidn": `synthetic-device-${prefix}`,
          "eo-clt-actkn": `synthetic-actkn-${prefix}`,
          "eo-clt-snver": "synthetic-version",
          "eo-clt-bacsft": Array.from({ length: count }, (_, index) => `synthetic-sacsft-${prefix}-${index}`),
        },
        {
          businessScene: "qwen_web_capsule",
          "eo-clt-dvidn": `synthetic-device-${prefix}`,
          "eo-clt-actkn": `synthetic-actkn-${prefix}`,
          "eo-clt-snver": "synthetic-version",
          "eo-clt-bacsft": [],
        },
      ],
    },
  }
}

export function chatRequest({ stream = true, content = "synthetic question", ...extra } = {}) {
  return {
    model: "Qwen",
    messages: [{ role: "user", content }],
    stream,
    ...extra,
  }
}

export function sseResponse(text, init = {}) {
  return new Response(text, {
    status: 200,
    ...init,
    headers: { "content-type": "text/event-stream; charset=utf-8", ...(init.headers || {}) },
  })
}

export function jsonResponse(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", ...headers },
  })
}

export async function errorPayload(response) {
  return { status: response.status, headers: response.headers, ...(await response.json()) }
}

export function deferred() {
  let resolve
  let reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

export async function readChunks(stream) {
  const reader = stream.getReader()
  const chunks = []
  while (true) {
    const { done, value } = await reader.read()
    if (done) return chunks
    chunks.push(value)
  }
}
