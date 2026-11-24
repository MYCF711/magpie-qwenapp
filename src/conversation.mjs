import { createHash, randomUUID } from "node:crypto"
import { LIMITS } from "./constants.mjs"

function digest(value, length = 32) {
  return createHash("sha256").update(String(value)).digest("hex").slice(0, length)
}

function chainIdentity(messages) {
  const serialized = JSON.stringify(messages.map((message) => ({ role: message.role, content: message.content })))
  const first = JSON.stringify(messages[0] ? { role: messages[0].role, content: messages[0].content } : null)
  return `${digest(first)}:${messages.length}:${digest(serialized)}`
}

export function externalConversationId(body, headers) {
  const h = headers instanceof Headers ? headers : new Headers(headers || {})
  const candidates = [
    body?.session_id,
    body?.conversation_id,
    body?.chat_id,
    body?.metadata?.conversation_id,
    body?.metadata?.session_id,
    h.get("x-conversation-id"),
    h.get("x-session-id"),
    h.get("session-id"),
  ]
  const value = candidates.find((item) => typeof item === "string" && item.trim())
  return value ? digest(`external\n${value}`) : ""
}

/** 每账号独立 LRU；无宿主会话 ID 时，完整历史一变就创建新分支，避免首条相同导致串话。 */
export class ConversationStore {
  constructor({ capacity = LIMITS.conversations } = {}) {
    this.capacity = capacity
    this.entries = new Map()
  }

  resolve({ externalId = "", messages }) {
    const key = externalId ? `external:${externalId}` : `chain:${chainIdentity(messages)}`
    const previous = this.entries.get(key)
    const branch = previous || {
      session_id: randomUUID().replaceAll("-", ""),
      topic_id: randomUUID().replaceAll("-", ""),
      parent_req_id: "0",
      turn: 1,
    }
    this.entries.delete(key)
    this.entries.set(key, branch)
    while (this.entries.size > this.capacity) {
      this.entries.delete(this.entries.keys().next().value)
    }
    return { key, ...branch }
  }

  commit(key, reqId) {
    const branch = this.entries.get(key)
    if (!branch) return
    branch.parent_req_id = String(reqId)
    branch.turn = Number(branch.turn || 1) + 1
    this.entries.delete(key)
    this.entries.set(key, branch)
  }

  get size() { return this.entries.size }
}
