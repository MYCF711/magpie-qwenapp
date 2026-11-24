import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { buildChatBody, hasUnsupportedTools, normalizeMessages } from "../src/protocol.mjs"

const NATIVE_SHAPE = JSON.parse(readFileSync(new URL("../reference/fixtures/native-empirical-shape.json", import.meta.url), "utf8"))

const CALLER_MESSAGES = [
  { role: "system", content: "caller system: keep verbatim\n第二行" },
  { role: "user", content: [{ type: "text", text: "caller user 🌐 " }, { type: "input_text", text: "保留原文" }] },
  { role: "assistant", content: "caller assistant: exact" },
  { role: "user", content: "latest caller question" },
]

function conversation() {
  return { session_id: "synthetic-session", topic_id: "synthetic-topic", parent_req_id: "" }
}

function assertNativeShape(body, input) {
  assert.equal(body.req_id, undefined, "原生实捕没有 req_id；Web /api/v2 才保留它")
  assert.equal(body.request_id, "synthetic-req-id")
  assert.equal(body.messages.length, input.messages.length)
  assert.deepEqual(body.messages.map((message) => message.role), input.messages.map((message) => message.role))
  assert.deepEqual(body.messages.map((message) => message.content), [
    "caller system: keep verbatim\n第二行",
    "caller user 🌐 保留原文",
    "caller assistant: exact",
    "latest caller question",
  ])
  for (const [index, message] of body.messages.entries()) {
    assert.deepEqual(Object.keys(message).sort(), ["content", "role"], "原生实捕 messages 仅 role/content")
    assert.equal(message.content, normalizeMessages(input)[index].content)
    assert.equal(message.official_persona, undefined)
  }
  assert.equal(body.session_id, "synthetic-session")
  assert.equal(body.ext.initiate_type, "user")
  assert.equal(body.ext.raw_query, "latest caller question")
  assert.deepEqual(body.ext.attachment, [])
  assert.equal(body.ext.skill_call_list, "")
  assert.equal(body.ext.connector_call_list, "")
  assert.equal(body.ext.tool_call_list, "")
  assert.equal(body.turn_id, NATIVE_SHAPE.turnId)
  assert.equal(body.ext.query_index, NATIVE_SHAPE.queryIndex)
  const serialized = JSON.stringify(body)
  assert.doesNotMatch(serialized, /official persona|CMS prompt|you are qwen|你是千问|工具提示词|system prompt injection/i)
}

test("OpenAI→Qianwen native 保留调用方 role/content，补齐原生字段与 ext", () => {
  const input = { model: "qwenapp/qwen4-max", messages: CALLER_MESSAGES, qwenapp: { route: "native", ch: "synthetic-ch" } }
  const body = buildChatBody(input, conversation(), "synthetic-req-id")
  assertNativeShape(body, input)
  assert.equal(body.model, "qwen4-max")
  assert.equal(body.stream, true)
  assert.equal(body.fr, "win")
  assert.equal(Object.hasOwn(body, "parent_req_id"), false)
  assert.equal(body.ch, undefined, "ch 属于查询参数，不应重复进入 native body")
})

test("Web body 同样不注入 persona/CMS/工具提示词，且保持独立字段形状", () => {
  const input = { model: "Qwen", messages: CALLER_MESSAGES }
  const body = buildChatBody(input, conversation(), "synthetic-req-id")
  assert.equal(body.req_id, "synthetic-req-id")
  assert.equal(body.parent_req_id, "0")
  assert.equal(body.scene_param, "first_turn")
  assert.equal(body.protocol_version, "v2")
  assert.equal(body.messages_merge, false)
  assert.deepEqual(body.messages.map((message) => message.role), input.messages.map((message) => message.role))
  assert.deepEqual(body.messages.map((message) => message.content), normalizeMessages(input).map((message) => message.content))
  for (const message of body.messages) {
    assert.equal(message.mime_type, "text/plain")
    assert.equal(message.status, "complete")
    assert.equal(message.meta_data.ori_query, message.content)
  }
  assert.equal(body.ext, undefined)
  assert.doesNotMatch(JSON.stringify(body), /official persona|CMS prompt|you are qwen|你是千问|工具提示词/i)
})

test("tools/functions/tool_choice/tool 结果均明确 400 unsupported_tools，不静默丢弃", () => {
  const base = { messages: [{ role: "user", content: "synthetic" }] }
  const unsupported = [
    { ...base, tools: [{ type: "function", function: { name: "synthetic" } }] },
    { ...base, functions: [{ name: "synthetic" }] },
    { ...base, tool_choice: "auto" },
    { messages: [{ role: "tool", content: "synthetic result", tool_call_id: "synthetic" }] },
    { messages: [{ role: "assistant", content: "", tool_calls: [{ id: "synthetic" }] }] },
    { messages: [{ role: "function", content: "synthetic result" }] },
  ]
  for (const input of unsupported) {
    assert.equal(hasUnsupportedTools(input), true)
    assert.throws(
      () => normalizeMessages(input),
      (error) => error.status === 400 && error.code === "unsupported_tools" && /不支持 tools/.test(error.message),
    )
  }
  assert.equal(hasUnsupportedTools({ ...base, tools: [], tool_choice: "none" }), false)
  assert.equal(normalizeMessages({ ...base, tools: [], tool_choice: "none" })[0].content, "synthetic")
})

test("非文本 content parts 明确 400，不静默丢弃图片或文件", () => {
  assert.throws(
    () => normalizeMessages({ messages: [{ role: "user", content: [{ type: "image_url", image_url: { url: "https://example.invalid/synthetic" } }] }] }),
    (error) => error.status === 400 && error.code === "invalid_request" && /不会被静默丢弃/.test(error.message),
  )
})

test("native 标准 tools/tool_choice/tool role 原样保留，Web 仍 400，且不注入工具提示词", () => {
  const input = {
    model: "qwen4-max",
    messages: [
      { role: "system", content: "caller system only" },
      { role: "user", content: "call the caller-declared echo tool" },
      {
        role: "assistant",
        content: null,
        tool_calls: [{
          id: "call_synthetic_previous",
          type: "function",
          function: { name: "echo_marker", arguments: '{"value":"synthetic previous"}' },
        }],
      },
      { role: "tool", tool_call_id: "call_synthetic_previous", content: "synthetic tool result" },
    ],
    tools: [{
      type: "function",
      function: {
        name: "echo_marker",
        description: "caller-declared synthetic echo",
        parameters: {
          type: "object",
          properties: { value: { type: "string" } },
          required: ["value"],
          additionalProperties: false,
        },
      },
    }],
    tool_choice: "auto",
    qwenapp: { route: "native" },
  }
  const before = structuredClone(input)
  const body = buildChatBody(input, conversation(), "synthetic-req-id")
  assert.deepEqual(input, before, "不得改写调用方 schema/messages")
  assert.deepEqual(body.tools, input.tools)
  assert.equal(body.tool_choice, "auto")
  assert.equal(body.messages.length, input.messages.length)
  assert.deepEqual(body.messages.map((message) => message.role), ["system", "user", "assistant", "tool"])
  assert.deepEqual(body.messages.filter((message) => message.role === "system").map((message) => message.content), ["caller system only"])
  assert.deepEqual(body.messages[2].tool_calls, input.messages[2].tool_calls)
  assert.equal(body.messages[3].tool_call_id, "call_synthetic_previous")
  assert.equal(body.messages[3].content, "synthetic tool result")
  assert.equal(body.turn_id, NATIVE_SHAPE.turnId)
  assert.equal(body.ext.query_index, NATIVE_SHAPE.queryIndex)
  assert.doesNotMatch(JSON.stringify(body), /official persona|CMS prompt|you are qwen|你是千问|工具提示词|system prompt injection/i)

  assert.throws(
    () => buildChatBody({ ...input, qwenapp: { route: "web" } }, conversation(), "synthetic-req-id"),
    (error) => error.status === 400 && error.code === "unsupported_tools",
  )
})
