import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { parseSse, readSseEvents, openAIEvents, foldOpenAI } from "../src/openai-sse.mjs"
import { translateQwenEvents } from "../src/protocol.mjs"
import { deferred } from "./helpers.mjs"

function byteStream(chunks) {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk)
      controller.close()
    },
  })
}

async function eventsFor(chunks, options) {
  const out = []
  for await (const event of readSseEvents(byteStream(chunks), options)) out.push(event)
  return out
}

function nativeFrame(messages, { event = "", extra = {} } = {}) {
  return {
    event,
    data: JSON.stringify({ error_code: 0, error_msg: "", data: { extra_info: extra, messages } }),
  }
}

function assistant(content, extra = {}) {
  return { id: "synthetic-message", role: "assistant", mime_type: "multi_load/iframe", content, status: "processing", ...extra }
}

async function translated(frames) {
  const chunks = []
  for await (const chunk of translateQwenEvents(frames, { model: "Qwen", id: "synthetic-completion", created: 1700000000 })) chunks.push(chunk)
  return chunks
}

function contentOf(chunks, key = "content") {
  return chunks.map((chunk) => chunk.choices[0]?.delta?.[key] || "").join("")
}

test("SSE 任意二切分、逐字节、UTF-8 半字符与 CRLF 跨块均不丢字符", async () => {
  const bytes = new TextEncoder().encode("data: {\"content\":\"你好🌐\"}\r\n\r\n")
  for (let at = 0; at <= bytes.length; at += 1) {
    const events = await eventsFor([bytes.subarray(0, at), bytes.subarray(at)])
    assert.equal(events.length, 1, `split ${at}`)
    assert.deepEqual(JSON.parse(events[0].data), { content: "你好🌐" })
  }
  const bytewise = await eventsFor([...bytes].map((value) => Uint8Array.of(value)))
  assert.deepEqual(JSON.parse(bytewise[0].data), { content: "你好🌐" })
})

test("SSE 多行 data、注释、BOM、裸 CR 与末尾无空行", async () => {
  const events = await eventsFor([
    new TextEncoder().encode("\uFEFF: keepalive\rdata: {\"a\":\rdata: 1}\r\r"),
    new TextEncoder().encode("data: [DONE]"),
  ])
  assert.equal(events.length, 2)
  assert.equal(events[0].data, '{"a":\n1}')
  assert.deepEqual(JSON.parse(events[0].data), { a: 1 })
  assert.equal(events[1].data, "[DONE]")
  assert.deepEqual(parseSse("data: one\ndata: two\n\n")[0].data, "one\ntwo")
})

test("脱敏原生夹具：multi_load 全量快照去重、event:complete 与真实 total_usage", async () => {
  const text = readFileSync(new URL("../reference/fixtures/native-qwen-minimal.sse", import.meta.url), "utf8")
  assert.doesNotMatch(text, /sessionid|trace_id|account|79611bb3|fc4b83d7/i)
  const bytes = new TextEncoder().encode(text)
  const frames = readSseEvents(byteStream([...bytes].map((value) => Uint8Array.of(value))))
  const chunks = await translated(frames)
  assert.equal(contentOf(chunks), "你好")
  assert.equal(chunks.filter((chunk) => chunk.choices[0].finish_reason === "stop").length, 1)
  const finish = chunks.at(-1)
  assert.deepEqual(finish.usage, { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 })
  assert.equal(finish.model, "Qwen")
})

test("multi_load/iframe 增量序列与重复增量去重", async () => {
  const chunks = await translated([
    nativeFrame([assistant("A")]),
    nativeFrame([assistant("B")]),
    nativeFrame([assistant("B")]),
    nativeFrame([assistant("C", { status: "complete" })]),
  ])
  assert.equal(contentOf(chunks), "ABC")
})

test("reasoning 与正文通道分离，裸 true 与 [DONE] 正确终结", async () => {
  const chunks = await translated([
    { data: "true" },
    nativeFrame([{ id: "synthetic-reasoning", role: "assistant", reasoning_content: "先想", status: "processing" }]),
    nativeFrame([{ id: "synthetic-reasoning", role: "assistant", reasoning_content: "先想一步", status: "complete" }]),
    nativeFrame([assistant("答案")]),
    { data: "[DONE]" },
  ])
  assert.equal(contentOf(chunks, "reasoning_content"), "先想一步")
  assert.equal(contentOf(chunks), "答案")
  assert.equal(chunks.at(-1).choices[0].finish_reason, "stop")
})

test("非流折叠复用同一状态机并保留 usage，不估算 token", async () => {
  const text = readFileSync(new URL("../reference/fixtures/native-qwen-minimal.sse", import.meta.url), "utf8")
  const frames = readSseEvents(byteStream([new TextEncoder().encode(text)]))
  const completion = await foldOpenAI(translateQwenEvents(frames, { model: "qwen4-max", id: "synthetic-fold" }), { model: "qwen4-max" })
  assert.equal(completion.object, "chat.completion")
  assert.equal(completion.choices[0].message.content, "你好")
  assert.equal(completion.choices[0].finish_reason, "stop")
  assert.deepEqual(completion.usage, { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 })
})

test("complete/[DONE] 前 EOF 是 504 截断，非法 JSON 是 502", async () => {
  await assert.rejects(
    () => translated([nativeFrame([assistant("partial")])]),
    (error) => error.status === 504 && error.code === "upstream_timeout",
  )
  await assert.rejects(
    () => translated([{ data: "not-json" }]),
    (error) => error.status === 502 && error.code === "upstream_error",
  )
})

test("SSE abort 取消底层 reader，提前 break 也取消", async () => {
  const controller = new AbortController()
  const pending = deferred()
  let cancels = 0
  const body = {
    getReader() {
      return {
        read: () => pending.promise,
        cancel: async () => { cancels += 1; pending.resolve({ done: true }) },
        releaseLock() {},
      }
    },
  }
  const iteration = (async () => {
    for await (const _ of readSseEvents(body, { signal: controller.signal })) void _
  })()
  await new Promise((resolve) => setImmediate(resolve))
  controller.abort(new DOMException("synthetic cancel", "AbortError"))
  await assert.rejects(iteration, (error) => error.name === "AbortError")
  assert.equal(cancels, 1)

  let earlyCancel = 0
  const earlyBody = new ReadableStream({
    start(stream) { stream.enqueue(new TextEncoder().encode("data: true\n\n")) },
    cancel() { earlyCancel += 1 },
  })
  for await (const _ of readSseEvents(earlyBody)) { void _; break }
  assert.equal(earlyCancel, 1)
})

test("SSE 与错误响应都有字节上限", async () => {
  await assert.rejects(
    () => eventsFor([new TextEncoder().encode("data: 1234567890\n\n")], { maxBytes: 8 }),
    (error) => error.code === "SSE_TOO_LARGE",
  )
})

async function nativeToolEvents() {
  const events = []
  for await (const event of openAIEvents(byteStream([new TextEncoder().encode(readFileSync(new URL("../reference/fixtures/native-openai-tool-call.sse", import.meta.url), "utf8"))]))) events.push(event)
  return events
}

test("native OpenAI delta.tool_calls 分片解析不改写，synthetic call id 完整", async () => {
  const events = await nativeToolEvents()
  const expected = events.flatMap((payload) => (payload.choices || []).flatMap((choice) => choice.delta?.tool_calls || []))
  const chunks = events
  const actual = chunks.flatMap((chunk) => chunk.choices[0]?.delta?.tool_calls || [])
  assert.equal(expected.length, 5)
  assert.deepEqual(actual, expected)
  assert.equal(actual[0].id, "call_synthetic_echo_1")
  assert.equal(actual[0].function.name, "echo_marker")
  assert.equal(contentOf(chunks, "reasoning_content"), "synthetic reasoning")
  assert.equal(chunks.at(-1).choices[0].finish_reason, "tool_calls")
})

test("native tool_calls 非流 fold 保留 id/name/arguments/finish_reason/usage", async () => {
  const completion = await foldOpenAI(await nativeToolEvents(), { model: "qwen4-max", id: "synthetic-tool-fold" })
  assert.equal(completion.choices[0].finish_reason, "tool_calls")
  assert.equal(completion.choices[0].message.content, null)
  assert.deepEqual(completion.choices[0].message.tool_calls, [{
    id: "call_synthetic_echo_1",
    type: "function",
    function: { name: "echo_marker", arguments: '{"value": "SYNTHETIC_TOOL_OK"}' },
  }])
  assert.deepEqual(completion.usage, { prompt_tokens: 20, completion_tokens: 10, total_tokens: 30 })
})
