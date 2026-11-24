import test from "node:test"
import assert from "node:assert/strict"


test("上游 reasoningEffortList 对象数组取 value 作档位，绝不产出 [object Object]", async () => {
  const { modelEntry } = await import("../src/models.mjs")
  const row = {
    model: "qwen4-max",
    name: "Qwen4-Max",
    deepThinking: true,
    contextWindow: 1000000,
    reasoningEffortList: [
      { label: "低", value: "low", isDefault: false },
      { label: "高", value: "high", isDefault: true },
      { label: "极高", value: "xhigh", isDefault: false },
    ],
  }
  const entry = modelEntry(row, { live: true })
  assert.deepEqual(Object.keys(entry.variants), ["low", "high", "xhigh"])
  assert.equal(entry.capabilities.reasoning, true)
  assert.equal(entry.limit.context, 1000000)
  assert.ok(!JSON.stringify(entry).includes("[object Object]"), JSON.stringify(entry))
})

test("reasoningEffortList 兼容纯字符串、去空去重、剔除畸形项", async () => {
  const { modelEntry } = await import("../src/models.mjs")
  assert.deepEqual(Object.keys(modelEntry({ model: "a", reasoningEffortList: ["low", "high"] }, { live: true }).variants), ["low", "high"])
  assert.deepEqual(Object.keys(modelEntry({ model: "b", reasoningEffortList: ["high", "high", " low "] }, { live: true }).variants), ["high", "low"])
  // 空对象 / null / 非字符串非对象 都不能变成档位名
  const malformed = modelEntry({ model: "c", reasoningEffortList: [{}, null, " high ", 42] }, { live: true })
  assert.deepEqual(Object.keys(malformed.variants), ["high"])
  assert.ok(!JSON.stringify(malformed).includes("[object Object]"))
})

test("没有 reasoningEffortList 时不产生 variants", async () => {
  const { modelEntry } = await import("../src/models.mjs")
  const entry = modelEntry({ model: "plain" }, { live: true })
  assert.equal(entry.variants, undefined)
  assert.equal(entry.capabilities.reasoning, false)
})
