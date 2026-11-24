import { BASE, PROVIDER, SDK, STATIC_MODEL_ROWS } from "./constants.mjs"

function finitePositive(value) {
  const number = Number(value)
  return Number.isFinite(number) && number > 0 ? number : undefined
}

export function modelEntry(row, { live = false } = {}) {
  const id = String(row?.id || row?.model || row?.modelCode || row?.legacyModelCode || "").trim()
  if (!id) return null
  const name = String(row?.name || row?.displayModelName || id).trim() || id
  const image = false
  // 上游 reasoningEffortList 是对象数组 [{value,label,isDefault}]，直接 String() 会得到
  // "[object Object]" 并被宿主当成档位名显示。这里取 value（真正发给上游的档位值），
  // 兼容纯字符串数组，并去掉空值与重复项。
  const efforts = Array.isArray(row?.reasoningEffortList)
    ? [...new Set(row.reasoningEffortList
      .map((item) => (typeof item === "string" ? item : String(item?.value ?? item?.id ?? "")))
      .map((value) => value.trim())
      .filter(Boolean))]
    : []
  const context = finitePositive(row?.context_window ?? row?.contextWindow)
  const output = finitePositive(row?.max_tokens ?? row?.maxTokens)
  const entry = {
    id,
    name,
    api: { id, url: BASE, npm: SDK },
    status: "active",
    modalities: { input: image ? ["text", "image"] : ["text"], output: ["text"] },
    capabilities: {
      reasoning: row?.deepThinking === true || efforts.length > 0,
      toolcall: false,
      attachment: false,
      input: { text: true, image, audio: false, video: false, pdf: false },
      output: { text: true },
    },
    ...(efforts.length ? { variants: Object.fromEntries(efforts.map((effort) => [effort, {}])) } : {}),
    ...((context || output) ? { limit: { ...(context ? { context } : {}), ...(output ? { output } : {}) } } : {}),
  }
  return entry
}

export function staticModels() {
  return Object.fromEntries(STATIC_MODEL_ROWS.map((row) => {
    const model = modelEntry(row)
    return [model.id, model]
  }))
}

export function panelRows(payload) {
  const rows = payload?.data?.models
  if (!Array.isArray(rows)) throw new TypeError("模型面板响应缺少 data.models 数组")
  return rows
    .filter((row) => row && row.show !== false)
    .map((row) => ({ ...row, id: row.model || row.id, name: row.name || row.model || row.id }))
}

export function fallbackRows(payload) {
  const rows = Array.isArray(payload?.data) ? payload.data : payload?.data?.models
  if (!Array.isArray(rows)) throw new TypeError("模型列表响应缺少 data 数组")
  return rows.map((row) => ({
    ...row,
    id: row?.modelCode || row?.legacyModelCode,
    name: row?.displayModelName || row?.modelCode || row?.legacyModelCode,
  }))
}

export function buildModels(rows) {
  const valid = [...rows]
    .sort((a, b) => Number(Boolean(b?.defaultModel ?? b?._default ?? b?.default)) - Number(Boolean(a?.defaultModel ?? a?._default ?? a?.default)))
    .map((row) => modelEntry(row, { live: true })).filter(Boolean)
  const out = {}
  for (const entry of valid) out[entry.id] = entry
  if (!Object.keys(out).length) throw new TypeError("模型目录没有可展示的有效模型")
  return out
}

export function normalizePanelOrder(rows) {
  return [...rows].sort((a, b) => Number(Boolean(b?.defaultModel)) - Number(Boolean(a?.defaultModel)))
}

export const MODEL_PROVIDER = PROVIDER
