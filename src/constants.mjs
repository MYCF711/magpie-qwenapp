export const PROVIDER = "qwenapp"
export const PROVIDER_NAME = "千问 QwenApp"
export const SDK = "@ai-sdk/openai-compatible"
export const BASE = "https://chat2.qianwen.com/v1"
export const CHAT_URL = "https://chat2.qianwen.com/api/v2/chat"
export const NATIVE_CHAT_URL = "https://chat2.qianwen.com/v1/chat/completions"
export const REGISTER_URL = "https://sec.qianwen.com/security/external/access/register"
export const MODEL_PANEL_URL = "https://qwen-agent-api.qianwen.com/api/v1/agent/model/panel"
export const MODEL_LIST_URL = "https://chat2-api.qianwen.com/api/v1/model/list"
export const SIGN_VERSION = "2.9.3"
export const QUERY_PARAM_KEYS = "biz_id,chat_client,device,fe_version,fr,la,nonce,pr,timestamp,tz,ut,ve,wv"
export const OFFICIAL_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 TONGYI_DESKTOP/5.2.7.307"
export const ORIGIN = "https://www.qianwen.com"
export const STATIC_MODEL_ROWS = Object.freeze([
  { id: "Qwen", name: "Qwen" },
  { id: "qwen4-max", name: "Qwen4-Max" },
  { id: "qwen3.8-flash", name: "Qwen3.8-Flash" },
  { id: "qwen3.8-max", name: "Qwen3.8-Max" },
  { id: "qwen3.7-max", name: "Qwen3.7-Max" },
])

export const LIMITS = Object.freeze({
  connectMs: 30_000,
  jsonMs: 15_000,
  streamIdleMs: 60_000,
  jsonBytes: 8 * 1024 * 1024,
  errorBytes: 1024 * 1024,
  sseBytes: 32 * 1024 * 1024,
  conversations: 256,
  retries: 1,
  tokenLowWater: 2,
})
