import { BASE, OFFICIAL_UA, PROVIDER, PROVIDER_NAME, SDK } from "./src/constants.mjs"
import { staticModels } from "./src/models.mjs"
import { createQwenRuntime } from "./src/runtime.mjs"
import { refreshAuth, successAuth } from "./src/cookie.mjs"
import { importWindowsCookies } from "./src/desktop-import.mjs"
import { sanitizeText } from "./src/errors.mjs"
import { ICON } from "./src/icon.mjs"
import { createSmsLoginMethod } from "./src/sms-login.mjs"

export async function QwenAppAuthPlugin() {
  const runtime = createQwenRuntime()
  const smsLogin = createSmsLoginMethod()
  return {
    config(cfg) {
      cfg.provider ??= {}
      cfg.provider[PROVIDER] ??= {
        name: PROVIDER_NAME,
        npm: SDK,
        api: BASE,
        models: staticModels(),
      }
    },

    auth: {
      provider: PROVIDER,
      icon: ICON,
      maxConcurrency: 4,
      methods: [
        smsLogin,
        {
          type: "api",
          label: "导入千问 Windows 客户端 Cookie",
          placeholder: "本机导入，无需联网",
          prompts: [{ type: "text", key: "note", message: "账号备注（可选）", placeholder: "例如：我的千问" }],
          async authorize(inputs) {
            try {
              return await importWindowsCookies({ note: inputs?.note, nativeDevice: inputs?.native_device })
            } catch (error) {
              return { type: "failed", error: sanitizeText(error?.message || error) }
            }
          },
        },
        {
          type: "api",
          label: "粘贴千问 Cookie",
          placeholder: "粘贴 Cookie（Web）或完整 JSON credential（原生）",
          prompts: [
            { type: "password", key: "cookie", message: "千问 Cookie 或完整 JSON credential", placeholder: '{"cookie":"tongyi_sso_ticket=...; ...","native":{...}}' },
            { type: "text", key: "note", message: "账号备注（可选）", placeholder: "例如：我的千问" },
          ],
          async authorize(inputs) {
            try { return successAuth(String(inputs?.cookie || ""), { note: inputs?.note }) } catch (error) {
              return { type: "failed", error: sanitizeText(error?.message || error) }
            }
          },
        },
      ],

      async refresh(auth) {
        if (!auth?.key) return undefined
        return refreshAuth(auth)
      },

      async loader(getAuth) {
        const auth = await getAuth()
        if (!auth?.key) return {}
        return {
          baseURL: BASE,
          apiKey: "",
          headers: { "user-agent": OFFICIAL_UA },
          fetch(input, init) {
            return runtime.forward(getAuth, input, init)
          },
        }
      },

      async usage(getAuth) {
        return runtime.usage(await getAuth())
      },

      async checkin() {
        return { outcome: "inactive", message: "千问没有已核实的每日签到活动" }
      },
    },

    provider: {
      id: PROVIDER,
      async models(_provider, { auth } = {}) {
        return runtime.models(auth)
      },
    },

    // 不把客户端身份、会话头或任何自定义头注入调用方请求。
    "chat.headers": async () => {},
  }
}

export const _internal = { PROVIDER, PROVIDER_NAME, BASE, staticModels }
