import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs"
import { dirname, join, resolve } from "node:path"
import { homedir } from "node:os"
import { randomUUID } from "node:crypto"

// 所有 runtime/HMR 实例共享同一进程内队列；文件锁再协调其它宿主进程。
const processCacheLocks = new Map()
const pause = (ms) => new Promise((resolvePause) => setTimeout(resolvePause, ms))

export function securityCacheFile(identity, root) {
  const directory = root || join(homedir(), ".cache", "magpie")
  return join(directory, `qwenapp-security__${String(identity).replace(/[^a-zA-Z0-9_-]/g, "")}.json`)
}

export function readCache(file) {
  try {
    const value = JSON.parse(readFileSync(file, "utf8"))
    return value && typeof value === "object" ? value : null
  } catch { return null }
}

/** 安全缓存包含上游短期 token，仅写 0600 原子文件；日志永远不序列化该对象。 */
export function writeCache(file, value) {
  let temp = ""
  try {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
    temp = `${file}.${process.pid}.${randomUUID()}.tmp`
    writeFileSync(temp, JSON.stringify(value), { mode: 0o600, flag: "wx" })
    renameSync(temp, file)
    return true
  } catch {
    if (temp) { try { rmSync(temp, { force: true }) } catch {} }
    return false
  }
}

function abortIfNeeded(signal) {
  if (signal?.aborted) throw signal.reason || new DOMException("The operation was aborted.", "AbortError")
}

async function withFileLock(file, fn, { staleMs, waitMs, signal }) {
  const lockFile = `${file}.lock`
  const owner = `${process.pid}:${randomUUID()}`
  const started = Date.now()
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
  for (;;) {
    abortIfNeeded(signal)
    let fd
    try {
      fd = openSync(lockFile, "wx", 0o600)
      writeFileSync(fd, JSON.stringify({ owner, pid: process.pid, createdAt: new Date().toISOString() }), "utf8")
      closeSync(fd)
      fd = undefined
      break
    } catch (error) {
      if (fd !== undefined) { try { closeSync(fd) } catch {} }
      if (error?.code !== "EEXIST") throw error
      try {
        const stat = statSync(lockFile)
        if (Date.now() - stat.mtimeMs > staleMs) {
          rmSync(lockFile, { force: true })
          continue
        }
      } catch (statError) {
        if (statError?.code === "ENOENT") continue
      }
      if (Date.now() - started >= waitMs) {
        const timeout = new Error("等待千问安全缓存跨进程锁超时")
        timeout.code = "CACHE_LOCK_TIMEOUT"
        throw timeout
      }
      await pause(20)
    }
  }

  // register 可能耗时较长，心跳防止活跃锁被其它进程误判为 stale。
  const heartbeat = setInterval(() => {
    try {
      const now = new Date()
      utimesSync(lockFile, now, now)
    } catch {}
  }, Math.max(5, Math.min(5_000, Math.floor(staleMs / 3))))
  heartbeat.unref?.()
  try {
    abortIfNeeded(signal)
    return await fn()
  } finally {
    clearInterval(heartbeat)
    try {
      const current = JSON.parse(readFileSync(lockFile, "utf8"))
      if (current?.owner === owner) rmSync(lockFile, { force: true })
    } catch {}
  }
}

/** 进程内队列 + wx 文件锁；stale 锁按 mtime 回收，持锁期间以心跳续约。 */
export function withCacheLock(file, fn, { staleMs = 30_000, waitMs = 90_000, signal } = {}) {
  if (typeof fn !== "function") throw new TypeError("withCacheLock 需要回调")
  const key = resolve(file)
  const previous = processCacheLocks.get(key) || Promise.resolve()
  const task = previous.catch(() => {}).then(() => withFileLock(key, fn, { staleMs, waitMs, signal }))
  let tracked
  tracked = task.finally(() => {
    if (processCacheLocks.get(key) === tracked) processCacheLocks.delete(key)
  })
  processCacheLocks.set(key, tracked)
  return tracked
}
