import type { GenerationRecord } from "@/types/history";
import type { TFunction } from "i18next";

import { useCallback, useEffect, useState } from "react";

/** 未使用记录的滚动过期时间：创建满 24h 后删除 */
export const HISTORY_TTL_MS = 24 * 60 * 60 * 1000;
/** 每种类型未使用记录的条数兜底上限（已使用记录不占限额） */
export const HISTORY_MAX_UNUSED_PER_KIND = 50;

const DB_NAME = "memshell-party";
const STORE_NAME = "generationHistory";
/** 「记录生成历史」开关，默认关闭（无痕生成），与语言选择一样走 localStorage */
const HISTORY_ENABLED_KEY = "memshell-party:history-enabled";

export function isHistoryEnabled(): boolean {
  try {
    return localStorage.getItem(HISTORY_ENABLED_KEY) === "true";
  } catch {
    return false;
  }
}

function persistHistoryEnabled(enabled: boolean) {
  try {
    localStorage.setItem(HISTORY_ENABLED_KEY, String(enabled));
  } catch {
    // localStorage 不可用时开关仅本次会话生效
  }
}

function isIndexedDbAvailable() {
  return typeof indexedDB !== "undefined";
}

/** crypto.randomUUID 需要安全上下文，http 部署时退化为时间戳+随机串 */
export function newRecordId() {
  return typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME, { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function requestToPromise<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function getAllRecords(): Promise<GenerationRecord[]> {
  const db = await openDb();
  try {
    return (await requestToPromise(
      db.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).getAll(),
    )) as GenerationRecord[];
  } finally {
    db.close();
  }
}

async function putRecord(record: GenerationRecord): Promise<void> {
  const db = await openDb();
  try {
    await requestToPromise(
      db.transaction(STORE_NAME, "readwrite").objectStore(STORE_NAME).put(record),
    );
  } finally {
    db.close();
  }
}

async function deleteRecords(ids: string[]): Promise<void> {
  if (ids.length === 0) return;
  const db = await openDb();
  try {
    const store = db.transaction(STORE_NAME, "readwrite").objectStore(STORE_NAME);
    await Promise.all(ids.map((id) => requestToPromise(store.delete(id))));
  } finally {
    db.close();
  }
}

/** 惰性清理：过期（未使用且满 24h）+ 未使用条数超限，返回要删除的 id */
function collectStaleIds(records: GenerationRecord[], kind: GenerationRecord["kind"]): string[] {
  const now = Date.now();
  const ofKind = records.filter((record) => record.kind === kind);
  const expired = ofKind.filter(
    (record) => !record.used && now - record.createdAt > HISTORY_TTL_MS,
  );
  const aliveUnused = ofKind
    .filter((record) => !record.used && now - record.createdAt <= HISTORY_TTL_MS)
    .sort((a, b) => b.createdAt - a.createdAt);
  const excess = aliveUnused.slice(HISTORY_MAX_UNUSED_PER_KIND);
  return [...expired, ...excess].map((record) => record.id);
}

/** 已使用置顶，其余按时间倒序 */
function sortRecords<T extends GenerationRecord>(records: T[]): T[] {
  return records.sort((a, b) => Number(b.used) - Number(a.used) || b.createdAt - a.createdAt);
}

export async function loadHistory(kind: GenerationRecord["kind"]): Promise<GenerationRecord[]> {
  if (!isIndexedDbAvailable()) return [];
  try {
    const all = await getAllRecords();
    const staleIds = collectStaleIds(all, kind);
    await deleteRecords(staleIds);
    return sortRecords(
      all.filter((record) => record.kind === kind && !staleIds.includes(record.id)),
    );
  } catch {
    return [];
  }
}

export async function addHistoryRecord(record: GenerationRecord): Promise<void> {
  if (!isIndexedDbAvailable()) return;
  try {
    await putRecord(record);
    await deleteRecords(collectStaleIds(await getAllRecords(), record.kind));
  } catch {
    // 存储不可用时静默降级，不影响生成本身
  }
}

export async function deleteHistoryRecord(id: string): Promise<void> {
  if (!isIndexedDbAvailable()) return;
  try {
    await deleteRecords([id]);
  } catch {
    // 同上
  }
}

export async function clearHistory(kind: GenerationRecord["kind"]): Promise<void> {
  if (!isIndexedDbAvailable()) return;
  try {
    const all = await getAllRecords();
    await deleteRecords(all.filter((record) => record.kind === kind).map((record) => record.id));
  } catch {
    // 同上
  }
}

/** 已删除/不存在的记录不重建，直接跳过 */
export async function setHistoryUsed(id: string, used: boolean): Promise<void> {
  if (!isIndexedDbAvailable()) return;
  try {
    const db = await openDb();
    try {
      const store = db.transaction(STORE_NAME, "readwrite").objectStore(STORE_NAME);
      const record = (await requestToPromise(store.get(id))) as GenerationRecord | undefined;
      if (record && record.used !== used) {
        await requestToPromise(store.put({ ...record, used }));
      }
    } finally {
      db.close();
    }
  } catch {
    // 同上
  }
}

export function formatRelativeTime(t: TFunction, createdAt: number): string {
  const minutes = Math.floor((Date.now() - createdAt) / 60_000);
  if (minutes < 1) return t("common:history.time.justNow");
  if (minutes < 60) return t("common:history.time.minutesAgo", { count: minutes });
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return t("common:history.time.hoursAgo", { count: hours });
  return t("common:history.time.daysAgo", { count: Math.floor(hours / 24) });
}

export function useGenerationHistory<T extends GenerationRecord>(kind: T["kind"]) {
  const [records, setRecords] = useState<T[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [enabled, setEnabledState] = useState(isHistoryEnabled);

  const setEnabled = useCallback((next: boolean) => {
    persistHistoryEnabled(next);
    setEnabledState(next);
  }, []);

  const refresh = useCallback(async () => {
    setRecords((await loadHistory(kind)) as T[]);
    setLoaded(true);
  }, [kind]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const add = useCallback(
    async (record: T) => {
      // 无痕生成：开关关闭时不落库
      if (!isHistoryEnabled()) return;
      await addHistoryRecord(record);
      await refresh();
    },
    [refresh],
  );

  const remove = useCallback(
    async (id: string) => {
      await deleteHistoryRecord(id);
      await refresh();
    },
    [refresh],
  );

  const clearAll = useCallback(async () => {
    await clearHistory(kind);
    await refresh();
  }, [kind, refresh]);

  const setUsed = useCallback(
    async (id: string, used: boolean) => {
      const existing = records.find((record) => record.id === id);
      if (!existing || existing.used === used) return;
      await setHistoryUsed(id, used);
      await refresh();
    },
    [records, refresh],
  );

  return { records, loaded, enabled, setEnabled, add, remove, clearAll, setUsed };
}
