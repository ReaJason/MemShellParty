import type { DecompiledClass, DecompileRequest, DecompileResponse } from "./decompile.worker";

import { useEffect, useState } from "react";

/** Structural subset shared by MemShellResult and ProbeShellResult */
export interface DecompileInput {
  shellClassName?: string;
  shellBytesBase64Str?: string;
  helperClassName?: string;
  helperBytesBase64Str?: string;
  injectorClassName?: string;
  injectorBytesBase64Str?: string;
}

export interface DecompiledSources {
  shell: DecompiledClass | null;
  helper: DecompiledClass | null;
  injector: DecompiledClass | null;
}

interface DecompileState {
  sources: DecompiledSources;
  isDecompiling: boolean;
  error: string | null;
}

const IDLE: DecompileState = {
  sources: { shell: null, helper: null, injector: null },
  isDecompiling: false,
  error: null,
};

const CACHE_LIMIT = 8;
const cache = new Map<string, DecompiledSources>();

function cacheGet(key: string) {
  const value = cache.get(key);
  if (value) {
    cache.delete(key);
    cache.set(key, value);
  }
  return value;
}

function cacheSet(key: string, value: DecompiledSources) {
  cache.set(key, value);
  if (cache.size > CACHE_LIMIT) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
}

/** FNV-1a over the base64 payloads; cheap identity for one generation. */
function cacheKey(shellBytes: string, helperBytes: string, injectorBytes: string) {
  let hash = 0x811c9dc5;
  for (const str of [shellBytes, helperBytes, injectorBytes]) {
    for (let i = 0; i < str.length; i++) {
      hash ^= str.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193);
    }
  }
  return `${(hash >>> 0).toString(36)}:${shellBytes.length}:${helperBytes.length}:${injectorBytes.length}`;
}

let worker: Worker | null = null;
let nextId = 0;
const pending = new Map<
  number,
  { resolve: (value: DecompiledSources) => void; reject: (reason: Error) => void }
>();

function getWorker() {
  if (!worker) {
    worker = new Worker(new URL("./decompile.worker.ts", import.meta.url), { type: "module" });
    worker.onmessage = (event: MessageEvent<DecompileResponse>) => {
      const { id, shell, helper, injector, error } = event.data;
      const entry = pending.get(id);
      if (!entry) return;
      pending.delete(id);
      if (error || !shell) {
        entry.reject(new Error(error ?? "decompile failed"));
      } else {
        entry.resolve({ shell, helper: helper ?? null, injector: injector ?? null });
      }
    };
    worker.onerror = (event) => {
      const reason = new Error(event.message || "decompile worker failed");
      for (const entry of pending.values()) entry.reject(reason);
      pending.clear();
    };
  }
  return worker;
}

function decompileInWorker(request: Omit<DecompileRequest, "id">) {
  return new Promise<DecompiledSources>((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    getWorker().postMessage({ ...request, id } satisfies DecompileRequest);
  });
}

export function useDecompiledSources(generateResult: DecompileInput | undefined) {
  const shellClassName = generateResult?.shellClassName;
  const shellBytesBase64 = generateResult?.shellBytesBase64Str;
  const helperClassName = generateResult?.helperClassName;
  const helperBytesBase64 = generateResult?.helperBytesBase64Str;
  const injectorClassName = generateResult?.injectorClassName;
  const injectorBytesBase64 = generateResult?.injectorBytesBase64Str;

  const [state, setState] = useState<DecompileState>(IDLE);

  useEffect(() => {
    if (!shellClassName || !shellBytesBase64) {
      setState(IDLE);
      return;
    }

    const key = cacheKey(shellBytesBase64, helperBytesBase64 ?? "", injectorBytesBase64 ?? "");
    const cached = cacheGet(key);
    if (cached) {
      setState({ sources: cached, isDecompiling: false, error: null });
      return;
    }

    let cancelled = false;
    setState({
      sources: { shell: null, helper: null, injector: null },
      isDecompiling: true,
      error: null,
    });

    decompileInWorker({
      shellClassName,
      shellBytesBase64,
      helperClassName,
      helperBytesBase64,
      injectorClassName,
      injectorBytesBase64,
    })
      .then((sources) => {
        cacheSet(key, sources);
        if (!cancelled) setState({ sources, isDecompiling: false, error: null });
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setState({
            sources: { shell: null, helper: null, injector: null },
            isDecompiling: false,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [
    helperBytesBase64,
    helperClassName,
    injectorBytesBase64,
    injectorClassName,
    shellBytesBase64,
    shellClassName,
  ]);

  return state;
}
