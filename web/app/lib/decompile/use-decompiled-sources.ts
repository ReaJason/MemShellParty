import type { DecompiledClass, DecompileRequest, DecompileResponse } from "./decompile.worker";

import { useEffect, useState } from "react";

/** Structural subset shared by MemShellResult and ProbeShellResult */
export interface DecompileInput {
  shellClassName?: string;
  shellBytesBase64Str?: string;
  injectorClassName?: string;
  injectorBytesBase64Str?: string;
}

export interface DecompiledSources {
  shell: DecompiledClass | null;
  injector: DecompiledClass | null;
}

interface DecompileState {
  sources: DecompiledSources;
  isDecompiling: boolean;
  error: string | null;
}

const IDLE: DecompileState = {
  sources: { shell: null, injector: null },
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

/** FNV-1a over both base64 payloads; cheap identity for one generation. */
function cacheKey(shellBytes: string, injectorBytes: string) {
  let hash = 0x811c9dc5;
  for (const str of [shellBytes, injectorBytes]) {
    for (let i = 0; i < str.length; i++) {
      hash ^= str.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193);
    }
  }
  return `${(hash >>> 0).toString(36)}:${shellBytes.length}:${injectorBytes.length}`;
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
      const { id, shell, injector, error } = event.data;
      const entry = pending.get(id);
      if (!entry) return;
      pending.delete(id);
      if (error || !shell) {
        entry.reject(new Error(error ?? "decompile failed"));
      } else {
        entry.resolve({ shell, injector: injector ?? null });
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
  const injectorClassName = generateResult?.injectorClassName;
  const injectorBytesBase64 = generateResult?.injectorBytesBase64Str;

  const [state, setState] = useState<DecompileState>(IDLE);

  useEffect(() => {
    if (!shellClassName || !shellBytesBase64) {
      setState(IDLE);
      return;
    }

    const key = cacheKey(shellBytesBase64, injectorBytesBase64 ?? "");
    const cached = cacheGet(key);
    if (cached) {
      setState({ sources: cached, isDecompiling: false, error: null });
      return;
    }

    let cancelled = false;
    setState({ sources: { shell: null, injector: null }, isDecompiling: true, error: null });

    decompileInWorker({
      shellClassName,
      shellBytesBase64,
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
            sources: { shell: null, injector: null },
            isDecompiling: false,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [injectorBytesBase64, injectorClassName, shellBytesBase64, shellClassName]);

  return state;
}
