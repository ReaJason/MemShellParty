/**
 * 配置类接口的统一请求封装：非 2xx 直接抛错，并给单次请求加超时。
 *
 * <p>没有超时的 fetch 在网关挂起时会一直 pending，React Query 的重试永远触发不了，
 * 界面就会停在「加载中」。超时后按普通错误走重试/错误态。
 */
const DEFAULT_TIMEOUT_MS = 20_000;

export async function fetchJson<T>(
  url: string,
  init: RequestInit = {},
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(new DOMException("Request timed out", "TimeoutError")),
    timeoutMs,
  );

  const external = init.signal;
  const onAbort = () => controller.abort(external?.reason);
  if (external) {
    if (external.aborted) {
      controller.abort(external.reason);
    } else {
      external.addEventListener("abort", onAbort, { once: true });
    }
  }

  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`.trim());
    }
    return (await response.json()) as T;
  } finally {
    clearTimeout(timer);
    external?.removeEventListener("abort", onAbort);
  }
}
