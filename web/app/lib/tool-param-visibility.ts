/**
 * 工具参数的适用性判断，与 core 的 `com.reajason.javaweb.memshell.ToolParamVisibility` 同源
 * （桌面端直接调那份 Java 实现；web 端过不了语言边界，只能照抄，改规则时两边一起改）：
 *
 * - `Command.paramName`：WebSocket 走请求头传参、Dubbo 没有 HTTP 请求，两者都用不上；
 * - `Command` / `Proxy` 的 `headerName` / `headerValue`：只在 BypassNginx 的 WebSocket 回落里当"暗号"。
 *
 * 没声明的工具（含 SPI 插件工具）一律可见 —— 兜底方向必须偏"显示"，否则参数会凭空消失。
 */
export function isToolParamVisible(
  tool: string,
  param: string,
  server: string | undefined,
  shellType: string | undefined,
): boolean {
  const isHeaderParam = param === "headerName" || param === "headerValue";
  if (isHeaderParam && (tool === "Command" || tool === "Proxy")) {
    return isBypassNginxWebSocket(shellType);
  }
  if (tool === "Command" && param === "paramName") {
    return !shellType?.includes("WebSocket") && server !== "Dubbo";
  }
  return true;
}

function isBypassNginxWebSocket(shellType: string | undefined): boolean {
  // 与 core 的 ShellType 常量对齐：Jakarta 版是 JakartaWebBypassNginxWebSocket，
  // 别照字面顺序写成 BypassNginxJakartaWebSocket（写错了这一支永远不会成立）
  return shellType === "BypassNginxWebSocket" || shellType === "JakartaWebBypassNginxWebSocket";
}
