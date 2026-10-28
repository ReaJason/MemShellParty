/**
 * 工具参数的适用性判断，与 core 的 `com.reajason.javaweb.memshell.ToolParamVisibility` 同源
 * （桌面端直接调那份 Java 实现；web 端过不了语言边界，只能照抄，改规则时两边一起改）：
 *
 * - `Command.paramName`：WebSocket 走请求头传参、Dubbo 没有 HTTP 请求，两者都用不上。
 * - `Proxy.headerName/headerValue`：仅 HTTP/PHT 用于隔离流量。
 *
 * 没声明的工具（含 SPI 插件工具）一律可见 —— 兜底方向必须偏"显示"，否则参数会凭空消失。
 */
export function isToolParamVisible(
  tool: string,
  param: string,
  server: string | undefined,
  shellType: string | undefined,
): boolean {
  if (tool === "Command" && param === "paramName") {
    return !shellType?.includes("WebSocket") && server !== "Dubbo";
  }
  if (tool === "Proxy" && (param === "headerName" || param === "headerValue")) {
    return !shellType?.includes("WebSocket") && server !== "Dubbo";
  }
  return true;
}
