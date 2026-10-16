package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;

/**
 * 工具参数的适用性判断：某个工具参数在当前服务端 / 挂载类型下是否有意义。
 * <p>
 * 「无意义」的参数不应在表单里出现（web 端保留挂载、桌面端隐藏），否则用户填了也不会生效：
 * <ul>
 *   <li>{@code Command.paramName} —— WebSocket 走请求头传参、Dubbo 没有 HTTP 请求，两者都用不上；</li>
 *   <li>{@code Command/Proxy.headerName/headerValue} —— 只在 BypassNginx 的 WebSocket 回落里当"暗号"，其余挂载类型不读。</li>
 * </ul>
 * 规则与工具 config 类上的注释同源，插件工具没有声明即视为所有参数都适用。
 *
 * @author ReaJason
 * @since 3.0.0
 */
public final class ToolParamVisibility {

    private ToolParamVisibility() {
    }

    /**
     * @param tool      当前 shellTool 名（如 {@code Command} / {@code Proxy}）
     * @param param     config 字段名（如 {@code paramName} / {@code headerName}）
     * @param server    当前服务端（如 {@code Dubbo}），可为 null
     * @param shellType 当前挂载类型（如 {@code BypassNginxWebSocket}），可为 null
     */
    public static boolean isVisible(String tool, String param, String server, String shellType) {
        if (isHeaderParam(param) && (ShellTool.Command.equals(tool) || ShellTool.Proxy.equals(tool))) {
            return isBypassNginxWebSocket(shellType);
        }
        if (ShellTool.Command.equals(tool) && "paramName".equals(param)) {
            return !isWebSocket(shellType) && !Server.Dubbo.equals(server);
        }
        return true;
    }

    private static boolean isHeaderParam(String param) {
        return "headerName".equals(param) || "headerValue".equals(param);
    }

    private static boolean isWebSocket(String shellType) {
        return shellType != null && shellType.contains(ShellType.WEBSOCKET);
    }

    private static boolean isBypassNginxWebSocket(String shellType) {
        // 常量而非字面量：Jakarta 版是 JakartaWebBypassNginxWebSocket，手写极易拼成 BypassNginxJakartaWebSocket
        return ShellType.BYPASS_NGINX_WEBSOCKET.equals(shellType)
                || ShellType.JAKARTA_BYPASS_NGINX_WEBSOCKET.equals(shellType);
    }
}
