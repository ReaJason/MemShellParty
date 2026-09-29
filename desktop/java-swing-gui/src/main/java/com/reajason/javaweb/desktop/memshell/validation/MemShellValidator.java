package com.reajason.javaweb.desktop.memshell.validation;

import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.memshell.ShellTool;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 表单校验，规则对齐 web 端 types/schema.ts。
 */
public class MemShellValidator {

    public static class Result {
        private final Map<String, String> fieldErrors = new LinkedHashMap<String, String>();

        public boolean isValid() {
            return fieldErrors.isEmpty();
        }

        public Map<String, String> getFieldErrors() {
            return fieldErrors;
        }

        public void add(String field, String message) {
            fieldErrors.put(field, message);
        }

        public String firstMessage() {
            for (String message : fieldErrors.values()) {
                return message;
            }
            return "";
        }
    }

    public Result validate(MemShellFormState s) {
        Result r = new Result();
        required(r, "server", s.getServer(), "请选择服务类型");
        required(r, "serverVersion", s.getServerVersion(), "请选择服务版本");
        required(r, "shellTool", s.getShellTool(), "请选择内存马工具");
        required(r, "shellType", s.getShellType(), "请选择内存马挂载类型");
        required(r, "packingMethod", s.getPackingMethod(), "请选择打包方式");

        if (needsUrlPattern(s.getShellType()) && isInvalidUrl(s.getUrlPattern())) {
            r.add("urlPattern", "请使用具体 URL 路径，不能为 / 或 /*");
        }
        if (ShellTool.Custom.equals(s.getShellTool()) && isBlank(s.getShellClassBase64())) {
            r.add("shellClassBase64", "自定义内存马 Class(Base64) 不能为空");
        }
        if ("TongWeb".equals(s.getServer()) && "Valve".equals(s.getShellType()) && "Unknown".equals(s.getServerVersion())) {
            r.add("serverVersion", "TongWeb Valve 模式需要指定服务版本");
        }
        if ("Jetty".equals(s.getServer())
                && ("Handler".equals(s.getShellType()) || "JakartaHandler".equals(s.getShellType()))
                && "Unknown".equals(s.getServerVersion())) {
            r.add("serverVersion", "Jetty Handler 模式需要指定服务版本");
        }
        return r;
    }

    /**
     * 对齐 web urlPatternIsNeeded：Servlet/ControllerHandler/HandlerMethod/HandlerFunction/WebSocket 需要具体路径（Agent 除外）。
     */
    public boolean needsUrlPattern(String shellType) {
        if (isBlank(shellType) || shellType.startsWith("Agent")) {
            return false;
        }
        return shellType.endsWith("Servlet")
                || shellType.endsWith("ControllerHandler")
                || "HandlerMethod".equals(shellType)
                || "HandlerFunction".equals(shellType)
                || shellType.endsWith("WebSocket");
    }

    /**
     * 对齐 web notNeedUrlPattern：这些挂载类型没有请求路径输入。
     */
    public boolean notNeedUrlPattern(String shellType) {
        if (isBlank(shellType)) {
            return true;
        }
        if (shellType.startsWith("Agent")) {
            return true;
        }
        if (shellType.endsWith("Listener") || shellType.endsWith("Valve")
                || shellType.endsWith("Interceptor") || shellType.endsWith("WebFilter")) {
            return true;
        }
        if (shellType.endsWith("Handler") && !shellType.contains("Controller")) {
            return true;
        }
        return "Customizer".equals(shellType) || "Upgrade".equals(shellType);
    }

    public boolean isInvalidUrl(String urlPattern) {
        return isBlank(urlPattern) || "/".equals(urlPattern) || "/*".equals(urlPattern) || !urlPattern.startsWith("/");
    }

    private void required(Result r, String field, String value, String message) {
        if (isBlank(value)) {
            r.add(field, message);
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }
}
