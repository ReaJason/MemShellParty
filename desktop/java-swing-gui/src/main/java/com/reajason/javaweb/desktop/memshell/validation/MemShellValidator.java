package com.reajason.javaweb.desktop.memshell.validation;

import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;

import java.util.LinkedHashMap;
import java.util.Map;

public class MemShellValidator {
    public static class Result {
        private final Map<String, String> fieldErrors = new LinkedHashMap<>();

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
            return fieldErrors.values().stream().findFirst().orElse("");
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
        if ("Custom".equals(s.getShellTool()) && (s.getShellClassBase64() == null || s.getShellClassBase64().trim().isEmpty())) {
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

    public boolean needsUrlPattern(String shellType) {
        if (shellType == null || shellType.trim().isEmpty()) return false;
        if (shellType.startsWith("Agent")) return false;
        return shellType.endsWith("Servlet") ||
                shellType.endsWith("ControllerHandler") ||
                shellType.equals("HandlerMethod") ||
                shellType.equals("HandlerFunction") ||
                shellType.endsWith("WebSocket");
    }

    public boolean isInvalidUrl(String urlPattern) {
        return urlPattern == null || urlPattern.trim().isEmpty() || "/".equals(urlPattern) || "/*".equals(urlPattern) || !urlPattern.startsWith("/");
    }

    private void required(Result r, String field, String value, String message) {
        if (value == null || value.trim().isEmpty()) {
            r.add(field, message);
        }
    }
}
