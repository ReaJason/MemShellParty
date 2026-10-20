package com.reajason.javaweb.desktop.memshell.validation;

import com.reajason.javaweb.desktop.memshell.model.ProbeShellFormState;
import com.reajason.javaweb.memshell.PackerRegistry;
import com.reajason.javaweb.probe.ProbeMethod;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 探测马表单校验，规则对齐 web 端 probeShellFormSchema 与各探测方式的生成器前置条件。
 */
public class ProbeShellValidator {

    /**
     * RFC 7230 header-field-name token。
     */
    private static final Pattern HEADER_NAME_PATTERN = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");

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

    public Result validate(ProbeShellFormState s) {
        Result r = new Result();
        required(r, "probeMethod", s.getProbeMethod(), "请选择探测方式");
        required(r, "probeContent", s.getProbeContent(), "请选择探测内容");
        // 空打包方式合法（直接输出 raw Base64）；非空时必须能在注册表里找到
        if (!isBlank(s.getPackingMethod()) && !PackerRegistry.getInstance().contains(s.getPackingMethod())) {
            r.add("packingMethod", "未知打包方式: " + s.getPackingMethod());
        }

        if (ProbeMethod.DNSLog.name().equals(s.getProbeMethod()) && isBlank(s.getHost())) {
            r.add("host", "请填写 DNSLog 域名");
        }
        if ((ProbeMethod.ResponseBody.name().equals(s.getProbeMethod())
                || ProbeMethod.ResponseHeader.name().equals(s.getProbeMethod()))
                && isBlank(s.getServer())) {
            r.add("server", "请选择目标服务");
        }
        if (ProbeMethod.ResponseHeader.name().equals(s.getProbeMethod())
                && !isBlank(s.getRespHeaderName())
                && !HEADER_NAME_PATTERN.matcher(s.getRespHeaderName().trim()).matches()) {
            r.add("respHeaderName", "响应头名称只能包含字母、数字和 header token 字符");
        }
        if (ProbeMethod.Sleep.name().equals(s.getProbeMethod())) {
            required(r, "sleepServer", s.getSleepServer(), "请选择休眠探测服务");
            // 对齐 SleepGenerator：seconds 必须大于 0
            if (parsePositiveInt(s.getSeconds()) <= 0) {
                r.add("seconds", "休眠秒数必须为大于 0 的整数");
            }
        }
        return r;
    }

    private void required(Result r, String field, String value, String message) {
        if (isBlank(value)) {
            r.add(field, message);
        }
    }

    private static int parsePositiveInt(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (Exception e) {
            return -1;
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }
}
