package com.reajason.javaweb.desktop.memshell.validation;

import com.reajason.javaweb.desktop.memshell.model.ProbeShellFormState;
import com.reajason.javaweb.probe.ProbeMethod;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 探测马表单校验，规则对齐 web 端 probeShellFormSchema 与各探测方式的生成器前置条件。
 */
public class ProbeShellValidator {

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
        required(r, "packingMethod", s.getPackingMethod(), "请选择打包方式");

        if (ProbeMethod.DNSLog.name().equals(s.getProbeMethod()) && isBlank(s.getHost())) {
            r.add("host", "请填写 DNSLog 域名");
        }
        if (ProbeMethod.ResponseBody.name().equals(s.getProbeMethod()) && isBlank(s.getServer())) {
            r.add("server", "请选择目标服务");
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
