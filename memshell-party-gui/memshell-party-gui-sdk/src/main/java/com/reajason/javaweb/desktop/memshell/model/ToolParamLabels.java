package com.reajason.javaweb.desktop.memshell.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 内置工具参数的中文名：桌面端表单（{@code DynamicToolPanel}）与结果区（{@code ResultInfoService}）
 * 共用这一份，避免两处展示口径漂移。
 * <p>
 * {@code @ConfigField.label} 优先 —— 内置工具没在注解上写中文名（注解留空，REST 目录的契约
 * 因此不受影响），SPI 插件工具只能走注解这条路；注解也没有才回落参数名本身。
 */
public final class ToolParamLabels {

    private static final Map<String, String> BUILT_IN = builtIn();

    private ToolParamLabels() {
    }

    /**
     * @param paramName       config 字段名，如 {@code pass}
     * @param annotationLabel {@code @ConfigField.label}，留空表示没写
     * @return 表单 / 结果区显示的名字
     */
    public static String of(String paramName, String annotationLabel) {
        if (annotationLabel != null && !annotationLabel.isEmpty()) {
            return annotationLabel;
        }
        String builtIn = BUILT_IN.get(paramName);
        return builtIn == null ? paramName : builtIn;
    }

    public static String of(String paramName) {
        return of(paramName, null);
    }

    private static Map<String, String> builtIn() {
        Map<String, String> labels = new LinkedHashMap<String, String>();
        labels.put("pass", "密码");
        labels.put("key", "密钥");
        labels.put("paramName", "参数名");
        labels.put("template", "命令模板");
        labels.put("encryptor", "加密器");
        labels.put("implementationClass", "实现类");
        labels.put("headerName", "请求头名");
        labels.put("headerValue", "请求头值");
        labels.put("shellClassBase64", "自定义类(Base64)");
        return Collections.unmodifiableMap(labels);
    }
}
