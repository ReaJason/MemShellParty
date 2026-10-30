package com.reajason.javaweb.examples.plugin;

/**
 * 最小注入器模板：只演示生成期字节码替换，不针对真实中间件执行注入。
 */
public class ExampleInjector {
    public String getUrlPattern() {
        return "{{urlPattern}}";
    }

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() {
        return "{{base64Str}}";
    }
}
