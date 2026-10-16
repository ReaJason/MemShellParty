package com.reajason.javaweb.desktop.memshell.model;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 内存马生成器表单状态，字段与 web 端 MemShellFormSchema 对齐。
 * <p>
 * 工具参数统一放在 {@link #toolParams} 里，key 就是工具 config 的字段名（{@code pass} / {@code headerName} / …），
 * 与 web 端表单、{@code /api/config/shelltool/configs} 同源 —— 内置工具与插件工具因此走同一条链路。
 */
public class MemShellFormState {
    public static final String DEFAULT_URL_PATTERN = "/*";

    /**
     * Custom 工具的自定义内存马类（Base64），即 {@code CustomConfig.shellClassBase64} 的字段名。
     */
    public static final String PARAM_SHELL_CLASS_BASE64 = "shellClassBase64";

    private String server = "Tomcat";
    private String serverVersion = "Unknown";
    private String targetJdkVersion = "50";
    private boolean debug;
    private boolean byPassJavaModule;
    private boolean probe;
    private boolean lambdaSuffix;
    private boolean shrink = true;
    private boolean staticInitialize = true;

    /**
     * 留空 = 由 {@code MemShellFormController} 取当前服务支持的第一个工具（插件工具 order 小就排前面）。
     * 写死某个内置工具名会让下游自带工具永远不是默认项。
     */
    private String shellTool = "";
    private String shellType = "Listener";
    private String urlPattern = DEFAULT_URL_PATTERN;

    private String shellClassName = "";
    private String injectorClassName = "";

    private String packingMethod = "";

    private String customInputMode = "base64";

    /**
     * 当前工具的参数，key 为 config 字段名；切换工具时整体清空，避免上一个工具的取值跟着发出去。
     */
    private final Map<String, String> toolParams = new LinkedHashMap<String, String>();

    public MemShellFormState copy() {
        MemShellFormState c = new MemShellFormState();
        c.server = server;
        c.serverVersion = serverVersion;
        c.targetJdkVersion = targetJdkVersion;
        c.debug = debug;
        c.byPassJavaModule = byPassJavaModule;
        c.probe = probe;
        c.lambdaSuffix = lambdaSuffix;
        c.shrink = shrink;
        c.staticInitialize = staticInitialize;
        c.shellTool = shellTool;
        c.shellType = shellType;
        c.urlPattern = urlPattern;
        c.shellClassName = shellClassName;
        c.injectorClassName = injectorClassName;
        c.packingMethod = packingMethod;
        c.customInputMode = customInputMode;
        c.toolParams.putAll(toolParams);
        return c;
    }

    public Map<String, String> getToolParams() {
        return toolParams;
    }

    public String getToolParam(String name) {
        String value = toolParams.get(name);
        return value == null ? "" : value;
    }

    public void setToolParam(String name, String value) {
        toolParams.put(name, value);
    }

    /**
     * 清空全部工具参数，由调用方按新工具的默认值重设（见 {@code MemShellFormController}）。
     */
    public void resetToolParams() {
        toolParams.clear();
    }

    public String getServer() {
        return server;
    }

    public void setServer(String server) {
        this.server = server;
    }

    public String getServerVersion() {
        return serverVersion;
    }

    public void setServerVersion(String serverVersion) {
        this.serverVersion = serverVersion;
    }

    public String getTargetJdkVersion() {
        return targetJdkVersion;
    }

    public void setTargetJdkVersion(String targetJdkVersion) {
        this.targetJdkVersion = targetJdkVersion;
    }

    public boolean isDebug() {
        return debug;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    public boolean isByPassJavaModule() {
        return byPassJavaModule;
    }

    public void setByPassJavaModule(boolean byPassJavaModule) {
        this.byPassJavaModule = byPassJavaModule;
    }

    public boolean isProbe() {
        return probe;
    }

    public void setProbe(boolean probe) {
        this.probe = probe;
    }

    public boolean isLambdaSuffix() {
        return lambdaSuffix;
    }

    public void setLambdaSuffix(boolean lambdaSuffix) {
        this.lambdaSuffix = lambdaSuffix;
    }

    public boolean isShrink() {
        return shrink;
    }

    public void setShrink(boolean shrink) {
        this.shrink = shrink;
    }

    public boolean isStaticInitialize() {
        return staticInitialize;
    }

    public void setStaticInitialize(boolean staticInitialize) {
        this.staticInitialize = staticInitialize;
    }

    public String getShellTool() {
        return shellTool;
    }

    public void setShellTool(String shellTool) {
        this.shellTool = shellTool;
    }

    public String getShellType() {
        return shellType;
    }

    public void setShellType(String shellType) {
        this.shellType = shellType;
    }

    public String getUrlPattern() {
        return urlPattern;
    }

    public void setUrlPattern(String urlPattern) {
        this.urlPattern = urlPattern;
    }

    public String getShellClassName() {
        return shellClassName;
    }

    public void setShellClassName(String shellClassName) {
        this.shellClassName = shellClassName;
    }

    public String getInjectorClassName() {
        return injectorClassName;
    }

    public void setInjectorClassName(String injectorClassName) {
        this.injectorClassName = injectorClassName;
    }

    public String getPackingMethod() {
        return packingMethod;
    }

    public void setPackingMethod(String packingMethod) {
        this.packingMethod = packingMethod;
    }

    public String getCustomInputMode() {
        return customInputMode;
    }

    public void setCustomInputMode(String customInputMode) {
        this.customInputMode = customInputMode;
    }
}
