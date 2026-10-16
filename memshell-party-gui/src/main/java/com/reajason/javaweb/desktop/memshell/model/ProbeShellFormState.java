package com.reajason.javaweb.desktop.memshell.model;

/**
 * 探测马生成器表单状态，字段与 web 端 ProbeShellFormSchema 对齐。
 */
public class ProbeShellFormState {
    private String probeMethod = "ResponseBody";
    private String probeContent = "Command";
    private String shellClassName = "";
    private String targetJdkVersion = "50";
    private boolean debug;
    private boolean byPassJavaModule;
    private boolean lambdaSuffix;
    private boolean shrink = true;
    private boolean staticInitialize = true;

    // ResponseBody：目标服务 + 回显参数/命令模板
    private String server = "Tomcat";
    private String reqParamName = "";
    private String commandTemplate = "";
    // DNSLog：域名
    private String host = "";
    // Sleep：候选服务 + 休眠秒数（文本框友好，生成时转 int）
    private String sleepServer = "Tomcat";
    private String seconds = "5";

    private String packingMethod = "";

    public ProbeShellFormState copy() {
        ProbeShellFormState c = new ProbeShellFormState();
        c.probeMethod = probeMethod;
        c.probeContent = probeContent;
        c.shellClassName = shellClassName;
        c.targetJdkVersion = targetJdkVersion;
        c.debug = debug;
        c.byPassJavaModule = byPassJavaModule;
        c.lambdaSuffix = lambdaSuffix;
        c.shrink = shrink;
        c.staticInitialize = staticInitialize;
        c.server = server;
        c.reqParamName = reqParamName;
        c.commandTemplate = commandTemplate;
        c.host = host;
        c.sleepServer = sleepServer;
        c.seconds = seconds;
        c.packingMethod = packingMethod;
        return c;
    }

    public String getProbeMethod() {
        return probeMethod;
    }

    public void setProbeMethod(String probeMethod) {
        this.probeMethod = probeMethod;
    }

    public String getProbeContent() {
        return probeContent;
    }

    public void setProbeContent(String probeContent) {
        this.probeContent = probeContent;
    }

    public String getShellClassName() {
        return shellClassName;
    }

    public void setShellClassName(String shellClassName) {
        this.shellClassName = shellClassName;
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

    public String getServer() {
        return server;
    }

    public void setServer(String server) {
        this.server = server;
    }

    public String getReqParamName() {
        return reqParamName;
    }

    public void setReqParamName(String reqParamName) {
        this.reqParamName = reqParamName;
    }

    public String getCommandTemplate() {
        return commandTemplate;
    }

    public void setCommandTemplate(String commandTemplate) {
        this.commandTemplate = commandTemplate;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getSleepServer() {
        return sleepServer;
    }

    public void setSleepServer(String sleepServer) {
        this.sleepServer = sleepServer;
    }

    public String getSeconds() {
        return seconds;
    }

    public void setSeconds(String seconds) {
        this.seconds = seconds;
    }

    public String getPackingMethod() {
        return packingMethod;
    }

    public void setPackingMethod(String packingMethod) {
        this.packingMethod = packingMethod;
    }
}
