package com.reajason.javaweb.desktop.memshell.model;

/**
 * 内存马生成器表单状态，字段与 web 端 MemShellFormSchema 对齐。
 */
public class MemShellFormState {
    public static final String DEFAULT_URL_PATTERN = "/*";

    private String server = "Tomcat";
    private String serverVersion = "Unknown";
    private String targetJdkVersion = "50";
    private boolean debug;
    private boolean byPassJavaModule;
    private boolean probe;
    private boolean lambdaSuffix;
    private boolean shrink = true;
    private boolean staticInitialize = true;

    private String shellTool = "Godzilla";
    private String shellType = "Listener";
    private String urlPattern = DEFAULT_URL_PATTERN;

    private String shellClassName = "";
    private String injectorClassName = "";

    private String godzillaPass = "";
    private String godzillaKey = "";
    private String behinderPass = "";
    private String antSwordPass = "";
    private String commandParamName = "";
    private String commandTemplate = "";
    private String headerName = "User-Agent";
    private String headerValue = "";
    private String shellClassBase64 = "";
    private String encryptor = "";
    private String implementationClass = "";

    private String packingMethod = "";

    private String customInputMode = "base64";

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
        c.godzillaPass = godzillaPass;
        c.godzillaKey = godzillaKey;
        c.behinderPass = behinderPass;
        c.antSwordPass = antSwordPass;
        c.commandParamName = commandParamName;
        c.commandTemplate = commandTemplate;
        c.headerName = headerName;
        c.headerValue = headerValue;
        c.shellClassBase64 = shellClassBase64;
        c.encryptor = encryptor;
        c.implementationClass = implementationClass;
        c.packingMethod = packingMethod;
        c.customInputMode = customInputMode;
        return c;
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

    public String getGodzillaPass() {
        return godzillaPass;
    }

    public void setGodzillaPass(String godzillaPass) {
        this.godzillaPass = godzillaPass;
    }

    public String getGodzillaKey() {
        return godzillaKey;
    }

    public void setGodzillaKey(String godzillaKey) {
        this.godzillaKey = godzillaKey;
    }

    public String getBehinderPass() {
        return behinderPass;
    }

    public void setBehinderPass(String behinderPass) {
        this.behinderPass = behinderPass;
    }

    public String getAntSwordPass() {
        return antSwordPass;
    }

    public void setAntSwordPass(String antSwordPass) {
        this.antSwordPass = antSwordPass;
    }

    public String getCommandParamName() {
        return commandParamName;
    }

    public void setCommandParamName(String commandParamName) {
        this.commandParamName = commandParamName;
    }

    public String getCommandTemplate() {
        return commandTemplate;
    }

    public void setCommandTemplate(String commandTemplate) {
        this.commandTemplate = commandTemplate;
    }

    public String getHeaderName() {
        return headerName;
    }

    public void setHeaderName(String headerName) {
        this.headerName = headerName;
    }

    public String getHeaderValue() {
        return headerValue;
    }

    public void setHeaderValue(String headerValue) {
        this.headerValue = headerValue;
    }

    public String getShellClassBase64() {
        return shellClassBase64;
    }

    public void setShellClassBase64(String shellClassBase64) {
        this.shellClassBase64 = shellClassBase64;
    }

    public String getEncryptor() {
        return encryptor;
    }

    public void setEncryptor(String encryptor) {
        this.encryptor = encryptor;
    }

    public String getImplementationClass() {
        return implementationClass;
    }

    public void setImplementationClass(String implementationClass) {
        this.implementationClass = implementationClass;
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
