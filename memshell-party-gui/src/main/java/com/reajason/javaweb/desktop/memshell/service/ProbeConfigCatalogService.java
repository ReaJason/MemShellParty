package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.PackerCategory;
import com.reajason.javaweb.probe.generator.response.ResponseBodyGenerator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 探测马配置目录：探测方式/探测内容选项、ResponseBody 与 Sleep 的候选服务、探测马可用的打包树。
 * 选项集对齐 web 端 probeshell/main-config-card 与 package-config-card。
 */
public class ProbeConfigCatalogService {

    /**
     * 探测方式顺序对齐 web PROBE_METHOD_OPTIONS。
     */
    private static final List<String> PROBE_METHODS = Arrays.asList("ResponseBody", "DNSLog", "Sleep");

    /**
     * 探测方式 → 可选探测内容，对齐 web filterMap。
     */
    private static final Map<String, List<String>> METHOD_CONTENTS = new LinkedHashMap<String, List<String>>();

    /**
     * Sleep 探测的候选服务名（运行时 ServerProbe 按实际服务名比对命中后休眠），
     * 对齐 web MIDDLEWARE_OPTIONS。
     */
    private static final List<String> SLEEP_SERVERS = Arrays.asList(
            "Tomcat", "Jetty", "Undertow", "Resin", "JBoss", "GlassFish", "BES",
            "TongWeb", "InforSuite", "Apusic", "SpringWebFlux", "WebLogic", "WebSphere");

    static {
        METHOD_CONTENTS.put("ResponseBody", Arrays.asList("Command", "Bytecode", "ScriptEngine", "Filter"));
        METHOD_CONTENTS.put("DNSLog", Arrays.asList("JDK", "Server"));
        METHOD_CONTENTS.put("Sleep", Arrays.asList("Server"));
    }

    private final ConfigCatalogService configCatalogService;
    private final List<PackerCategory> packers;

    public ProbeConfigCatalogService(ConfigCatalogService configCatalogService) {
        this.configCatalogService = configCatalogService;
        this.packers = filterPackers(configCatalogService.load().getPackers());
    }

    public ConfigCatalogService getConfigCatalogService() {
        return configCatalogService;
    }

    public List<String> getProbeMethods() {
        return PROBE_METHODS;
    }

    public List<String> getProbeContents(String probeMethod) {
        List<String> contents = METHOD_CONTENTS.get(probeMethod);
        return contents == null ? new ArrayList<String>() : contents;
    }

    /**
     * ResponseBody 探测支持的目标服务，与 boot 端 /api/config/probe/response-body/servers 同源。
     */
    public List<String> getResponseBodyServers() {
        return ResponseBodyGenerator.getSupportedServers();
    }

    public List<String> getSleepServers() {
        return SLEEP_SERVERS;
    }

    public List<PackerCategory> getPackers() {
        return packers;
    }

    public List<String> getTargetJdkOptions() {
        return configCatalogService.getTargetJdkOptions();
    }

    public String getTargetJdkLabel(String value) {
        return configCatalogService.getTargetJdkLabel(value);
    }

    /**
     * 探测马打包树过滤（对齐 web probeshell/package-config-card）：
     * 排除 Agent*、xxl*（探测马无注入器，agent/调度任务类产物不适用）与 *Jar 分类。
     */
    private static List<PackerCategory> filterPackers(List<PackerCategory> all) {
        List<PackerCategory> out = new ArrayList<PackerCategory>();
        for (PackerCategory category : all) {
            String name = category.getName();
            String lower = name.toLowerCase(Locale.ROOT);
            if (name.startsWith("Agent") || lower.startsWith("xxl") || lower.endsWith("jar")) {
                continue;
            }
            out.add(category);
        }
        return out;
    }
}
