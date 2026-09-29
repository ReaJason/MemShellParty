package com.reajason.javaweb.desktop.memshell.controller;

import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.model.PackerCategory;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import com.reajason.javaweb.memshell.ShellTool;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 表单控制器：持有目录与状态，集中承载 web 端的全部联动/重置/过滤规则，UI 面板保持哑组件。
 */
public class MemShellFormController {
    private final ConfigCatalogService configCatalogService;
    private final MemShellValidator validator;
    private final ConfigCatalogService.ConfigCatalog catalog;
    private final MemShellFormState state = new MemShellFormState();

    public MemShellFormController(ConfigCatalogService configCatalogService, MemShellValidator validator) {
        this.configCatalogService = configCatalogService;
        this.validator = validator;
        this.catalog = configCatalogService.load();
        reconcileAfterServerChange(true);
        reconcilePackerSelection();
    }

    public ConfigCatalogService getConfigCatalogService() {
        return configCatalogService;
    }

    public MemShellFormState getState() {
        return state;
    }

    public ConfigCatalogService.ConfigCatalog getCatalog() {
        return catalog;
    }

    // ---------------- 目录查询 ----------------

    public List<String> getServers() {
        return new ArrayList<String>(catalog.getCore().keySet());
    }

    public List<String> getServerVersionOptions() {
        return configCatalogService.getServerVersionOptions(state.getServer());
    }

    public List<String> getShellTools() {
        Map<String, List<String>> toolMap = catalog.getCore().get(state.getServer());
        if (toolMap == null) {
            return new ArrayList<String>();
        }
        LinkedHashSet<String> tools = new LinkedHashSet<String>(toolMap.keySet());
        tools.add(ShellTool.Custom);
        return new ArrayList<String>(tools);
    }

    public List<String> getShellTypesForCurrentTool() {
        if (ShellTool.Custom.equals(state.getShellTool())) {
            List<String> values = catalog.getCustomShellTypes().get(state.getServer());
            return values == null ? new ArrayList<String>() : new ArrayList<String>(values);
        }
        Map<String, List<String>> toolMap = catalog.getCore().get(state.getServer());
        if (toolMap == null) {
            return new ArrayList<String>();
        }
        List<String> values = toolMap.get(state.getShellTool());
        return values == null ? new ArrayList<String>() : new ArrayList<String>(values);
    }

    public List<String> getCommandEncryptors() {
        return catalog.getCommandEncryptors();
    }

    public List<String> getCommandImplementationClasses() {
        return catalog.getCommandImplementationClasses();
    }

    /**
     * packer 树过滤（对齐 web package-config-card）：
     * shellType 为 Agent* → 仅 Agent* 分类；server 为 XXL* → 排除 Agent*；其余 → 排除 Agent* 与（忽略大小写）xxl*。
     */
    public List<PackerCategory> getFilteredPackers() {
        List<PackerCategory> out = new ArrayList<PackerCategory>();
        for (PackerCategory category : catalog.getPackers()) {
            String name = category.getName();
            String shellType = state.getShellType();
            String server = state.getServer();
            if (shellType != null && shellType.startsWith("Agent")) {
                if (name.startsWith("Agent")) {
                    out.add(category);
                }
                continue;
            }
            if (server != null && server.startsWith("XXL")) {
                if (!name.startsWith("Agent")) {
                    out.add(category);
                }
                continue;
            }
            if (!name.startsWith("Agent") && !name.toLowerCase(Locale.ROOT).startsWith("xxl")) {
                out.add(category);
            }
        }
        return out;
    }

    public PackerCategory findCategoryOf(String packerName) {
        if (packerName == null || packerName.trim().isEmpty()) {
            return null;
        }
        for (PackerCategory category : catalog.getPackers()) {
            if (packerName.equals(category.getName())) {
                return category;
            }
            for (String child : category.getChildren()) {
                if (packerName.equals(child)) {
                    return category;
                }
            }
        }
        return null;
    }

    // ---------------- 可见性查询 ----------------

    public boolean isUrlPatternVisible() {
        return !validator.notNeedUrlPattern(state.getShellType());
    }

    public boolean isCommandParamVisible() {
        if (state.getShellType() != null && state.getShellType().contains("WebSocket")) {
            return false;
        }
        return !"Dubbo".equals(state.getServer());
    }

    public boolean isCommandHeaderVisible() {
        return "BypassNginxWebSocket".equals(state.getShellType())
                || "BypassNginxJakartaWebSocket".equals(state.getShellType());
    }

    public boolean isProxyHeaderVisible() {
        return isCommandHeaderVisible();
    }

    public MemShellValidator.Result validate() {
        return validator.validate(state);
    }

    // ---------------- setter（含联动） ----------------

    public void setServer(String server) {
        state.setServer(server);
        reconcileAfterServerChange(false);
        reconcilePackerSelection();
    }

    public void setServerVersion(String version) {
        state.setServerVersion(version);
    }

    public void setTargetJdkVersion(String value) {
        state.setTargetJdkVersion(value);
        state.setByPassJavaModule(parseInt(value, 50) >= 53);
    }

    public void setShellTool(String tool) {
        handleShellToolChange(tool);
        reconcilePackerSelection();
    }

    public void setShellType(String shellType) {
        state.setShellType(shellType);
        state.setUrlPattern(MemShellFormState.DEFAULT_URL_PATTERN);
        reconcilePackerSelection();
    }

    public void setPacker(String packerName) {
        state.setPackingMethod(packerName);
    }

    public void setUrlPattern(String urlPattern) {
        state.setUrlPattern(urlPattern);
    }

    public void setDebug(boolean value) {
        state.setDebug(value);
    }

    public void setProbe(boolean value) {
        state.setProbe(value);
    }

    public void setByPassJavaModule(boolean value) {
        state.setByPassJavaModule(value);
    }

    public void setLambdaSuffix(boolean value) {
        state.setLambdaSuffix(value);
    }

    public void setShrink(boolean value) {
        state.setShrink(value);
    }

    public void setStaticInitialize(boolean value) {
        state.setStaticInitialize(value);
    }

    public void setGodzillaPass(String v) {
        state.setGodzillaPass(v);
    }

    public void setGodzillaKey(String v) {
        state.setGodzillaKey(v);
    }

    public void setBehinderPass(String v) {
        state.setBehinderPass(v);
    }

    public void setAntSwordPass(String v) {
        state.setAntSwordPass(v);
    }

    public void setCommandParamName(String v) {
        state.setCommandParamName(v);
    }

    public void setCommandTemplate(String v) {
        state.setCommandTemplate(v);
    }

    public void setHeaderName(String v) {
        state.setHeaderName(v);
    }

    public void setHeaderValue(String v) {
        state.setHeaderValue(v);
    }

    public void setShellClassBase64(String v) {
        state.setShellClassBase64(v);
    }

    public void setEncryptor(String v) {
        state.setEncryptor(v);
    }

    public void setImplementationClass(String v) {
        state.setImplementationClass(v);
    }

    public void setShellClassName(String v) {
        state.setShellClassName(v);
    }

    public void setInjectorClassName(String v) {
        state.setInjectorClassName(v);
    }

    public void setCustomInputMode(String mode) {
        state.setCustomInputMode(mode);
    }

    // ---------------- 联动实现 ----------------

    private void reconcileAfterServerChange(boolean initial) {
        List<String> serverVersions = getServerVersionOptions();
        if (!serverVersions.contains(state.getServerVersion())) {
            state.setServerVersion(serverVersions.get(0));
        }

        Map<String, List<String>> toolMap = catalog.getCore().get(state.getServer());
        if (toolMap == null || toolMap.isEmpty()) {
            return;
        }
        List<String> toolKeys = new ArrayList<String>(toolMap.keySet());
        String currentTool = state.getShellTool();
        String nextTool = toolMap.containsKey(currentTool) ? currentTool : toolKeys.get(0);
        state.setShellTool(nextTool);

        // 对齐 web：SpringWebFlux/XXLJOB/Dubbo 至少 Java 8，其余回落 Java 6
        int currentJdk = parseInt(state.getTargetJdkVersion(), 50);
        boolean raise = ("SpringWebFlux".equals(state.getServer())
                || "XXLJOB".equals(state.getServer())
                || "Dubbo".equals(state.getServer())) && currentJdk <= 52;
        state.setTargetJdkVersion(raise ? "52" : "50");
        state.setByPassJavaModule(parseInt(state.getTargetJdkVersion(), 50) >= 53);

        if (!initial) {
            state.setUrlPattern(MemShellFormState.DEFAULT_URL_PATTERN);
        }
        ensureShellTypeValidForCurrentTool();
    }

    private void ensureShellTypeValidForCurrentTool() {
        List<String> shellTypes = getShellTypesForCurrentTool();
        if (shellTypes.isEmpty()) {
            state.setShellType("");
            return;
        }
        if (!shellTypes.contains(state.getShellType())) {
            state.setShellType(shellTypes.get(0));
        }
    }

    private void handleShellToolChange(String value) {
        if (value == null || value.trim().isEmpty()) {
            return;
        }
        state.setUrlPattern(MemShellFormState.DEFAULT_URL_PATTERN);
        state.setShellClassName("");
        state.setInjectorClassName("");

        if (ShellTool.Command.equals(value)) {
            state.setCommandParamName("");
            state.setImplementationClass("");
            state.setEncryptor("");
        } else if (ShellTool.Godzilla.equals(value)) {
            state.setGodzillaKey("");
            state.setGodzillaPass("");
            state.setHeaderName("User-Agent");
            state.setHeaderValue("");
        } else if (ShellTool.Behinder.equals(value)) {
            state.setBehinderPass("");
            state.setHeaderName("User-Agent");
            state.setHeaderValue("");
        } else if (ShellTool.Suo5.equals(value) || ShellTool.Suo5v2.equals(value)) {
            state.setHeaderName("User-Agent");
            state.setHeaderValue("");
        } else if (ShellTool.AntSword.equals(value)) {
            state.setAntSwordPass("");
            state.setHeaderName("User-Agent");
            state.setHeaderValue("");
        } else if (ShellTool.NeoreGeorg.equals(value)) {
            state.setHeaderName("Referer");
            state.setHeaderValue("");
        } else if (ShellTool.Custom.equals(value)) {
            state.setShellClassBase64("");
        } else if (ShellTool.Proxy.equals(value)) {
            state.setHeaderName("User-Agent");
            state.setHeaderValue("");
        }

        state.setShellTool(value);
        ensureShellTypeValidForCurrentTool();
    }

    /**
     * 当前打包选择失效时自动回退：优先当前分类首个子变体，否则分类本身（对齐 web PackerSelector）。
     */
    private void reconcilePackerSelection() {
        List<PackerCategory> filtered = getFilteredPackers();
        if (filtered.isEmpty()) {
            state.setPackingMethod("");
            return;
        }
        boolean exists = false;
        for (PackerCategory category : filtered) {
            if (category.getName().equals(state.getPackingMethod())
                    || category.getChildren().contains(state.getPackingMethod())) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            PackerCategory first = filtered.get(0);
            String next = first.hasChildren() ? first.getChildren().get(0) : first.getName();
            state.setPackingMethod(next);
        }
    }

    private static int parseInt(String v, int d) {
        try {
            return Integer.parseInt(v);
        } catch (Exception e) {
            return d;
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }
}
