package com.reajason.javaweb.desktop.memshell.controller;

import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ToolConfigFactory;
import com.reajason.javaweb.memshell.ToolParamVisibility;

import com.reajason.javaweb.packer.PackerCategory;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

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
        return catalog.getShellTypeCatalog().getServers();
    }

    public List<String> getServerVersionOptions() {
        return configCatalogService.getServerVersionOptions(state.getServer());
    }

    public List<String> getShellTools() {
        // Custom 不在矩阵里（它没有工具映射），但界面要能选，固定追加在末尾
        LinkedHashSet<String> tools = new LinkedHashSet<String>(
                catalog.getShellTypeCatalog().getShellTools(state.getServer()));
        tools.add(ShellTool.Custom);
        return new ArrayList<String>(tools);
    }

    public List<String> getShellTypesForCurrentTool() {
        if (ShellTool.Custom.equals(state.getShellTool())) {
            List<String> values = catalog.getCustomShellTypes().get(state.getServer());
            return values == null ? new ArrayList<String>() : new ArrayList<String>(values);
        }
        return catalog.getShellTypeCatalog().getShellTypes(state.getServer(), state.getShellTool());
    }

    /**
     * 某工具某个参数的枚举可选值（如 Command 的 encryptor / implementationClass），
     * 取自 config 类上的 {@code @ConfigField}，与 web 端 /api/config/shelltool/configs 同源。
     */
    public List<String> getParamOptions(String tool, String paramName) {
        return catalog.getParamOptions(tool, paramName);
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

    /**
     * 某个工具参数在当前服务端 / 挂载类型下是否有意义（规则见 core 的 {@code ToolParamVisibility}）。
     * 无意义的字段在面板里隐藏而不是禁用：禁用会让人以为填了能生效。
     */
    public boolean isToolParamVisible(String param) {
        return ToolParamVisibility.isVisible(state.getShellTool(), param, state.getServer(), state.getShellType());
    }

    public MemShellValidator.Result validate() {
        return validator.validate(state);
    }

    /**
     * 校验指定快照：生成前在 EDT 侧 copy 出快照后，校验与生成必须共用同一份，消 TOCTOU。
     */
    public MemShellValidator.Result validate(MemShellFormState snapshot) {
        return validator.validate(snapshot);
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

    public void setObfuscation(boolean value) {
        state.setObfuscation(value);
    }

    public void setObfuscationOptions(String value) {
        state.setObfuscationOptions(value);
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

    /**
     * 工具参数：key 就是工具 config 的字段名（{@code pass} / {@code headerName} / {@code shellClassBase64}…）。
     * 面板不需要知道当前是哪个工具 —— 目录（{@code ToolConfigFactory.describeParams}）决定了有哪些字段。
     */
    public void setToolParam(String name, String value) {
        state.setToolParam(name, value);
    }

    // ---------------- 联动实现 ----------------

    private void reconcileAfterServerChange(boolean initial) {
        List<String> serverVersions = getServerVersionOptions();
        if (!serverVersions.contains(state.getServerVersion())) {
            state.setServerVersion(serverVersions.get(0));
        }

        List<String> toolKeys = catalog.getShellTypeCatalog().getShellTools(state.getServer());
        if (toolKeys.isEmpty()) {
            return;
        }
        String currentTool = state.getShellTool();
        String nextTool = toolKeys.contains(currentTool) ? currentTool : toolKeys.get(0);
        if (!nextTool.equals(currentTool)) {
            // 换服务端会顺带换掉当前工具不支持的场景，参数必须跟着清，否则上个工具的参数会发出去报错
            resetToolParamsFor(nextTool);
        }
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

        resetToolParamsFor(value);

        state.setShellTool(value);
        ensureShellTypeValidForCurrentTool();
    }

    /**
     * 通用重置：清空全部工具参数后，headerName 取新工具 config 的 builder 默认值
     * （NeoreGeorg 为 Referer、其余多数为 User-Agent，插件工具自动适用，无需逐工具分支）。
     */
    private void resetToolParamsFor(String tool) {
        state.resetToolParams();
        String defaultHeaderName = ToolConfigFactory.defaultParamValue(tool, "headerName");
        state.setToolParam("headerName", defaultHeaderName == null ? "" : defaultHeaderName);
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
