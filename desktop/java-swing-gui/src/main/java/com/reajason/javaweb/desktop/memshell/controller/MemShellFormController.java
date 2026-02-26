package com.reajason.javaweb.desktop.memshell.controller;

import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.model.PackerCategoryModel;
import com.reajason.javaweb.desktop.memshell.model.PackerEntryModel;
import com.reajason.javaweb.desktop.memshell.model.PackerSchemaFieldModel;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import com.reajason.javaweb.memshell.ShellTool;

import java.util.*;

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

    public ConfigCatalogService getConfigCatalogService() { return configCatalogService; }
    public MemShellFormState getState() { return state; }
    public ConfigCatalogService.ConfigCatalog getCatalog() { return catalog; }
    public MemShellValidator getValidator() { return validator; }

    public List<String> getServers() {
        return new ArrayList<>(catalog.getServers().keySet());
    }

    public List<String> getServerVersionOptions() {
        return configCatalogService.getServerVersionOptions(state.getServer());
    }

    public List<String> getShellTools() {
        Map<String, List<String>> toolMap = catalog.getCore().get(state.getServer());
        if (toolMap == null) return Collections.emptyList();
        LinkedHashSet<String> tools = new LinkedHashSet<>(toolMap.keySet());
        tools.add(ShellTool.Custom);
        return new ArrayList<>(tools);
    }

    public List<String> getCustomShellTypes() {
        List<String> values = catalog.getServers().get(state.getServer());
        return new ArrayList<String>(values == null ? Collections.<String>emptyList() : values);
    }

    public List<String> getShellTypesForCurrentTool() {
        Map<String, List<String>> toolMap = catalog.getCore().get(state.getServer());
        if (toolMap == null) return Collections.emptyList();
        if (ShellTool.Custom.equals(state.getShellTool())) {
            return getCustomShellTypes();
        }
        List<String> values = toolMap.get(state.getShellTool());
        return new ArrayList<String>(values == null ? Collections.<String>emptyList() : values);
    }

    public List<PackerEntryModel> getFilteredPackers() {
        List<PackerEntryModel> out = new ArrayList<>();
        for (PackerCategoryModel c : catalog.getPackers()) {
            for (PackerEntryModel p : c.getPackers()) {
                if (p.isCategoryAnchor()) continue;
                String name = p.getName();
                String shellType = state.getShellType();
                String server = state.getServer();
                if (shellType != null && shellType.startsWith("Agent")) {
                    if (name.startsWith("Agent")) out.add(p);
                    continue;
                }
                if (server != null && server.startsWith("XXL")) {
                    if (!name.startsWith("Agent")) out.add(p);
                    continue;
                }
                if (!name.startsWith("Agent") && !name.toLowerCase(Locale.ROOT).startsWith("xxl")) {
                    out.add(p);
                }
            }
        }
        return out;
    }

    public PackerEntryModel getSelectedPackerEntry() {
        String selected = state.getPackingMethod();
        if (selected == null || selected.trim().isEmpty()) return null;
        for (PackerCategoryModel c : catalog.getPackers()) {
            for (PackerEntryModel p : c.getPackers()) {
                if (selected.equals(p.getName())) return p;
            }
        }
        return null;
    }

    public List<PackerSchemaFieldModel> getSelectedPackerFields() {
        PackerEntryModel p = getSelectedPackerEntry();
        return p == null ? Collections.<PackerSchemaFieldModel>emptyList() : p.getFields();
    }

    public List<String> getCommandEncryptors() { return catalog.getCommandEncryptors(); }
    public List<String> getCommandImplementationClasses() { return catalog.getCommandImplementationClasses(); }

    public void setServer(String server) {
        state.setServer(server);
        reconcileAfterServerChange(false);
        reconcilePackerSelection();
    }

    public void setServerVersion(String version) { state.setServerVersion(version); }

    public void setTargetJdkVersion(String value) {
        state.setTargetJdkVersion(value);
        try {
            state.setByPassJavaModule(Integer.parseInt(value) >= 53);
        } catch (Exception ignored) {
        }
    }

    public void setShellTool(String tool) {
        handleShellToolChange(tool);
        reconcilePackerSelection();
    }

    public void setShellType(String shellType) {
        state.setShellType(shellType);
        state.setUrlPattern("");
        reconcilePackerSelection();
    }

    public void setUrlPattern(String urlPattern) { state.setUrlPattern(urlPattern); }
    public void setDebug(boolean value) { state.setDebug(value); }
    public void setProbe(boolean value) { state.setProbe(value); }
    public void setByPassJavaModule(boolean value) { state.setByPassJavaModule(value); }
    public void setLambdaSuffix(boolean value) { state.setLambdaSuffix(value); }
    public void setShrink(boolean value) { state.setShrink(value); }
    public void setStaticInitialize(boolean value) { state.setStaticInitialize(value); }

    public void setGodzillaPass(String v) { state.setGodzillaPass(v); }
    public void setGodzillaKey(String v) { state.setGodzillaKey(v); }
    public void setBehinderPass(String v) { state.setBehinderPass(v); }
    public void setAntSwordPass(String v) { state.setAntSwordPass(v); }
    public void setCommandParamName(String v) { state.setCommandParamName(v); }
    public void setCommandTemplate(String v) { state.setCommandTemplate(v); }
    public void setHeaderName(String v) { state.setHeaderName(v); }
    public void setHeaderValue(String v) { state.setHeaderValue(v); }
    public void setShellClassBase64(String v) { state.setShellClassBase64(v); }
    public void setEncryptor(String v) { state.setEncryptor(v); }
    public void setImplementationClass(String v) { state.setImplementationClass(v); }

    public void setShellClassName(String v) {
        state.setShellClassName(v);
        autoDisableRandomIfManualNames();
    }

    public void setInjectorClassName(String v) {
        state.setInjectorClassName(v);
        autoDisableRandomIfManualNames();
    }

    public void setRandomClassName(boolean checked) {
        state.setRandomClassName(checked);
        if (checked) {
            state.setSavedShellClassName(state.getShellClassName());
            state.setSavedInjectorClassName(state.getInjectorClassName());
            state.setShellClassName("");
            state.setInjectorClassName("");
        } else {
            state.setShellClassName(state.getSavedShellClassName());
            state.setInjectorClassName(state.getSavedInjectorClassName());
        }
    }

    public void setCustomInputMode(String mode) { state.setCustomInputMode(mode); }

    public void setPacker(String packerName) {
        state.setPackingMethod(packerName);
        resetPackerCustomConfigToDefaults();
    }

    public void setPackerCustomField(String key, Object value) {
        if (value == null) {
            state.getPackerCustomConfig().remove(key);
        } else {
            state.getPackerCustomConfig().put(key, value);
        }
    }

    public Map<String, Object> getPackerCustomConfig() { return state.getPackerCustomConfig(); }

    public boolean isUrlPatternVisible() {
        return validator.needsUrlPattern(state.getShellType());
    }

    public boolean isCommandHeaderVisible() {
        return "BypassNginxWebSocket".equals(state.getShellType()) || "BypassNginxJakartaWebSocket".equals(state.getShellType());
    }

    public boolean isProxyHeaderVisible() { return isCommandHeaderVisible(); }

    public boolean isCommandParamVisible() {
        return state.getShellType() == null || !state.getShellType().contains("WebSocket");
    }

    public MemShellValidator.Result validate() { return validator.validate(state); }

    private void reconcileAfterServerChange(boolean initial) {
        List<String> serverVersions = getServerVersionOptions();
        if (!serverVersions.contains(state.getServerVersion())) {
            state.setServerVersion(serverVersions.get(0));
        }
        Map<String, List<String>> toolMap = catalog.getCore().get(state.getServer());
        if (toolMap == null || toolMap.isEmpty()) {
            return;
        }
        List<String> toolKeys = new ArrayList<>(toolMap.keySet());
        String currentTool = state.getShellTool();
        String nextTool = toolMap.containsKey(currentTool) ? currentTool : toolKeys.get(0);
        state.setShellTool(nextTool);

        String currentTargetJdk = state.getTargetJdkVersion();
        int currentJdk = parseInt(currentTargetJdk, 50);
        boolean raise = ("SpringWebFlux".equals(state.getServer()) || "XXLJOB".equals(state.getServer())) && currentJdk <= 52;
        state.setTargetJdkVersion(raise ? "52" : "50");
        state.setByPassJavaModule(parseInt(state.getTargetJdkVersion(), 50) >= 53);
        if (!initial) {
            state.setUrlPattern("");
        }

        if (!serverVersions.contains(state.getServerVersion())) {
            state.setServerVersion(serverVersions.get(0));
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
        if (value == null || value.trim().isEmpty()) return;

        state.setUrlPattern("");
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

    private void reconcilePackerSelection() {
        List<PackerEntryModel> filtered = getFilteredPackers();
        if (filtered.isEmpty()) {
            state.setPackingMethod("");
            state.getPackerCustomConfig().clear();
            return;
        }
        boolean exists = filtered.stream().anyMatch(p -> p.getName().equals(state.getPackingMethod()));
        if (!exists) {
            state.setPackingMethod(filtered.get(0).getName());
            resetPackerCustomConfigToDefaults();
        } else if (state.getPackerCustomConfig().isEmpty()) {
            resetPackerCustomConfigToDefaults();
        }
    }

    private void resetPackerCustomConfigToDefaults() {
        state.getPackerCustomConfig().clear();
        PackerEntryModel selected = getSelectedPackerEntry();
        if (selected != null) {
            state.getPackerCustomConfig().putAll(selected.getDefaultConfig());
        }
    }

    private void autoDisableRandomIfManualNames() {
        if (state.isRandomClassName() && (!state.getShellClassName().trim().isEmpty() || !state.getInjectorClassName().trim().isEmpty())) {
            state.setRandomClassName(false);
        }
        if (!state.isRandomClassName()) {
            state.setSavedShellClassName(state.getShellClassName());
            state.setSavedInjectorClassName(state.getInjectorClassName());
        }
    }

    private int parseInt(String v, int d) {
        try {
            return Integer.parseInt(v);
        } catch (Exception e) {
            return d;
        }
    }
}
