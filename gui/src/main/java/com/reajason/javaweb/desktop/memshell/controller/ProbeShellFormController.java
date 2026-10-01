package com.reajason.javaweb.desktop.memshell.controller;

import com.reajason.javaweb.desktop.memshell.model.PackerCategory;
import com.reajason.javaweb.desktop.memshell.model.ProbeShellFormState;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.ProbeConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.validation.ProbeShellValidator;

import java.util.List;

/**
 * 探测马表单控制器：持有目录与状态，集中承载 web 端 probeshell 页的联动/重置规则，UI 面板保持哑组件。
 */
public class ProbeShellFormController {
    private final ProbeConfigCatalogService catalogService;
    private final ProbeShellValidator validator;
    private final ProbeShellFormState state = new ProbeShellFormState();

    public ProbeShellFormController(ConfigCatalogService configCatalogService, ProbeShellValidator validator) {
        this.catalogService = new ProbeConfigCatalogService(configCatalogService);
        this.validator = validator;
        ensureProbeContentValid();
        reconcilePackerSelection();
    }

    public ProbeConfigCatalogService getCatalogService() {
        return catalogService;
    }

    public ProbeShellFormState getState() {
        return state;
    }

    // ---------------- 目录查询 ----------------

    public List<String> getProbeMethods() {
        return catalogService.getProbeMethods();
    }

    public List<String> getProbeContents() {
        return catalogService.getProbeContents(state.getProbeMethod());
    }

    public List<String> getResponseBodyServers() {
        return catalogService.getResponseBodyServers();
    }

    public List<String> getSleepServers() {
        return catalogService.getSleepServers();
    }

    /**
     * 探测马打包树在加载时已过滤（与状态无关），直接返回全量。
     */
    public List<PackerCategory> getFilteredPackers() {
        return catalogService.getPackers();
    }

    public PackerCategory findCategoryOf(String packerName) {
        if (packerName == null || packerName.trim().isEmpty()) {
            return null;
        }
        for (PackerCategory category : getFilteredPackers()) {
            if (packerName.equals(category.getName()) || category.getChildren().contains(packerName)) {
                return category;
            }
        }
        return null;
    }

    public ProbeShellValidator.Result validate() {
        return validator.validate(state);
    }

    /**
     * 校验指定快照：生成前在 EDT 侧 copy 出快照后，校验与生成必须共用同一份，消 TOCTOU。
     */
    public ProbeShellValidator.Result validate(ProbeShellFormState snapshot) {
        return validator.validate(snapshot);
    }

    // ---------------- setter（含联动） ----------------

    /**
     * 切换探测方式（对齐 web resetFormValues）：探测内容回落到当前方式的首个可选项，
     * Sleep 参数（休眠服务/秒数）回到默认值，其余输入保留。
     */
    public void setProbeMethod(String method) {
        if (method == null || method.trim().isEmpty()) {
            return;
        }
        state.setProbeMethod(method);
        state.setSleepServer("Tomcat");
        state.setSeconds("5");
        ensureProbeContentValid();
    }

    public void setProbeContent(String content) {
        if (content == null || content.trim().isEmpty()) {
            return;
        }
        state.setProbeContent(content);
    }

    public void setTargetJdkVersion(String value) {
        state.setTargetJdkVersion(value);
        state.setByPassJavaModule(parseInt(value, 50) >= 53);
    }

    public void setServer(String v) {
        state.setServer(v);
    }

    public void setReqParamName(String v) {
        state.setReqParamName(v);
    }

    public void setCommandTemplate(String v) {
        state.setCommandTemplate(v);
    }

    public void setHost(String v) {
        state.setHost(v);
    }

    public void setSleepServer(String v) {
        state.setSleepServer(v);
    }

    public void setSeconds(String v) {
        state.setSeconds(v);
    }

    public void setShellClassName(String v) {
        state.setShellClassName(v);
    }

    public void setDebug(boolean value) {
        state.setDebug(value);
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

    public void setPacker(String packerName) {
        state.setPackingMethod(packerName);
    }

    // ---------------- 联动实现 ----------------

    private void ensureProbeContentValid() {
        List<String> contents = getProbeContents();
        if (contents.isEmpty()) {
            state.setProbeContent("");
            return;
        }
        if (!contents.contains(state.getProbeContent())) {
            state.setProbeContent(contents.get(0));
        }
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
        if (findCategoryOf(state.getPackingMethod()) == null) {
            PackerCategory first = filtered.get(0);
            state.setPackingMethod(first.hasChildren() ? first.getChildren().get(0) : first.getName());
        }
    }

    private static int parseInt(String v, int d) {
        try {
            return Integer.parseInt(v);
        } catch (Exception e) {
            return d;
        }
    }
}
