package com.reajason.javaweb.desktop.memshell.extension;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.service.CustomClassNameParser;

/**
 * 工具面板的上下文：面板要用的东西都从这里拿，避免扩展去摸 GUI 内部实现。
 */
public final class ToolPanelContext {
    private final String shellTool;
    private final MemShellFormController controller;
    private final CustomClassNameParser customClassNameParser;
    private final Runnable refreshAll;

    public ToolPanelContext(String shellTool,
                            MemShellFormController controller,
                            CustomClassNameParser customClassNameParser,
                            Runnable refreshAll) {
        this.shellTool = shellTool;
        this.controller = controller;
        this.customClassNameParser = customClassNameParser;
        this.refreshAll = refreshAll;
    }

    /**
     * 当前工具名（{@link GuiExtension#toolPanels()} 里的 key）。
     */
    public String getShellTool() {
        return shellTool;
    }

    /**
     * 表单控制器：参数读写（{@code setToolParam(paramName, value)}）、联动、校验都走它。
     */
    public MemShellFormController getController() {
        return controller;
    }

    /**
     * class 字节 → 类名解析：自定义内存马面板（Custom）用它回填类名。
     */
    public CustomClassNameParser getCustomClassNameParser() {
        return customClassNameParser;
    }

    /**
     * 触发一次全局刷新：面板做了结构性改动（如改了挂载类型列表）后调用。
     */
    public Runnable getRefreshAll() {
        return refreshAll;
    }
}
