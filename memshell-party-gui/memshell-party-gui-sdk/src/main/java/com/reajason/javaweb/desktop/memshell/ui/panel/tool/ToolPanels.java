package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.extension.GuiExtension;
import com.reajason.javaweb.desktop.memshell.extension.ToolPanelContext;
import com.reajason.javaweb.desktop.memshell.extension.ToolPanelFactory;
import com.reajason.javaweb.desktop.memshell.service.CustomClassNameParser;
import com.reajason.javaweb.memshell.ShellTool;

import java.util.List;
import java.util.Map;

/**
 * 工具面板目录：登记需要专用面板的工具（Custom），其余工具的参数面板由
 * {@link ToolPanelRegistry#resolve} 按 {@code @ConfigField} 注解动态生成。
 */
public final class ToolPanels {

    private ToolPanels() {
    }

    /**
     * 专用面板 + 扩展面板（扩展同名覆盖内置，顺序为内置在前、扩展按传入顺序在后）。
     */
    public static ToolPanelRegistry createRegistry(MemShellFormController controller,
                                                   Runnable refreshAll,
                                                   CustomClassNameParser parser,
                                                   List<GuiExtension> extensions) {
        ToolPanelRegistry registry = new ToolPanelRegistry();
        // Custom 的输入是"字节码本身"（Base64 ⇄ .class + 类名解析），生成器画不出这种字段，只能专用面板
        registry.register(ShellTool.Custom, new CustomToolPanel(controller, parser, refreshAll));

        if (extensions != null) {
            for (GuiExtension extension : extensions) {
                for (Map.Entry<String, ToolPanelFactory> entry : extension.toolPanels().entrySet()) {
                    ToolPanelContext context = new ToolPanelContext(entry.getKey(), controller, parser, refreshAll);
                    registry.register(entry.getKey(), entry.getValue().create(context));
                }
            }
        }
        return registry;
    }
}
