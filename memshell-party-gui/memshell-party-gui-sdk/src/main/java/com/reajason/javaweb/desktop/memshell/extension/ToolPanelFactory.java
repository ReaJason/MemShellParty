package com.reajason.javaweb.desktop.memshell.extension;

import com.reajason.javaweb.desktop.memshell.ui.panel.tool.RefreshableToolPanel;

/**
 * 工具面板工厂：按需创建某个 shellTool 的专用面板。
 *
 * <p>面板可以直接继承 {@code AbstractToolPanel}（自动带上"内存马挂载类型 + 请求路径"两个公共字段，
 * 与内置面板外观一致），也可以是完全自定义的组件。
 */
public interface ToolPanelFactory {

    /**
     * @param context 当前工具名与可用的控制器/服务，见 {@link ToolPanelContext}
     */
    RefreshableToolPanel create(ToolPanelContext context);
}
