package com.reajason.javaweb.examples.customgui.gui;

import com.reajason.javaweb.desktop.memshell.extension.GuiExtension;
import com.reajason.javaweb.desktop.memshell.extension.ResultAction;
import com.reajason.javaweb.desktop.memshell.extension.ToolPanelContext;
import com.reajason.javaweb.desktop.memshell.extension.ToolPanelFactory;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.RefreshableToolPanel;
import com.reajason.javaweb.examples.customgui.shelltool.GodzillaSessionShellToolProvider;
import org.kohsuke.MetaInfServices;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 下游发行版的 GUI 扩展：自己的 shelltool（{@code GodzillaSession} 插件）配上自己的界面与动作。
 *
 * <p>{@code @MetaInfServices} 会生成 {@code META-INF/services/...GuiExtension}，
 * 于是 {@code MemShellGui.resolveExtensions()} 开箱就能发现它；打包进自己的客户端时记得合并 SPI 文件
 * （Shadow 的 {@code mergeServiceFiles()}）。
 */
@MetaInfServices(GuiExtension.class)
public class GodzillaSessionGuiExtension implements GuiExtension {

    @Override
    public String name() {
        return "custom-gui-example";
    }

    @Override
    public String applicationTitle(String defaultTitle) {
        return "自定义工具生成器 - " + defaultTitle;
    }

    @Override
    public Map<String, ToolPanelFactory> toolPanels() {
        Map<String, ToolPanelFactory> panels = new LinkedHashMap<String, ToolPanelFactory>();
        // key 就是插件工具名（@ShellToolMeta(name = ...)），这里换成自己的专用面板
        panels.put(GodzillaSessionShellToolProvider.NAME, new ToolPanelFactory() {
            @Override
            public RefreshableToolPanel create(ToolPanelContext context) {
                return new GodzillaSessionToolPanel(context);
            }
        });
        return panels;
    }

    @Override
    public List<ResultAction> resultActions() {
        return Collections.<ResultAction>singletonList(new AddToShellLedgerAction());
    }

    @Override
    public void onResultGenerated(DesktopMemShellGenerateResult result) {
        // 生成即入历史：宿主程序不用等用户点按钮就能拿到最新结果
        ShellLedger.recordGenerated(result);
    }
}
