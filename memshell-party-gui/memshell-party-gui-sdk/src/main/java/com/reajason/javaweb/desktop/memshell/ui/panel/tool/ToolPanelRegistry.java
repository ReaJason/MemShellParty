package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.memshell.MemShellGenerator;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 工具面板注册表：只登记"需要专用面板"的工具（Custom，以及扩展提供的），其余工具一律懒挂
 * 按 {@code @ConfigField} 注解生成的 {@link DynamicToolPanel}。
 *
 * <p>不依赖窗口，可以脱离 UI 单独构造与断言（见各模块的 headless 测试）。
 */
public final class ToolPanelRegistry {
    private final MemShellGenerator memShellGenerator = new MemShellGenerator();
    private final Map<String, RefreshableToolPanel> panels = new LinkedHashMap<String, RefreshableToolPanel>();

    /**
     * 注册（同名覆盖，扩展因此可以顶掉内置面板），返回被覆盖的旧面板，调用方负责把它从容器里摘掉。
     */
    public RefreshableToolPanel register(String shellTool, RefreshableToolPanel panel) {
        return panels.put(shellTool, panel);
    }

    public boolean contains(String shellTool) {
        return panels.containsKey(shellTool);
    }

    public RefreshableToolPanel get(String shellTool) {
        return panels.get(shellTool);
    }

    /**
     * 已建好的面板（按需创建，key 即 shellTool 名）—— 窗口按它逐个挂进 CardLayout。
     */
    public Map<String, RefreshableToolPanel> panels() {
        return new LinkedHashMap<String, RefreshableToolPanel>(panels);
    }

    public List<RefreshableToolPanel> panelList() {
        return new ArrayList<RefreshableToolPanel>(panels.values());
    }

    /**
     * 取当前工具的面板：没有专用面板、但 core 注册过这个工具时，懒挂一个动态参数面板。
     * 既不是内置工具也没有专用面板时返回 null（正常不会出现，工具下拉框和注册表同源）。
     */
    public RefreshableToolPanel resolve(String shellTool, MemShellFormController controller, Runnable refreshAll) {
        if (shellTool == null) {
            return null;
        }
        RefreshableToolPanel panel = panels.get(shellTool);
        if (panel == null && memShellGenerator.getToolProvider(shellTool) != null) {
            panel = new DynamicToolPanel(shellTool, controller, refreshAll);
            panels.put(shellTool, panel);
        }
        return panel;
    }
}
