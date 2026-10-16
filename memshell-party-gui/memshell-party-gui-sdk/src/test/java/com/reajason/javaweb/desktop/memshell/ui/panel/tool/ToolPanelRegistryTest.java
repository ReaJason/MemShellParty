package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.extension.GuiExtension;
import com.reajason.javaweb.desktop.memshell.extension.ToolPanelContext;
import com.reajason.javaweb.desktop.memshell.extension.ToolPanelFactory;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.CustomClassNameParser;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.memshell.MemShellRegistry;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.ToolMapping;
import com.reajason.javaweb.memshell.spi.ShellToolProvider;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * 工具面板注册表：专用面板（Custom）、扩展面板、其余工具的动态参数面板 —— 全部无需窗口即可断言。
 */
class ToolPanelRegistryTest {

    private static final String PLUGIN_TOOL = "TestPluginTool";

    private final MemShellFormController controller =
            new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
    private final Runnable refreshAll = new Runnable() {
        @Override
        public void run() {
        }
    };

    /**
     * 只有输入不是普通字段的工具才留专用面板（Custom 是 Base64 ⇄ .class），其余全走动态表单。
     */
    @Test
    void onlyCustomKeepsADedicatedPanel() {
        ToolPanelRegistry registry = registry(Collections.<GuiExtension>emptyList());
        assertInstanceOf(CustomToolPanel.class, registry.get(ShellTool.Custom));
        assertFalse(registry.contains(ShellTool.Godzilla), "内置工具不再逐个登记");
        assertInstanceOf(DynamicToolPanel.class, registry.resolve(ShellTool.Godzilla, controller, refreshAll));
    }

    @Test
    void pluginToolWithoutExtensionFallsBackToTheDynamicPanel() {
        registerPluginTool(PLUGIN_TOOL);
        ToolPanelRegistry registry = registry(Collections.<GuiExtension>emptyList());
        assertInstanceOf(DynamicToolPanel.class, registry.resolve(PLUGIN_TOOL, controller, refreshAll));
    }

    @Test
    void extensionPanelTakesOverItsTool() {
        registerPluginTool(PLUGIN_TOOL);
        TestToolPanelFactory factory = new TestToolPanelFactory();
        ToolPanelRegistry registry = registry(
                Collections.<GuiExtension>singletonList(new TestExtension(PLUGIN_TOOL, factory)));

        TestToolPanel panel = assertInstanceOf(TestToolPanel.class, registry.get(PLUGIN_TOOL));
        assertSame(panel, registry.resolve(PLUGIN_TOOL, controller, refreshAll), "有专用面板就不该再建通用面板");
        // 工厂拿到的是"当前这个工具"的上下文
        assertEquals(PLUGIN_TOOL, factory.createdToolName);
        assertNotNull(factory.refreshAll);
        assertSame(controller, factory.controller);
    }

    @Test
    void extensionCanOverrideABuiltInPanel() {
        ToolPanelRegistry registry = registry(Collections.<GuiExtension>singletonList(
                new TestExtension(ShellTool.Godzilla, new TestToolPanelFactory())));
        assertInstanceOf(TestToolPanel.class, registry.get(ShellTool.Godzilla));
    }

    private ToolPanelRegistry registry(List<GuiExtension> extensions) {
        return ToolPanels.createRegistry(controller, refreshAll, new CustomClassNameParser(), extensions);
    }

    /**
     * 造一个 core 里注册过的插件工具：动态面板兜底逻辑要求工具得在 registry 里。
     */
    private static void registerPluginTool(String name) {
        MemShellRegistry.getInstance().registerTool(name, new ShellToolProvider() {
            @Override
            public ToolMapping getToolMapping() {
                return ToolMapping.builder().build();
            }

            @Override
            public Class<? extends ShellToolConfig> getConfigClass() {
                return ShellToolConfig.class;
            }

            @Override
            public Class<? extends ShellGenerator> getGeneratorClass() {
                return null;
            }
        });
    }

    private static final class TestExtension implements GuiExtension {
        private final String tool;
        private final ToolPanelFactory factory;

        private TestExtension(String tool, ToolPanelFactory factory) {
            this.tool = tool;
            this.factory = factory;
        }

        @Override
        public String name() {
            return "test-extension";
        }

        @Override
        public Map<String, ToolPanelFactory> toolPanels() {
            Map<String, ToolPanelFactory> panels = new LinkedHashMap<String, ToolPanelFactory>();
            panels.put(tool, factory);
            return panels;
        }
    }

    private static final class TestToolPanelFactory implements ToolPanelFactory {
        private String createdToolName;
        private Runnable refreshAll;
        private MemShellFormController controller;

        @Override
        public RefreshableToolPanel create(ToolPanelContext context) {
            createdToolName = context.getShellTool();
            refreshAll = context.getRefreshAll();
            controller = context.getController();
            return new TestToolPanel(context.getController(), context.getRefreshAll());
        }
    }

    private static final class TestToolPanel extends AbstractToolPanel {
        private TestToolPanel(MemShellFormController controller, Runnable refreshAll) {
            super(controller, refreshAll);
        }
    }
}
