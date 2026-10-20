package com.reajason.javaweb.examples.customshellgui;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.desktop.memshell.MemShellGui;
import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.extension.GuiExtension;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.CustomClassNameParser;
import com.reajason.javaweb.desktop.memshell.service.GenerationService;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.RefreshableToolPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.ToolPanelRegistry;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.ToolPanels;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import com.reajason.javaweb.examples.customshelltool.GodzillaSessionConfig;
import com.reajason.javaweb.examples.customshelltool.GodzillaSessionShellToolProvider;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 无窗口验证：扩展被 SPI 发现、自定义工具的专用面板接管、参数经 GUI 链路绑定到工具 config、
 * 结果回调/动作按钮把结果同步给下游台账。
 */
class GodzillaSessionGuiExtensionTest {

    private static final String TOOL = GodzillaSessionShellToolProvider.NAME;

    private final Runnable refreshAll = new Runnable() {
        @Override
        public void run() {
        }
    };

    @BeforeEach
    @AfterEach
    void clearLedger() {
        ShellLedger.clear();
    }

    @Test
    void spiDiscoversTheExtension() {
        // META-INF/services/...GuiExtension 由 @MetaInfServices 生成，MemShellGui.resolveExtensions 靠它自动发现
        List<GuiExtension> extensions = MemShellGui.resolveExtensions();
        assertEquals(1, extensions.size(), extensions.toString());
        assertEquals("custom-shelltool-gui-example", extensions.get(0).name());
    }

    @Test
    void explicitExtensionDoesNotDuplicateTheDiscoveredOne() {
        // 显式传入同名扩展时按名字去重，不会出现两份面板/两个按钮
        List<GuiExtension> extensions = MemShellGui.resolveExtensions(new GodzillaSessionGuiExtension());
        assertEquals(1, extensions.size(), extensions.toString());
    }

    @Test
    void customToolShowsUpInTheToolDropdownAndGetsItsOwnPanel() {
        MemShellFormController controller = controller();

        // 插件工具本来就在 GUI 的工具下拉框里（server.getSupportedShellTool × 注入器映射求交集）
        assertTrue(controller.getShellTools().contains(TOOL), controller.getShellTools().toString());

        ToolPanelRegistry registry = ToolPanels.createRegistry(controller, refreshAll,
                new CustomClassNameParser(), MemShellGui.resolveExtensions());
        RefreshableToolPanel panel = registry.get(TOOL);
        assertInstanceOf(GodzillaSessionToolPanel.class, panel);
    }

    @Test
    void panelParamsReachTheGeneratedToolConfig() {
        MemShellFormState state = new MemShellFormState();
        state.setServer(Server.Tomcat);
        state.setServerVersion("Unknown");
        state.setShellTool(TOOL);
        state.setShellType(ShellType.FILTER);
        state.setPackingMethod(Packers.DefaultBase64);
        // 专用面板写进去的就是这些（toolParams → 工具 config builder），生成链路和动态面板一致
        state.setToolParam("pass", "passFilter");
        state.setToolParam("key", "keyFilter");
        state.setToolParam("headerValue", "Firefox");
        state.setToolParam("sessionKey", "sessionCore");

        DesktopMemShellGenerateResult result = new GenerationService().generate(state);

        GodzillaSessionConfig config = (GodzillaSessionConfig) result.getMemShellResult().getShellToolConfig();
        assertEquals("passFilter", config.getPass());
        assertEquals("keyFilter", config.getKey());
        assertEquals("Firefox", config.getHeaderValue());
        assertEquals("sessionCore", config.getSessionKey());
        assertFalse(result.getMemShellResult().getShellBytesBase64Str().isEmpty());
    }

    @Test
    void resultHooksFeedTheDownstreamLedger() {
        DesktopMemShellGenerateResult result = generate();
        GodzillaSessionGuiExtension extension = new GodzillaSessionGuiExtension();

        // 回调：生成即入历史（GUI 每次生成成功后调用）
        extension.onResultGenerated(result);
        assertEquals(1, ShellLedger.history().size());
        assertTrue(ShellLedger.myShells().isEmpty(), "回调不该动\"我的 Shell 列表\"");
        ShellLedger.Entry historyEntry = ShellLedger.history().get(0);
        assertEquals(result.getMemShellResult().getShellClassName(), historyEntry.getShellClassName());
        assertEquals(Server.Tomcat, historyEntry.getServer());
        assertTrue(historyEntry.getConnectionInfo().contains("pass="), historyEntry.getConnectionInfo());

        // 动作按钮：用户手动加入"我的 Shell 列表"
        assertEquals("加入我的 Shell 列表", extension.resultActions().get(0).label());
        extension.resultActions().get(0).perform(result);
        assertEquals(1, ShellLedger.myShells().size());
        assertEquals(1, ShellLedger.history().size(), "手动加入不该影响历史");
    }

    private static DesktopMemShellGenerateResult generate() {
        MemShellFormState state = new MemShellFormState();
        state.setServer(Server.Tomcat);
        state.setServerVersion("Unknown");
        state.setShellTool(TOOL);
        state.setShellType(ShellType.FILTER);
        state.setPackingMethod(Packers.DefaultBase64);
        return new GenerationService().generate(state);
    }

    private static MemShellFormController controller() {
        return new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
    }
}
