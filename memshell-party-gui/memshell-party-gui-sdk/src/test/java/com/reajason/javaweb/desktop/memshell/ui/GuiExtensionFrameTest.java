package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.MemShellGui;
import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.extension.GuiExtension;
import com.reajason.javaweb.desktop.memshell.extension.ResultAction;
import com.reajason.javaweb.desktop.memshell.extension.ToolPanelContext;
import com.reajason.javaweb.desktop.memshell.extension.ToolPanelFactory;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.AbstractToolPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.RefreshableToolPanel;
import com.reajason.javaweb.desktop.memshell.util.AppVersion;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.GraphicsEnvironment;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 扩展点接进内存马生成器的效果：标题被接管、专用面板按工具名挂上、结果动作按钮出现在结果区、
 * 状态出口收到消息（外壳不在了，状态归宿主显示）。
 * 需要显示环境（与 {@link MemShellGeneratorFrameLayoutTest} 同款：headless 跳过，不安装 FlatLaf）。
 */
class GuiExtensionFrameTest {

    @Test
    void frameHonoursExtensionTitlePanelAndResultActions() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final TestExtension extension = new TestExtension();
        final MemShellGeneratorFrame[] frameHolder = new MemShellGeneratorFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frameHolder[0] = MemShellGui.createMemShellFrame(extension);
            }
        });
        final MemShellGeneratorFrame frame = frameHolder[0];
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    // 品牌：标题基于默认标题改写
                    assertEquals("TestKit · MemShellParty v" + AppVersion.get(), frame.getTitle());

                    // 专用面板：按工具名注册，且已经挂进工具卡
                    RefreshableToolPanel panel = frame.getToolPanelRegistry().get("TestGuiTool");
                    assertInstanceOf(TestToolPanel.class, panel);

                    // 结果动作按钮出现在结果区（还没有结果，所以是禁用的）
                    JButton action = find(frame.getContentPane(), JButton.class, "加入我的列表");
                    assertNotNull(action, "扩展提供的动作按钮应当出现在结果区");
                    assertFalse(action.isEnabled());
                }
            });
        } finally {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    frame.dispose();
                }
            });
        }
    }

    /**
     * 状态出口：宿主设了 reporter 就收到「校验失败」这类消息；不设时静默（这里两者都验一遍，
     * 保证内嵌宿主接状态栏与只拿界面的宿主都能用）。
     */
    @Test
    void statusReporterReceivesGenerationMessages() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final List<String> reported = new ArrayList<String>();
        final MemShellGeneratorFrame[] frameHolder = new MemShellGeneratorFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frameHolder[0] = MemShellGui.createMemShellFrame();
                frameHolder[0].setStatusReporter(new StatusReporter() {
                    @Override
                    public void report(String message, StatusReporter.Level level) {
                        reported.add(level + ":" + message);
                    }
                });
            }
        });
        final MemShellGeneratorFrame frame = frameHolder[0];
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    // 清掉必填项制造校验失败，不真的跑生成
                    frame.getController().setServerVersion("");
                    frame.triggerGenerate();
                }
            });

            assertEquals(1, reported.size(), reported.toString());
            assertTrue(reported.get(0).startsWith("ERROR:校验失败"), reported.toString());

            // 传 null 回到静默：再来一次不再上报
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    frame.setStatusReporter(null);
                    frame.triggerGenerate();
                }
            });
            assertEquals(1, reported.size(), reported.toString());
        } finally {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    frame.dispose();
                }
            });
        }
    }

    /**
     * 深度优先找第一个文案匹配的组件（测试内部用，不去动 GUI 的内部结构）。
     */
    private static <T extends Component> T find(Container root, Class<T> type, String text) {
        for (Component child : root.getComponents()) {
            if (type.isInstance(child)) {
                String childText = null;
                if (child instanceof JButton) {
                    childText = ((JButton) child).getText();
                }
                if (text.equals(childText)) {
                    return type.cast(child);
                }
            }
            if (child instanceof Container) {
                T found = find((Container) child, type, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static final class TestExtension implements GuiExtension {
        @Override
        public String name() {
            return "test-extension";
        }

        @Override
        public String applicationTitle(String defaultTitle) {
            return "TestKit · " + defaultTitle;
        }

        @Override
        public Map<String, ToolPanelFactory> toolPanels() {
            Map<String, ToolPanelFactory> panels = new LinkedHashMap<String, ToolPanelFactory>();
            panels.put("TestGuiTool", new ToolPanelFactory() {
                @Override
                public RefreshableToolPanel create(ToolPanelContext context) {
                    return new TestToolPanel(context.getController(), context.getRefreshAll());
                }
            });
            return panels;
        }

        @Override
        public List<ResultAction> resultActions() {
            List<ResultAction> actions = new ArrayList<ResultAction>();
            actions.add(new ResultAction() {
                @Override
                public String label() {
                    return "加入我的列表";
                }

                @Override
                public void perform(DesktopMemShellGenerateResult result) {
                }
            });
            return actions;
        }
    }

    private static final class TestToolPanel extends AbstractToolPanel {
        private TestToolPanel(MemShellFormController controller, Runnable refreshAll) {
            super(controller, refreshAll);
        }
    }
}
