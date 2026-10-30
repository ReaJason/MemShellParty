package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.extension.GuiExtension;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.ui.panel.MainConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.PackageConfigPanel;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import com.reajason.javaweb.memshell.config.ObfuscationScope;
import com.reajason.javaweb.packer.PackerCategory;
import com.reajason.javaweb.packer.Packers;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JRootPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.GraphicsEnvironment;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 布局冒烟测试：headless 环境跳过；不安装 FlatLaf。
 */
class MemShellGeneratorFrameLayoutTest {

    @Test
    void frameStructureIsAsExpected() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final MemShellGeneratorFrame[] frameHolder = new MemShellGeneratorFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frameHolder[0] = new MemShellGeneratorFrame();
            }
        });
        final MemShellGeneratorFrame frame = frameHolder[0];
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    JPanel content = frame.getRootPanel();
                    assertNotNull(content);
                    // 固定上下布局：配置区（含打包条）在 NORTH，结果区占 CENTER，无分隔条
                    assertTrue(content.getLayout() instanceof BorderLayout);

                    JButton generateButton = frame.getGenerateButton();
                    assertNotNull(generateButton);
                    assertTrue(generateButton.isEnabled());
                    assertEquals("生成内存马", generateButton.getText());
                    // 生成期间自己会被禁用：不参与焦点遍历，否则焦点会甩给下一个配置输入框并被 FlatLaf 全选
                    assertFalse(generateButton.isFocusable(), "生成按钮不应参与焦点遍历");
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
     * 内嵌用法：standalone = false 时窗口属性不设，快捷键与默认按钮挂到宿主给的 rootPane 上。
     */
    @Test
    void embeddedFrameInstallsShortcutOnHostRootPane() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final MemShellGeneratorFrame[] frameHolder = new MemShellGeneratorFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frameHolder[0] = new MemShellGeneratorFrame(Collections.<GuiExtension>emptyList(), false);
            }
        });
        final MemShellGeneratorFrame frame = frameHolder[0];
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    JRootPane hostRootPane = new JRootPane();
                    frame.installGenerateShortcut(hostRootPane);

                    assertNotNull(hostRootPane.getActionMap().get("generateShell"),
                            "Ctrl/⌘ + Enter 应当挂到宿主窗口上");
                    assertEquals(frame.getGenerateButton(), hostRootPane.getDefaultButton());
                    // 传入空 rootPane 不炸（宿主窗口还没就绪时的容错）
                    frame.installGenerateShortcut(null);

                    // 离开生成页时卸掉，宿主窗口里别的页敲 Enter 不会再触发生成
                    frame.uninstallGenerateShortcut(hostRootPane);
                    assertNull(hostRootPane.getActionMap().get("generateShell"));
                    assertNull(hostRootPane.getDefaultButton());
                    frame.uninstallGenerateShortcut(null);
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

    @Test
    void controllerReconcilesWithoutUi() {
        // 无 UI 依赖的冒烟：controller 可独立初始化并完成联动
        MemShellFormController controller = new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
        assertTrue(controller.validate().isValid());
    }

    /**
     * 打包条在 frame 上而不是 configPanel 里：首屏与结构变更后都必须被刷新，
     * 否则分类/变体下拉是空模型（探测马没这个问题，因为它在 buildRootPanel 里调了自己的 refreshAll）。
     */
    @Test
    void packerCombosArePopulatedOnFirstShowAndFollowServerFilter() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final MemShellGeneratorFrame[] frameHolder = new MemShellGeneratorFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frameHolder[0] = new MemShellGeneratorFrame();
            }
        });
        final MemShellGeneratorFrame frame = frameHolder[0];
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    PackageConfigPanel packPanel = findComponent(frame.getRootPanel(), PackageConfigPanel.class);
                    assertNotNull(packPanel, "打包配置条应当已装配");

                    List<JComboBox<?>> combos = findCombos(packPanel);
                    assertEquals(2, combos.size(), "打包条应当有分类与变体两个下拉");
                    for (JComboBox<?> combo : combos) {
                        assertTrue(combo.getItemCount() > 0, "首屏打包下拉不应为空");
                    }

                    JComboBox<?> categoryCombo = null;
                    for (JComboBox<?> combo : combos) {
                        if (combo.getItemAt(0) instanceof PackerCategory) {
                            categoryCombo = combo;
                        }
                    }
                    assertNotNull(categoryCombo, "应当找到打包分类下拉");
                    // 默认 Tomcat/Listener：Agent* 与 xxl* 都不适用
                    assertFalse(hasCategory(categoryCombo, "Agent"), "非 Agent 类型不应出现 Agent 分类");
                    assertFalse(hasCategory(categoryCombo, Packers.XxlJob), "非 XXLJOB 服务端不应出现 XxlJob 分类");

                    // 切到 Agent 类型：只剩下 Agent* 分类（结构变更要级联刷新打包条）
                    frame.getController().setShellType("AgentFilterChain");
                    frame.refreshAll();
                    assertTrue(hasCategory(categoryCombo, "Agent"), "Agent 类型下应当只剩 Agent 分类");
                    assertFalse(hasCategory(categoryCombo, Packers.XxlJob), "Agent 类型下不应出现 XxlJob 分类");

                    // 切到 XXLJOB：Agent* 被排除，XxlJob 分类回来
                    frame.getController().setServer("XXLJOB");
                    frame.refreshAll();
                    assertFalse(hasCategory(categoryCombo, "Agent"), "XXLJOB 下不应再出现 Agent 分类");
                    assertTrue(hasCategory(categoryCombo, Packers.XxlJob), "XXLJOB 下应当出现 XxlJob 分类");
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
     * 无打包模式：不装配打包条，生成结果固定 DefaultBase64（注入宿主拿到 MemShellResult 直接用）。
     */
    @Test
    void withoutPackerGeneratesBase64Directly() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final java.util.concurrent.atomic.AtomicReference<com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult> captured =
                new java.util.concurrent.atomic.AtomicReference<com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult>();
        final GuiExtension capture = new GuiExtension() {
            @Override
            public String name() {
                return "capture-result";
            }

            @Override
            public void onResultGenerated(com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult result) {
                captured.set(result);
            }
        };

        final MemShellGeneratorFrame[] frameHolder = new MemShellGeneratorFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frameHolder[0] = new MemShellGeneratorFrame(
                        Collections.singletonList(capture), false, false);
            }
        });
        final MemShellGeneratorFrame frame = frameHolder[0];
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    assertNull(findComponent(frame.getRootPanel(), PackageConfigPanel.class),
                            "无打包模式不应装配打包配置条");
                    JButton generate = frame.getGenerateButton();
                    assertNotNull(generate);
                    assertEquals("生成内存马", generate.getText());
                }
            });

            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    frame.triggerGenerate();
                }
            });

            long deadline = System.currentTimeMillis() + 15000;
            while (captured.get() == null && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }
            assertNotNull(captured.get(), "生成超时");
            assertEquals("Base64", captured.get().getPackMethod());
            assertEquals(captured.get().getMemShellResult().getInjectorBytesBase64Str(),
                    captured.get().getPackResult(), "无打包模式应直接输出注入器 Base64");
        } finally {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    frame.dispose();
                }
            });
        }
    }

    @Test
    void obfuscationScopeSelectorFollowsCheckboxAndUpdatesController() throws Exception {
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                MemShellFormController controller = new MemShellFormController(
                        new ConfigCatalogService(), new MemShellValidator());
                MainConfigPanel panel = new MainConfigPanel(controller, new Runnable() {
                    @Override
                    public void run() {
                    }
                });
                panel.refreshFromController();

                JComboBox<?> scopeCombo = null;
                for (JComboBox<?> combo : findCombos(panel)) {
                    if (combo.getItemCount() > 0 && combo.getItemAt(0) instanceof ObfuscationScope) {
                        scopeCombo = combo;
                        break;
                    }
                }
                assertNotNull(scopeCombo, "内存马表单应当有混淆范围下拉");
                assertEquals(ObfuscationScope.ALL, scopeCombo.getSelectedItem());
                assertFalse(scopeCombo.isEnabled(), "未启用混淆时范围应禁用");

                controller.setObfuscation(true);
                panel.refreshFromController();
                assertTrue(scopeCombo.isEnabled());
                scopeCombo.setSelectedItem(ObfuscationScope.INJECTOR);
                assertEquals(ObfuscationScope.INJECTOR, controller.getState().getObfuscationScope());

                controller.setObfuscation(false);
                panel.refreshFromController();
                assertFalse(scopeCombo.isEnabled());
            }
        });
    }

    private static boolean hasCategory(JComboBox<?> combo, String prefix) {
        for (int i = 0; i < combo.getItemCount(); i++) {
            Object item = combo.getItemAt(i);
            if (item instanceof PackerCategory && ((PackerCategory) item).getName().startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static <T extends Component> T findComponent(Container root, Class<T> type) {
        for (Component child : root.getComponents()) {
            if (type.isInstance(child)) {
                return type.cast(child);
            }
            if (child instanceof Container) {
                T found = findComponent((Container) child, type);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static List<JComboBox<?>> findCombos(Container root) {
        List<JComboBox<?>> out = new ArrayList<JComboBox<?>>();
        for (Component child : root.getComponents()) {
            if (child instanceof JComboBox) {
                out.add((JComboBox<?>) child);
            }
            if (child instanceof Container) {
                out.addAll(findCombos((Container) child));
            }
        }
        return out;
    }
}
