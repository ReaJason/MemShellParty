package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.extension.GuiExtension;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JRootPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.GraphicsEnvironment;
import java.util.Collections;

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
}
