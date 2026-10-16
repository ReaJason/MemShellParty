package com.reajason.javaweb.desktop.memshell.ui;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JRootPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.GraphicsEnvironment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 探测马生成器的布局冒烟：与内存马 frame 对称 —— 内容可内嵌、快捷键可交给宿主窗口。
 * headless 环境跳过；不安装 FlatLaf。
 */
class ProbeGeneratorFrameLayoutTest {

    @Test
    void frameStructureIsAsExpected() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final ProbeGeneratorFrame[] frameHolder = new ProbeGeneratorFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frameHolder[0] = new ProbeGeneratorFrame();
            }
        });
        final ProbeGeneratorFrame frame = frameHolder[0];
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    JPanel content = frame.getRootPanel();
                    assertNotNull(content);
                    // 固定上下布局：探测马配置区在 NORTH，结果区占 CENTER
                    assertTrue(content.getLayout() instanceof BorderLayout);

                    JButton generateButton = frame.getGenerateButton();
                    assertNotNull(generateButton);
                    assertTrue(generateButton.isEnabled());
                    assertEquals("生成探测马", generateButton.getText());
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

    @Test
    void embeddedFrameInstallsShortcutOnHostRootPane() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final ProbeGeneratorFrame[] frameHolder = new ProbeGeneratorFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frameHolder[0] = new ProbeGeneratorFrame(false);
            }
        });
        final ProbeGeneratorFrame frame = frameHolder[0];
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    JRootPane hostRootPane = new JRootPane();
                    frame.installGenerateShortcut(hostRootPane);

                    assertNotNull(hostRootPane.getActionMap().get("generateShell"),
                            "Ctrl/⌘ + Enter 应当挂到宿主窗口上");
                    assertEquals(frame.getGenerateButton(), hostRootPane.getDefaultButton());
                    frame.installGenerateShortcut(null);
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
}
