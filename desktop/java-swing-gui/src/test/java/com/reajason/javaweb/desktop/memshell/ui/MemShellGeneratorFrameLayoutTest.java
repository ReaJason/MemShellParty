package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.GraphicsEnvironment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
                    JComponent content = frame.getMainContentPanel();
                    assertNotNull(content);
                    // 固定上下布局：配置区（含打包条）在 NORTH，结果区占 CENTER，无分隔条
                    assertTrue(content.getLayout() instanceof BorderLayout);

                    JButton generateButton = frame.getGenerateButton();
                    assertNotNull(generateButton);
                    assertTrue(generateButton.isEnabled());
                    assertEquals("生成内存马", generateButton.getText());
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
