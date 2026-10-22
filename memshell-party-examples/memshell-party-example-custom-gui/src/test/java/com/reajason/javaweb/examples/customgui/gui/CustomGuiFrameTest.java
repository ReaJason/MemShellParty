package com.reajason.javaweb.examples.customgui.gui;

import com.reajason.javaweb.desktop.memshell.MemShellGui;
import com.reajason.javaweb.desktop.memshell.ui.MemShellGeneratorFrame;
import com.reajason.javaweb.desktop.memshell.util.AppVersion;
import com.reajason.javaweb.examples.customgui.shelltool.GodzillaSessionShellToolProvider;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.GraphicsEnvironment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 带窗口的冒烟测试：下游自己排的外壳（{@link CustomGuiFrame}）装上 SDK 的生成器后，
 * 自己的工具在工具下拉框里、有自己的专用面板、"加入我的 Shell 列表"按钮在结果区，
 * 状态行接得住生成器上报的消息。需要显示环境（headless 跳过，不安装 FlatLaf）。
 */
class CustomGuiFrameTest {

    @Test
    void customShellIsBrandedAndWiredForTheCustomTool() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());
        final String tool = GodzillaSessionShellToolProvider.NAME;

        final CustomGuiFrame[] holder = new CustomGuiFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                holder[0] = new CustomGuiFrame(
                        MemShellGui.resolveExtensions(new GodzillaSessionGuiExtension()));
            }
        });
        final CustomGuiFrame frame = holder[0];
        final MemShellGeneratorFrame generator = frame.memShellFrame();
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    // 品牌：窗口标题是宿主自己的
                    assertEquals("自定义工具生成器 - MemShellParty v" + AppVersion.get(), frame.getTitle());

                    // 自己的工具：工具下拉框里有它，参数面板是自己的专用面板
                    assertNotNull(findComboContaining(frame.getContentPane(), tool),
                            tool + " 应当出现在工具下拉框里");
                    assertInstanceOf(GodzillaSessionToolPanel.class, generator.getToolPanelRegistry().get(tool));

                    // 结果区多了自己的动作按钮（还没有结果，所以是禁用的）
                    JButton action = findButton(frame.getContentPane(), "加入我的 Shell 列表");
                    assertNotNull(action, "结果区应当有扩展提供的动作按钮");
                    assertFalse(action.isEnabled());

                    // 切到自己的工具：专用面板跟着刷新（不抛异常即说明面板与状态对得上）
                    generator.getController().setShellTool(tool);
                    generator.refreshAll();
                    assertNotNull(generator.getToolPanelRegistry().get(tool));
                }
            });

            // 状态出口：宿主的状态行接住生成器上报的消息（清掉必填项制造校验失败）
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    generator.getController().setServerVersion("");
                    generator.triggerGenerate();
                    assertTrue(frame.statusLabel().getText().startsWith("校验失败"),
                            frame.statusLabel().getText());
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

    private static JButton findButton(Container root, String text) {
        for (Component child : root.getComponents()) {
            if (child instanceof JButton && text.equals(((JButton) child).getText())) {
                return (JButton) child;
            }
            if (child instanceof Container) {
                JButton found = findButton((Container) child, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static JComboBox<?> findComboContaining(Container root, String item) {
        for (Component child : root.getComponents()) {
            if (child instanceof JComboBox) {
                JComboBox<?> combo = (JComboBox<?>) child;
                for (int i = 0; i < combo.getItemCount(); i++) {
                    if (item.equals(combo.getItemAt(i))) {
                        return combo;
                    }
                }
            }
            if (child instanceof Container) {
                JComboBox<?> found = findComboContaining((Container) child, item);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
