package com.reajason.javaweb.desktop.memshell.app;

import com.reajason.javaweb.desktop.memshell.util.AppVersion;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.GraphicsEnvironment;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 官方外壳的结构冒烟：三个页签在、作者与关于入口在、状态栏按页各自接住页面上报的状态
 * （切页不串）、快捷键随当前页转移。需要显示环境（headless 跳过，不安装 FlatLaf）。
 */
class MemShellDesktopFrameTest {

    @Test
    void shellComposesAllPagesWithSharedStatusBar() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final MemShellDesktopFrame[] holder = new MemShellDesktopFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                holder[0] = new MemShellDesktopFrame(Collections.emptyList());
            }
        });
        final MemShellDesktopFrame frame = holder[0];
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    assertEquals("MemShellParty v" + AppVersion.get(), frame.getTitle());

                    // 外壳带来三个页签，页面本体是 SDK 的三个界面
                    assertEquals(3, frame.pageTabs().getTabCount());
                    assertEquals("内存马", frame.pageTabs().getTitleAt(0));
                    assertEquals("探测马", frame.pageTabs().getTitleAt(1));
                    assertEquals("反编译", frame.pageTabs().getTitleAt(2));
                    assertTrue(frame.pageTabs().getComponentAt(0) == frame.memShellFrame().getRootPanel());
                    assertTrue(frame.pageTabs().getComponentAt(1) == frame.probeFrame().getRootPanel());
                    assertTrue(frame.pageTabs().getComponentAt(2) == frame.decompileFrame().getRootPanel());

                    // 状态栏：作者与关于入口（图标来自本模块资源 icons/about.svg，加载不到才降级成文字）
                    assertNotNull(find(frame.getContentPane(), JLabel.class, "By ReaJason"));
                    JButton aboutButton = findAboutButton(frame.getContentPane());
                    assertNotNull(aboutButton);
                    assertNotNull(aboutButton.getIcon(), "关于按钮应当加载到 icons/about.svg");
                    assertEquals("就绪", frame.statusLabel().getText());
                }
            });

            // 状态出口：内存马页校验失败 -> 状态栏出文案；别的页不受影响，切过去看到的是它自己那份
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    frame.memShellFrame().getController().setServerVersion("");
                    frame.memShellFrame().triggerGenerate();
                    assertTrue(frame.statusLabel().getText().startsWith("校验失败"), frame.statusLabel().getText());

                    frame.pageTabs().setSelectedIndex(1);
                    assertEquals("就绪", frame.statusLabel().getText());

                    frame.pageTabs().setSelectedIndex(0);
                    assertTrue(frame.statusLabel().getText().startsWith("校验失败"), frame.statusLabel().getText());
                }
            });

            // 反编译页：输入为空时点一下，状态栏出它自己的提示
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    frame.pageTabs().setSelectedIndex(2);
                    assertEquals("就绪", frame.statusLabel().getText());

                    frame.decompileFrame().triggerDecompile();
                    assertTrue(frame.statusLabel().getText().startsWith("请粘贴"), frame.statusLabel().getText());

                    // 快捷键与默认按钮跟着当前页：反编译页上是它自己的按钮
                    assertEquals(frame.decompileFrame().getDecompileButton(), frame.getRootPane().getDefaultButton());
                    assertNotNull(frame.getRootPane().getActionMap().get("decompileClass"));

                    frame.pageTabs().setSelectedIndex(0);
                    assertTrue(frame.memShellFrame().getGenerateButton() == frame.getRootPane().getDefaultButton(),
                            "切回内存马页，默认按钮应当换回生成按钮");
                    assertNull(frame.getRootPane().getActionMap().get("decompileClass"));
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
     * 深度优先找文案匹配的组件（测试内部用，不去动外壳的内部结构）。
     */
    private static <T extends Component> T find(Container root, Class<T> type, String text) {
        for (Component child : root.getComponents()) {
            if (type.isInstance(child)) {
                String childText = null;
                if (child instanceof JLabel) {
                    childText = ((JLabel) child).getText();
                } else if (child instanceof JButton) {
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

    /**
     * 关于按钮没有文案（SVG 图标 + tooltip），按 tooltip 找。
     */
    private static JButton findAboutButton(Container root) {
        for (Component child : root.getComponents()) {
            if (child instanceof JButton && "关于 MemShellParty".equals(((JButton) child).getToolTipText())) {
                return (JButton) child;
            }
            if (child instanceof Container) {
                JButton found = findAboutButton((Container) child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
