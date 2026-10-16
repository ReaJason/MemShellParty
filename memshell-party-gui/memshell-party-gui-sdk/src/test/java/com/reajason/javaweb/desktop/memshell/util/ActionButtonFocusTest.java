package com.reajason.javaweb.desktop.memshell.util;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.Dimension;
import java.awt.GraphicsEnvironment;
import java.awt.GridLayout;
import java.awt.KeyboardFocusManager;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * 动作按钮的焦点契约测试：headless 环境跳过；不安装 FlatLaf。
 * 锁定两条——{@link SwingUiUtil#actionButton(String)} 不参与焦点遍历；
 * 不参与遍历并不削弱它作为宿主窗口默认按钮响应「裸 Enter」的能力（宿主程序依赖这条）。
 */
class ActionButtonFocusTest {

    @Test
    void actionButtonStaysOutOfTheFocusTraversalOrder() {
        JButton created = SwingUiUtil.actionButton("探测");
        assertFalse(created.isFocusable(), "actionButton 造出来的按钮不应参与焦点遍历");

        JButton existing = new JButton("探测");
        SwingUiUtil.markActionButton(existing);
        assertFalse(existing.isFocusable(), "markActionButton 应把已有按钮也标成不参与焦点遍历");
    }

    /**
     * 裸 Enter 走的是 rootPane 的 WHEN_IN_FOCUSED_WINDOW 绑定（默认按钮），与焦点遍历无关：
     * 焦点在配置输入框里敲 Enter 照样触发，不因按钮退出遍历序而失效。
     */
    @Test
    void actionButtonAsDefaultButtonStillAnswersPlainEnter() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final JFrame[] frameHolder = new JFrame[1];
        final JButton[] buttonHolder = new JButton[1];
        final JTextField[] fieldHolder = new JTextField[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                JTextField field = new JTextField(16);
                JButton button = SwingUiUtil.actionButton("生成内存马");
                JPanel content = new JPanel(new GridLayout(2, 1, 0, 6));
                content.add(field);
                content.add(button);

                JFrame frame = new JFrame("action-button-focus-test");
                frame.setContentPane(content);
                frame.setSize(new Dimension(420, 160));
                frame.getRootPane().setDefaultButton(button);
                frame.setLocationByPlatform(true);
                frame.setVisible(true);

                frameHolder[0] = frame;
                buttonHolder[0] = button;
                fieldHolder[0] = field;
            }
        });
        final JFrame frame = frameHolder[0];
        try {
            // 窗口没被桌面聚焦时，窗口级快捷键根本收不到事件：这种环境跳过（不是回归）
            Assumptions.assumeTrue(waitForActiveWindow(frame),
                    "窗口未被系统聚焦，无法派发窗口级 Enter");

            final AtomicInteger fired = new AtomicInteger();
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    buttonHolder[0].addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            fired.incrementAndGet();
                        }
                    });
                    fieldHolder[0].requestFocusInWindow();
                }
            });
            Thread.sleep(300);

            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    KeyboardFocusManager.getCurrentKeyboardFocusManager().dispatchKeyEvent(new KeyEvent(frame,
                            KeyEvent.KEY_PRESSED, System.currentTimeMillis(), 0, KeyEvent.VK_ENTER, '\n'));
                }
            });
            Thread.sleep(500);   // DefaultAction → doClick 的 68ms 定时器 → 动作

            assertEquals(1, fired.get(), "非焦点遍历的默认按钮应当照旧被裸 Enter 触发一次");
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
     * 等窗口拿到系统焦点（macOS 上 setVisible 到 isActive 之间有几拍）；超时视为环境不具备条件。
     */
    private static boolean waitForActiveWindow(JFrame frame) throws Exception {
        long deadline = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < deadline) {
            final boolean[] active = new boolean[1];
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    active[0] = frame.isActive();
                }
            });
            if (active[0]) {
                return true;
            }
            Thread.sleep(100);
        }
        return false;
    }
}
