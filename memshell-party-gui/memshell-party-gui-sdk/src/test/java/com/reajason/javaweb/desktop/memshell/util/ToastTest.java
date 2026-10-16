package com.reajason.javaweb.desktop.memshell.util;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JFrame;
import javax.swing.JLayeredPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 浮层提示（toast）行为测试：headless 环境跳过；不安装 FlatLaf。
 * 锁定四条契约——浮层叠在内容之上且不参与布局、贴底居中、不吃鼠标事件、到点自动移除。
 */
class ToastTest {

    private static final int BOTTOM_MARGIN = 28;

    @Test
    void toastOverlaysContentAndClearsItself() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());
        final JFrame frame = frame();
        try {
            final JLayeredPane layered = frame.getRootPane().getLayeredPane();
            final int baseline = layered.getComponentCount();

            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    SwingUiUtil.showToast(frame.getContentPane(), "URL 不能为空：先填目标地址再探测");
                }
            });

            // 叠加在 layered pane 上（内容区之下不参与布局），贴底居中
            assertEquals(baseline + 1, layered.getComponentCount());
            Component toast = popupLayer(layered);
            assertNotNull(toast, "浮层应挂在 POPUP_LAYER 上");
            Rectangle bounds = toast.getBounds();
            assertTrue(bounds.width > 0 && bounds.height > 0);
            assertEquals((layered.getWidth() - bounds.width) / 2, bounds.x, 1);
            assertEquals(layered.getHeight() - bounds.height - BOTTOM_MARGIN, bounds.y, 1);
            // 不吃鼠标事件：浮层下方该点哪儿还点哪儿
            assertFalse(toast.contains(5, 5));

            // 窗口尺寸变化时跟随重新定位（浮层在窗口里，不参与窗口布局）
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    frame.setSize(800, 500);
                    frame.validate();
                }
            });
            Thread.sleep(300);   // 组件尺寸事件走队列，等 EDT 派发完再看
            final Rectangle[] moved = new Rectangle[1];
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    moved[0] = toast.getBounds();
                }
            });
            assertEquals((layered.getWidth() - moved[0].width) / 2, moved[0].x, 1);
            assertEquals(layered.getHeight() - moved[0].height - BOTTOM_MARGIN, moved[0].y, 1);

            // 到点自己消失，不留残影
            assertTrue(waitForRemoval(layered, baseline, 8000),
                    "浮层未在预期时间内自动移除（layered=" + layered.getComponentCount() + "）");
        } finally {
            dispose(frame);
        }
    }

    @Test
    void newToastReplacesPreviousAndLongTextWraps() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());
        final JFrame frame = frame();
        try {
            final JLayeredPane layered = frame.getRootPane().getLayeredPane();
            final int baseline = layered.getComponentCount();

            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    SwingUiUtil.showToast(frame.getContentPane(), "短提示");
                    SwingUiUtil.showToast(frame.getContentPane(),
                            "会话未就绪：密钥、利用链、容器三者缺一不可，先完成密钥爆破与利用链探测，再回来注入内存马");
                }
            });

            // 同一窗口只留一个：后一条顶掉前一条
            assertEquals(baseline + 1, layered.getComponentCount());
            final Component longToast = popupLayer(layered);
            assertNotNull(longToast);
            final int longHeight = longToast.getBounds().height;
            assertTrue(longToast.getBounds().width <= layered.getWidth(),
                    "折行后浮层不应超出窗口宽度");

            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    SwingUiUtil.showToast(frame.getContentPane(), "短提示");
                }
            });
            assertEquals(baseline + 1, layered.getComponentCount());
            assertTrue(popupLayer(layered).getBounds().height < longHeight,
                    "长文案折行后应比单行浮层更高");
        } finally {
            dispose(frame);
        }
    }

    /**
     * 浮层是 layered pane 上唯一的 POPUP_LAYER 组件（JLayeredPane 按层排序，浮层不在数组末尾）。
     */
    private static Component popupLayer(JLayeredPane layered) {
        for (Component component : layered.getComponents()) {
            if (layered.getLayer(component) == JLayeredPane.POPUP_LAYER) {
                return component;
            }
        }
        return null;
    }

    /**
     * 打包（pack）过的窗口即可布局：不必真正显示，浮层定位与尺寸就有效。
     */
    private static JFrame frame() throws Exception {
        final JFrame[] holder = new JFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                JFrame frame = new JFrame("toast-test");
                JPanel content = new JPanel();
                content.setPreferredSize(new Dimension(600, 400));
                frame.setContentPane(content);
                frame.pack();
                holder[0] = frame;
            }
        });
        return holder[0];
    }

    /**
     * 轮询等待浮层自动移除（Timer 在 EDT 上跑，测试线程睡等即可）。
     */
    private static boolean waitForRemoval(JLayeredPane layered, int baseline, long timeoutMillis)
            throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        while (System.currentTimeMillis() < deadline) {
            final int[] count = new int[1];
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    count[0] = layered.getComponentCount();
                }
            });
            if (count[0] == baseline) {
                return true;
            }
            Thread.sleep(100);
        }
        return false;
    }

    private static void dispose(final JFrame frame) throws Exception {
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frame.dispose();
            }
        });
    }
}
