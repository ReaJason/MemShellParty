package com.reajason.javaweb.desktop.memshell.util;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.awt.GraphicsConfiguration;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 小屏适配：承载组件的窗口超出屏幕时，{@link SwingUiUtil#fitWindowToScreen(java.awt.Component)}
 * 把它收进屏幕边界；本来就在屏幕内的窗口不动。
 */
class SwingUiUtilWindowFitTest {

    @Test
    void oversizedWindowIsFittedIntoItsScreen() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());
        final AtomicReference<JFrame> frameHolder = new AtomicReference<JFrame>();
        final Rectangle[] screenHolder = new Rectangle[1];

        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                JFrame frame = new JFrame();
                frame.setContentPane(new JPanel());
                GraphicsConfiguration config = GraphicsEnvironment.getLocalGraphicsEnvironment()
                        .getDefaultScreenDevice().getDefaultConfiguration();
                Rectangle screen = config.getBounds();
                screenHolder[0] = screen;
                frame.setBounds(screen.x - 120, screen.y - 80, screen.width + 260, screen.height + 200);
                frame.setVisible(true);
                // 窗口管理器可能先一步约束了窗口，这里只要求调用后一定在屏幕内
                SwingUiUtil.fitWindowToScreen(frame.getContentPane());
                Rectangle fitted = frame.getBounds();
                // 已经收进屏幕：同一轮里再调一次不应再动
                assertTrue(!SwingUiUtil.fitWindowToScreen(frame.getContentPane()));
                assertEquals(fitted, frame.getBounds());
                frameHolder.set(frame);
            }
        });

        try {
            Rectangle screen = screenHolder[0];
            Rectangle bounds = frameHolder.get().getBounds();
            assertTrue(bounds.width <= screen.width, "窗口宽度应收进屏幕");
            assertTrue(bounds.height <= screen.height, "窗口高度应收进屏幕");
            assertTrue(bounds.x >= screen.x, "窗口左边缘不应出界");
            assertTrue(bounds.y >= screen.y, "窗口上边缘不应出界");
            assertTrue(bounds.x + bounds.width <= screen.x + screen.width, "窗口右边缘不应出界");
            assertTrue(bounds.y + bounds.height <= screen.y + screen.height, "窗口下边缘不应出界");
        } finally {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    frameHolder.get().dispose();
                }
            });
        }
    }
}
