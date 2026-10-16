package com.reajason.javaweb.desktop.memshell.util;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JRootPane;
import javax.swing.KeyStroke;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;

/**
 * 界面主操作的快捷键：Ctrl/⌘ + Enter 触发，主按钮同时接管裸 Enter（默认按钮）。
 * 三个界面（内存马 / 探测马生成器、CFR 反编译工具）共用这一套装/卸逻辑，
 * 宿主在页签之间切换时「先卸旧页、再装新页」，别的页里不会误触发。
 */
public final class FrameShortcutUtil {

    private FrameShortcutUtil() {
    }

    /**
     * 把 Ctrl/⌘ + Enter 与默认按钮挂到承载界面的 rootPane 上。
     *
     * @param rootPane      实际承载本界面的 rootPane（内嵌时是宿主窗口的）；为空则跳过
     * @param actionKey     动作名，同一窗口里各页面自己挑：装新的会顶掉 InputMap 里同一个击键，
     *                      ActionMap 里的旧动作由 {@link #uninstall} 按自己的名字摘
     * @param action        Ctrl/⌘ + Enter 触发的主操作
     * @param defaultButton 默认按钮（裸 Enter），为空则只挂快捷键
     */
    public static void install(JRootPane rootPane, String actionKey, final Runnable action, JButton defaultButton) {
        if (rootPane == null) {
            return;
        }
        // Java 8 Toolkit 只有 getMenuShortcutKeyMask()（Java 9+ 才有 MaskEx 变体）
        int menuMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMask();
        rootPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, menuMask), actionKey);
        rootPane.getActionMap().put(actionKey, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                action.run();
            }
        });
        rootPane.setDefaultButton(defaultButton);
    }

    /**
     * 撤销 {@link #install}：摘掉快捷键与动作，并清掉本界面自己的默认按钮。
     *
     * @param defaultButton 刚才装的默认按钮；只有它还占着默认按钮时才清，别的页的不碰
     */
    public static void uninstall(JRootPane rootPane, String actionKey, JButton defaultButton) {
        if (rootPane == null) {
            return;
        }
        // Java 8 Toolkit 只有 getMenuShortcutKeyMask()（Java 9+ 才有 MaskEx 变体）
        int menuMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMask();
        rootPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .remove(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, menuMask));
        rootPane.getActionMap().remove(actionKey);
        if (rootPane.getDefaultButton() == defaultButton) {
            rootPane.setDefaultButton(null);
        }
    }
}
