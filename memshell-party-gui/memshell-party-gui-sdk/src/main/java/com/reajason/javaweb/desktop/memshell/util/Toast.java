package com.reajason.javaweb.desktop.memshell.util;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JLayeredPane;
import javax.swing.JRootPane;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import java.awt.AlphaComposite;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.RenderingHints;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * 浮层提示（toast）：贴在窗口 layered pane 底部的圆角浮层，淡入 → 停留 → 淡出后自动移除。
 *
 * <p>三个「不」：不抢焦点、不参与布局（浮层是叠加组件，不改任何组件尺寸，消失即无痕）、
 * 不挡鼠标（{@link Layer#contains} 恒 false，浮层下方该点哪儿还点哪儿）。比行内错误 label
 * （显隐改行高、整块表单跟着重排）和模态弹窗（多一个窗口还阻塞）都省渲染，
 * 是「用户操作当场被拒」这类提示的最优形态。
 *
 * <p>同一窗口只留一个：新提示顶掉旧提示。文案按字符宽度折行，浮层始终贴底居中；
 * 窗口尺寸变化时跟随重新定位。外部入口是 {@link SwingUiUtil#showToast}。
 */
final class Toast {

    private static final int FADE_IN_MILLIS = 140;
    private static final int HOLD_MILLIS = 2400;
    private static final int FADE_OUT_MILLIS = 320;
    private static final int TICK_MILLIS = 25;

    private static final int PADDING_X = 16;
    private static final int PADDING_Y = 10;
    private static final int ARC = 14;
    private static final int BOTTOM_MARGIN = 28;
    private static final int SIDE_MARGIN = 24;

    /**
     * 主题无关的深色药丸：亮/暗主题下都保持同样的可读性，语义交给文案。
     */
    private static final Color BACKGROUND = new Color(0x33, 0x37, 0x3D, 235);
    private static final Color FOREGROUND = new Color(0xF5, 0xF6, 0xF7);

    /**
     * root pane 上的当前浮层（client property）：同一窗口只留一个。
     */
    private static final String TOAST_KEY = "memshell.toast";

    private Toast() {
    }

    /**
     * 在 owner 所在窗口弹出提示；非 EDT 调用自动收口到 EDT（sdk 回调都在后台线程）。
     */
    static void show(final Component owner, final String message) {
        if (owner == null || message == null || message.trim().isEmpty()) {
            return;
        }
        final JRootPane root = SwingUtilities.getRootPane(owner);
        if (root == null) {
            return;
        }
        Runnable install = new Runnable() {
            @Override
            public void run() {
                install(root, message);
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            install.run();
        } else {
            SwingUtilities.invokeLater(install);
        }
    }

    private static void install(JRootPane root, String message) {
        Object previous = root.getClientProperty(TOAST_KEY);
        if (previous instanceof Layer) {
            ((Layer) previous).dismiss();
        }
        Layer toast = new Layer(message);
        root.putClientProperty(TOAST_KEY, toast);
        root.getLayeredPane().add(toast, JLayeredPane.POPUP_LAYER);
        toast.start();
    }

    /**
     * 浮层本体：自绘圆角药丸 + 居中文本（一个组件搞定，省掉 JPanel/JLabel 两层容器）。
     */
    private static final class Layer extends JComponent implements ActionListener {

        private final String message;
        private final List<String> lines = new ArrayList<String>();
        private final Timer timer = new Timer(TICK_MILLIS, this);
        private final ComponentAdapter resizeListener = new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                place();
            }
        };

        private int elapsed;
        private float alpha;

        Layer(String message) {
            this.message = message;
            setFont(labelFont());
            setOpaque(false);
            setFocusable(false);
        }

        void start() {
            Container parent = getParent();
            if (parent != null) {
                parent.addComponentListener(resizeListener);
            }
            place();
            timer.start();
        }

        void dismiss() {
            timer.stop();
            Container parent = getParent();
            if (parent != null) {
                parent.removeComponentListener(resizeListener);
            }
            JRootPane root = SwingUtilities.getRootPane(this);
            if (root != null && root.getClientProperty(TOAST_KEY) == this) {
                root.putClientProperty(TOAST_KEY, null);
            }
            if (parent != null) {
                Rectangle bounds = getBounds();
                parent.remove(this);
                parent.repaint(bounds.x, bounds.y, bounds.width, bounds.height);
            }
        }

        /**
         * 折行 + 贴底居中：窗口一改尺寸就重算（浮层在窗口里，不占窗口布局）。
         */
        private void place() {
            Container parent = getParent();
            if (parent == null) {
                return;
            }
            FontMetrics metrics = getFontMetrics(getFont());
            lines.clear();
            lines.addAll(wrap(message, metrics, Math.max(120, parent.getWidth() - 2 * (SIDE_MARGIN + PADDING_X))));
            int textWidth = 0;
            for (String line : lines) {
                textWidth = Math.max(textWidth, metrics.stringWidth(line));
            }
            int width = textWidth + 2 * PADDING_X;
            int height = lines.size() * metrics.getHeight() + 2 * PADDING_Y;
            setBounds(Math.max(0, (parent.getWidth() - width) / 2),
                    Math.max(0, parent.getHeight() - height - BOTTOM_MARGIN), width, height);
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            elapsed += TICK_MILLIS;
            int fadeOutStart = FADE_IN_MILLIS + HOLD_MILLIS;
            if (elapsed < FADE_IN_MILLIS) {
                alpha = elapsed / (float) FADE_IN_MILLIS;
            } else if (elapsed < fadeOutStart) {
                alpha = 1f;
            } else {
                alpha = 1f - (elapsed - fadeOutStart) / (float) FADE_OUT_MILLIS;
            }
            if (alpha <= 0f) {
                dismiss();
                return;
            }
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, alpha));
            g2.setColor(BACKGROUND);
            g2.fillRoundRect(0, 0, getWidth(), getHeight(), ARC, ARC);
            g2.setColor(FOREGROUND);
            FontMetrics metrics = g2.getFontMetrics(getFont());
            int y = PADDING_Y + metrics.getAscent();
            for (String line : lines) {
                g2.drawString(line, (getWidth() - metrics.stringWidth(line)) / 2, y);
                y += metrics.getHeight();
            }
            g2.dispose();
        }

        /**
         * 浮层不吃鼠标事件：toast 只是提示，不是可交互组件。
         */
        @Override
        public boolean contains(int x, int y) {
            return false;
        }

        /**
         * 按字符宽度折行：CJK 没有词边界，逐字累加即可（与生成器的文案排版一致）。
         */
        private static List<String> wrap(String text, FontMetrics metrics, int maxWidth) {
            List<String> wrapped = new ArrayList<String>();
            StringBuilder line = new StringBuilder();
            int width = 0;
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                int charWidth = metrics.charWidth(c);
                if (width + charWidth > maxWidth && line.length() > 0) {
                    wrapped.add(line.toString());
                    line.setLength(0);
                    width = 0;
                }
                line.append(c);
                width += charWidth;
            }
            wrapped.add(line.toString());
            return wrapped;
        }

        private static Font labelFont() {
            Font font = UIManager.getFont("Label.font");
            return font != null ? font : new JLabel().getFont();
        }
    }
}
