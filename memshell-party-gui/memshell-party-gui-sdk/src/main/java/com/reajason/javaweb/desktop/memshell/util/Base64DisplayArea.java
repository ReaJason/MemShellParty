package com.reajason.javaweb.desktop.memshell.util;

import javax.swing.JTextArea;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Insets;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;

/**
 * 结果区 Base64/源码展示文本区。
 *
 * <p>只读 JTextArea 对超长无空格单词做字符级断行会触发 macOS 26 + JDK<26 的字形缓存污染
 * （整窗拉丁字形随机丢失，实测可致 JVM 崩溃），所以本组件永不打开 setLineWrap。
 * Base64 的多行展示效果与原生换行一致——跟随组件宽度自动重排——但换行是这里
 * 按「宽度 ÷ 字符宽」算列数后插入的显式 \n（{@link #showBase64}），文本区自己从不参与断行。
 * CFR 源码/使用步骤有空格和真实换行，用 {@link #showText} 按词换行展示。
 */
public class Base64DisplayArea extends JTextArea {

    /** 拿到真实布局宽度前的展示列宽（MIME 惯例 76 列）。 */
    static final int DEFAULT_COLUMNS = 76;
    /** 列宽低于这个值重排没有意义（窗口过窄时保留上一次排版，横向滚动兜底）。 */
    private static final int MIN_COLUMNS = 8;

    /** 当前展示的原始单行串；null = 普通文本模式（源码/使用步骤/空）。 */
    private String rawSingleLine;
    private int columns = DEFAULT_COLUMNS;

    public Base64DisplayArea() {
        // 列数锚定首选宽度：超长内容不会撑大结果区最小宽度
        super(0, 40);
        setEditable(false);
        setLineWrap(false);
        setWrapStyleWord(false);
        setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                rewrapToWidth();
            }
        });
    }

    /**
     * 展示 Base64（或其他单行超长内容）：按当前组件宽度插显式换行，之后随宽度变化自动重排，
     * 视觉效果与原生 setLineWrap(true) 一致。
     */
    public void showBase64(String raw) {
        rawSingleLine = raw == null ? "" : raw;
        setLineWrap(false);
        setWrapStyleWord(false);
        applyWrapped();
    }

    /**
     * 首选宽度只由列数锚定，内容宽度不参与：展示换行是本组件插的显式 \n，行宽永远贴合视口。
     * 若放任内容宽度进来（JTextArea 取 max(内容, 列数)），换行后的行宽会把最小宽度顶大，
     * 视口判定不再跟随缩放，窄窗口就会冒出横向滚动条。
     */
    @Override
    public Dimension getPreferredSize() {
        Dimension d = super.getPreferredSize();
        d.width = getColumnWidth() * getColumns() + getInsets().left + getInsets().right;
        return d;
    }

    /**
     * 内容总是重排到视口宽度，视口永远可以按自己的宽度调整本组件（原生不换行 JTextArea
     * 只在视口比内容宽时才跟随）。
     */
    @Override
    public boolean getScrollableTracksViewportWidth() {
        return true;
    }

    /**
     * JTextComponent 的最小宽度也按内容算，换行后的行宽同样会把外层布局的最小宽度顶大
     * （窄窗口下右侧按钮被顶出窗口），钳到首选宽度。
     */
    @Override
    public Dimension getMinimumSize() {
        Dimension d = super.getMinimumSize();
        d.width = Math.min(d.width, getPreferredSize().width);
        return d;
    }

    /**
     * 展示普通文本（CFR 源码/使用步骤/清空）：退出 Base64 模式，按需打开按词换行。
     */
    public void showText(String text, boolean wrap) {
        rawSingleLine = null;
        setLineWrap(wrap);
        setWrapStyleWord(wrap);
        setText(text == null ? "" : text);
        setCaretPosition(0);
    }

    /**
     * 打包产物自适应：单行超长内容走 Base64 模式，自带换行的内容（脚本类产物）原样展示。
     */
    public void showAuto(String text) {
        if (text != null && text.indexOf('\n') < 0 && text.length() > DEFAULT_COLUMNS) {
            showBase64(text);
        } else {
            showText(text, false);
        }
    }

    /**
     * 宽度变化时按新列宽重排 Base64；列宽没变或普通文本模式不动。
     */
    private void rewrapToWidth() {
        if (rawSingleLine == null) {
            return;
        }
        int cols = currentColumns();
        if (cols >= MIN_COLUMNS && cols != columns) {
            columns = cols;
            applyWrapped();
        }
    }

    private void applyWrapped() {
        int caret = getCaretPosition();
        setText(wrapColumns(rawSingleLine, columns));
        // 重排保持滚动位置不跳变（与原生换行重排的观感一致）
        int max = Math.max(0, getText().length() - 1);
        setCaretPosition(Math.min(caret, max));
    }

    private int currentColumns() {
        FontMetrics fm = getFontMetrics(getFont());
        // 多字符采样拿小数精度：int charWidth 截断小数步进（Menlo 12pt ≈ 7.23px），
        // 列数按整数算会超出真实像素宽度，横滚条就冒出来了
        double charWidth = fm.stringWidth("0000000000") / 10.0;
        if (charWidth <= 0) {
            return columns;
        }
        Insets insets = getInsets();
        // 留 1px 余量防次像素渲染误差
        double usable = getWidth() - insets.left - insets.right - 1;
        return usable > 0 ? (int) (usable / charWidth) : columns;
    }

    /**
     * 按固定列宽给单行文本插显式换行；短于列宽或已含换行的内容原样返回。
     */
    static String wrapColumns(String text, int columns) {
        if (text == null || columns <= 0 || text.length() <= columns || text.indexOf('\n') >= 0) {
            return text;
        }
        StringBuilder wrapped = new StringBuilder(text.length() + text.length() / columns);
        for (int i = 0; i < text.length(); i += columns) {
            if (i > 0) {
                wrapped.append('\n');
            }
            wrapped.append(text, i, Math.min(i + columns, text.length()));
        }
        return wrapped.toString();
    }
}
