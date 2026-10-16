package com.reajason.javaweb.desktop.memshell.ui.panel;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.InfoRow;
import com.reajason.javaweb.desktop.memshell.service.ResultInfoService;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import net.miginfocom.swing.MigLayout;

import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Cursor;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

/**
 * 生成结果基本信息：摘要行（label: value 对），值可点击复制。
 * 行集由 {@link ResultInfoService} 提供（对齐 web basic-info.tsx），本类只负责渲染。
 */
public class BasicInfoPanel extends JPanel {

    /**
     * 展示用截断长度：Base64 这类长值只显示开头，复制取的仍是完整值。
     */
    private static final int DISPLAY_MAX = 64;

    private final JPanel content = new JPanel(new MigLayout("insets 0, fillx, gapx 10, gapy 2, wrap 2", "[right]6[grow,fill]", "[]"));

    public BasicInfoPanel() {
        setLayout(new MigLayout("insets 0, fillx", "[grow,fill]", "[]"));
        add(content, "growx, wrap");
    }

    public void clear() {
        content.removeAll();
        content.revalidate();
        content.repaint();
    }

    public void setResult(DesktopMemShellGenerateResult result) {
        content.removeAll();
        for (InfoRow row : ResultInfoService.describe(result)) {
            row(row.getName(), row.getValue(), row.getCopyValue());
        }
        content.revalidate();
        content.repaint();
    }

    /**
     * displayValue 用于展示（过长截断），copyValue 用于点击复制（如类名行展示带大小、复制只取类名）。
     */
    private void row(String key, String displayValue, String copyValue) {
        String text = displayValue == null ? "" : displayValue;
        final String copyText = copyValue == null ? "" : copyValue;
        content.add(new JLabel(key + ":"));
        final JLabel valueLabel = new JLabel(truncate(text));
        valueLabel.setToolTipText(text + "（点击复制）");
        valueLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        valueLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                SwingUiUtil.copyLabelWithFeedback(valueLabel, copyText);
            }
        });
        content.add(valueLabel, "growx, wrap");
    }

    private static String truncate(String value) {
        if (value.length() <= DISPLAY_MAX) {
            return value;
        }
        return value.substring(0, DISPLAY_MAX) + "...";
    }
}
