package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.util.FileSaveUtil;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.WindowConstants;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Window;
import java.io.File;

/**
 * 反编译源码查看弹窗：只读展示 CFR 产出的 Java 源码，可复制或保存为 .java。
 * 字节码工具的「查看输入源码」用它；输出源码直接内嵌在页面里切换，不弹窗。
 */
public final class SourceViewDialog extends JDialog {

    private final JTextArea sourceArea = createSourceArea();

    public SourceViewDialog(Window owner, String title, final String className, String source) {
        super(owner, title, ModalityType.MODELESS);
        setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE);

        sourceArea.setText(source == null ? "" : source);
        sourceArea.setCaretPosition(0);

        JButton copyButton = SwingUiUtil.actionButton("复制源码");
        copyButton.addActionListener(e -> SwingUiUtil.copyWithFeedback(copyButton, sourceArea.getText()));
        JButton saveButton = new JButton("保存 .java");
        saveButton.addActionListener(e -> saveSource(className));

        setLayout(new MigLayout("insets 8, fill, wrap 1, gapy 6", "[grow,fill]", "[grow,fill][]"));
        JScrollPane scroll = new JScrollPane(sourceArea);
        scroll.setBorder(BorderFactory.createTitledBorder(
                className == null || className.trim().isEmpty() ? "源码" : className + ".java"));
        add(scroll, "grow, push");

        JPanel buttons = new JPanel(new MigLayout("insets 0, fillx, gapx 6", "push[][]", "[]"));
        buttons.add(copyButton);
        buttons.add(saveButton);
        add(buttons, "growx");

        setSize(new Dimension(900, 680));
        setLocationRelativeTo(owner);
    }

    private void saveSource(String className) {
        String source = sourceArea.getText();
        if (source == null || source.trim().isEmpty()) {
            SwingUiUtil.showError(this, "没有可保存的源码");
            return;
        }
        try {
            File file = FileSaveUtil.saveText(this, FileSaveUtil.simpleFileName(className, ".java"), source, "java");
            if (file != null) {
                SwingUiUtil.showToast(this, "已保存：" + file.getAbsolutePath());
            }
        } catch (Exception ex) {
            SwingUiUtil.showError(this, "保存失败: " + ex.getMessage());
        }
    }

    /**
     * 源码区不换行：保留原始缩进，长了横向滚动。
     */
    private static JTextArea createSourceArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }
}
