package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.service.CfrDecompileService;
import com.reajason.javaweb.desktop.memshell.util.FileSaveUtil;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.memshell.MemShellResult;
import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.Window;
import java.io.File;
import java.util.Base64;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

/**
 * CFR 反编译源码查看器：modeless 弹窗，「内存马 / 注入器」两个 Tab 并列展示源码，
 * 可与主窗口同屏对照字节码。打开即后台并行反编译两个类，结果按生成结果缓存；
 * 重新生成时由结果面板调用 {@link #syncResult} 原地刷新，清空时调用 {@link #clearAndHide}。
 */
public class DecompileDialog extends JDialog {
    private final CfrDecompileService decompileService = new CfrDecompileService();
    private final JTabbedPane tabs = new JTabbedPane();
    private final JTextArea shellArea = createSourceArea();
    private final JTextArea injectorArea = createSourceArea();
    private final JLabel shellNameLabel = new JLabel("");
    private final JLabel injectorNameLabel = new JLabel("");
    private final Consumer<String> statusReporter;
    // 反编译结果缓存：结果不变时重复打开/切 Tab 不重复跑 CFR，applyResult 时失效
    private MemShellResult result;
    private String shellSource;
    private String injectorSource;

    public DecompileDialog(Window owner, Consumer<String> statusReporter) {
        super(owner, "CFR 反编译源码", ModalityType.MODELESS);
        this.statusReporter = statusReporter;
        setDefaultCloseOperation(HIDE_ON_CLOSE);
        tabs.addTab("内存马", buildTab(shellArea, shellNameLabel, true));
        tabs.addTab("注入器", buildTab(injectorArea, injectorNameLabel, false));
        JPanel content = new JPanel(new BorderLayout());
        content.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        content.add(tabs, BorderLayout.CENTER);
        setContentPane(content);
        setSize(800, 600);
    }

    /**
     * 用户点击「反编译」：加载结果并弹出（已打开则前置并选中对应 Tab）。
     */
    public void open(MemShellResult result, boolean shell) {
        if (result == null) return;
        if (result != this.result) {
            applyResult(result);
        }
        tabs.setSelectedIndex(shell ? 0 : 1);
        refresh();
        if (!isVisible()) {
            setLocationRelativeTo(getOwner());
            setVisible(true);
        } else {
            toFront();
        }
    }

    /**
     * 重新生成后同步内容：弹窗开着则原地刷新（重新反编译），关着则仅替换结果待下次打开。
     */
    public void syncResult(MemShellResult result) {
        if (result == null || result == this.result) return;
        applyResult(result);
        if (isVisible()) {
            refresh();
        }
    }

    /**
     * 结果面板清空时关闭弹窗并丢弃缓存。
     */
    public void clearAndHide() {
        applyResult(null);
        setVisible(false);
    }

    private void applyResult(MemShellResult r) {
        this.result = r;
        shellSource = null;
        injectorSource = null;
        shellArea.setText("");
        injectorArea.setText("");
        shellNameLabel.setText(r == null ? "" : r.getShellClassName() + " (" + r.getShellSize() + " bytes)");
        injectorNameLabel.setText(r == null ? "" : r.getInjectorClassName() + " (" + r.getInjectorSize() + " bytes)");
    }

    private void refresh() {
        startDecompile(true);
        startDecompile(false);
    }

    /**
     * 后台线程跑 CFR，期间显示占位文本；完成后写缓存并回填对应 Tab。
     * 反编译期间用户可能重新生成：令牌失配则丢弃过期结果，不污染新结果的缓存与视图。
     */
    private void startDecompile(final boolean shell) {
        final JTextArea area = shell ? shellArea : injectorArea;
        String cached = shell ? shellSource : injectorSource;
        if (cached != null) {
            area.setText(cached);
            area.setCaretPosition(0);
            return;
        }
        final String className = shell ? result.getShellClassName() : result.getInjectorClassName();
        final String base64 = shell ? result.getShellBytesBase64Str() : result.getInjectorBytesBase64Str();
        if (base64 == null || base64.trim().isEmpty()) {
            area.setText("// 无可反编译的类字节码");
            return;
        }
        area.setText("// 正在使用 CFR 反编译 " + className + " ...");
        final Object generationToken = result;
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                byte[] bytes = Base64.getDecoder().decode(base64.trim());
                return decompileService.decompile(className, bytes);
            }

            @Override
            protected void done() {
                if (generationToken != result) return;
                try {
                    String source = get();
                    if (shell) {
                        shellSource = source;
                    } else {
                        injectorSource = source;
                    }
                    area.setText(source);
                    area.setCaretPosition(0);
                } catch (Exception ex) {
                    String message = rootCauseMessage(ex);
                    area.setText("// 反编译失败: " + message);
                    statusReporter.accept("反编译失败: " + message);
                }
            }
        }.execute();
    }

    private JPanel buildTab(final JTextArea area, JLabel nameLabel, final boolean shell) {
        JPanel tab = new JPanel(new MigLayout("insets 4, fill, wrap 1", "[grow,fill]", "[][grow]"));
        JPanel headerRow = new JPanel(new MigLayout("insets 0, fillx, gapx 6", "[][grow,fill][][]", "[]"));
        headerRow.add(nameLabel);
        headerRow.add(new JLabel(""), "growx");
        JButton copyBtn = new JButton("复制");
        JButton saveBtn = new JButton("保存 .java");
        headerRow.add(copyBtn);
        headerRow.add(saveBtn);
        tab.add(headerRow, "growx, wrap");
        tab.add(new JScrollPane(area), "grow, push");

        copyBtn.addActionListener(e -> SwingUiUtil.copyWithFeedback(copyBtn, area.getText()));
        saveBtn.addActionListener(e -> saveSource(shell));
        return tab;
    }

    private void saveSource(boolean shell) {
        if (result == null) return;
        try {
            String source = (shell ? shellArea : injectorArea).getText();
            // 占位/错误文本以 // 开头（CFR 正常产物以 /* 开头），视为不可保存
            if (source == null || source.trim().isEmpty() || source.trim().startsWith("//")) {
                statusReporter.accept("内容为空，未保存");
                return;
            }
            String className = shell ? result.getShellClassName() : result.getInjectorClassName();
            File file = FileSaveUtil.saveText(this, FileSaveUtil.simpleFileName(className, ".java"), source, "java");
            if (file != null) {
                statusReporter.accept("已保存：" + file.getAbsolutePath());
            }
        } catch (Exception ex) {
            SwingUiUtil.showError(this, "保存失败: " + ex.getMessage());
        }
    }

    private static JTextArea createSourceArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        // 源码视图不换行，保留原始缩进，横向滚动
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }

    private static String rootCauseMessage(Throwable ex) {
        Throwable t = ex instanceof ExecutionException && ex.getCause() != null ? ex.getCause() : ex;
        String message = t.getMessage();
        return message == null ? String.valueOf(t) : message;
    }
}
