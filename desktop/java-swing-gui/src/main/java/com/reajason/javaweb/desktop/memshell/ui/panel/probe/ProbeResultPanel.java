package com.reajason.javaweb.desktop.memshell.ui.panel.probe;

import com.reajason.javaweb.desktop.memshell.model.DesktopProbeShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.service.CfrDecompileService;
import com.reajason.javaweb.desktop.memshell.util.FileSaveUtil;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.probe.ProbeShellResult;
import net.miginfocom.swing.MigLayout;

import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Font;
import java.io.File;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

/**
 * 探测马结果面板：两页 Tab（生成结果 / 探测马类）。
 * 复制/保存作用于当前 Tab 与当前聚合条目；未生成时两 Tab 统一显示引导空态且按钮禁用。
 * 探测马页的「查看源码」按钮就地切换 Base64 ↔ CFR 反编译源码（结果按生成结果缓存）。
 */
public class ProbeResultPanel extends JPanel {
    private final JTabbedPane tabs = new JTabbedPane();
    private final ProbeBasicInfoPanel basicInfoPanel = new ProbeBasicInfoPanel();
    private final CfrDecompileService decompileService = new CfrDecompileService();
    private final JTextArea packResultArea = createTextArea();
    private final JComboBox<String> aggregateCombo = new JComboBox<String>();
    private final JLabel aggregateLabel = new JLabel("聚合条目");
    private final JLabel packHeaderLabel = new JLabel("未生成");
    private final JTextArea shellArea = createTextArea();
    private final JLabel shellNameLabel = new JLabel("");
    private final JButton sourceToggleBtn = new JButton("查看源码");
    private final JPanel packStack = new JPanel(new CardLayout());
    private final JPanel shellStack = new JPanel(new CardLayout());
    private final List<AbstractButton> resultButtons = new ArrayList<AbstractButton>();
    private StatusReporter statusReporter = new StatusReporter() {
        @Override
        public void report(String message, StatusReporter.Level level) {
        }
    };
    private DesktopProbeShellGenerateResult current;
    // 源码视图状态：showingSource 切换 Base64 ↔ 反编译源码；cachedSource 按 current 缓存，重新生成即失效
    private boolean showingSource;
    private String cachedSource;
    private long decompileGeneration;

    public ProbeResultPanel() {
        setLayout(new BorderLayout());
        tabs.addTab("生成结果", buildPackTab());
        tabs.addTab("探测马类", buildShellTab());
        add(tabs, BorderLayout.CENTER);
        setResultAvailable(false);
    }

    /**
     * 保存成功/空内容拦截等结果区消息上报给主窗口状态栏。
     */
    public void setStatusReporter(StatusReporter statusReporter) {
        this.statusReporter = statusReporter == null ? this.statusReporter : statusReporter;
    }

    /**
     * 未生成时的引导空态：说明操作路径。两 Tab 各持有一份实例（组件只能有一个父容器）。
     * 背景跟随 TextArea.background，暗色主题切换不翻车。
     */
    private JPanel buildEmptyHint() {
        JLabel title = new JLabel("尚未生成");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 15f));
        title.setHorizontalAlignment(SwingConstants.CENTER);
        final JLabel hint = new JLabel("<html><div style='text-align: center;'>配置上方表单后点击 <b>生成探测马</b><br>结果与探测马字节码将在此展示，均可复制或保存</div></html>");
        hint.setHorizontalAlignment(SwingConstants.CENTER);

        JPanel p = new JPanel(new MigLayout("insets 24, fill, wrap 1, align center", "[grow,fill]", "[]8[]")) {
            @Override
            public void updateUI() {
                super.updateUI();
                setBackground(UIManager.getColor("TextArea.background"));
                hint.setForeground(SwingUiUtil.mutedColor());
            }
        };
        p.add(title, "growx");
        p.add(hint, "growx");
        return p;
    }

    /**
     * 结果 Tab 统一外边距：上 4（上方已有 Tab 标签）、左右下 8。
     */
    private static final String TAB_OUTER_INSETS = "insets 4 8 8 8";

    private JPanel buildPackTab() {
        JPanel tab = new JPanel(new MigLayout(TAB_OUTER_INSETS + ", fill, wrap 1", "[grow,fill]", "[][grow]"));

        JPanel infoWrap = new JPanel(new MigLayout("insets 0, fillx", "[grow,fill]", "[]"));
        infoWrap.setBorder(BorderFactory.createTitledBorder("基本信息（值可点击复制）"));
        infoWrap.add(basicInfoPanel, "growx");
        tab.add(infoWrap, "growx");

        JPanel packWrap = new JPanel(new MigLayout("insets 4, fill, wrap 1", "[grow,fill]", "[][grow]"));
        packWrap.setBorder(BorderFactory.createTitledBorder("打包结果"));

        JPanel headerRow = new JPanel(new MigLayout("insets 0, fillx, gapx 6", "[][grow,fill][][][]", "[]"));
        headerRow.add(aggregateLabel);
        headerRow.add(aggregateCombo, "wmin 0, growx 40");
        headerRow.add(packHeaderLabel, "growx, pushx");
        JButton copyBtn = new JButton("复制");
        JButton saveBtn = new JButton("保存");
        headerRow.add(copyBtn);
        headerRow.add(saveBtn);
        resultButtons.add(copyBtn);
        resultButtons.add(saveBtn);
        aggregateCombo.setVisible(false);
        aggregateLabel.setVisible(false);
        packWrap.add(headerRow, "growx, wrap");

        packStack.add(buildEmptyHint(), "empty");
        packStack.add(new JScrollPane(packResultArea), "result");
        packWrap.add(packStack, "grow, push");
        tab.add(packWrap, "grow, push");

        copyBtn.addActionListener(e -> SwingUiUtil.copyWithFeedback(copyBtn, packResultArea.getText()));
        saveBtn.addActionListener(e -> savePackResult());

        aggregateCombo.addActionListener(e -> {
            if (current == null || !current.isMultiResult()) return;
            Object item = aggregateCombo.getSelectedItem();
            if (item != null) {
                String value = current.getPackResults().get(String.valueOf(item));
                if (value != null) {
                    packResultArea.setText(value);
                    packHeaderLabel.setText(current.getPackMethod() + " · " + item + " · " + value.length());
                }
            }
        });
        return tab;
    }

    private JPanel buildShellTab() {
        JPanel tab = new JPanel(new MigLayout("insets 4, fill, wrap 1", "[grow,fill]", "[grow]"));
        tab.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(4, 8, 8, 8),
                BorderFactory.createTitledBorder("探测马类字节(Base64)")));

        JPanel content = new JPanel(new MigLayout("insets 4, fill, wrap 1", "[grow,fill]", "[][grow]"));
        JPanel headerRow = new JPanel(new MigLayout("insets 0, fillx, gapx 6", "[][grow,fill][][][]", "[]"));
        headerRow.add(shellNameLabel);
        headerRow.add(new JLabel(""), "growx");
        JButton copyBtn = new JButton("复制");
        JButton saveBtn = new JButton("保存 .class");
        headerRow.add(sourceToggleBtn);
        headerRow.add(copyBtn);
        headerRow.add(saveBtn);
        resultButtons.add(sourceToggleBtn);
        resultButtons.add(copyBtn);
        resultButtons.add(saveBtn);
        content.add(headerRow, "growx, wrap");
        content.add(new JScrollPane(shellArea), "grow, push");

        shellStack.add(buildEmptyHint(), "empty");
        shellStack.add(content, "result");
        tab.add(shellStack, "grow, push");

        sourceToggleBtn.setToolTipText("在 Base64 与 CFR 反编译源码之间切换");
        sourceToggleBtn.addActionListener(e -> toggleSourceView());
        copyBtn.addActionListener(e -> SwingUiUtil.copyWithFeedback(copyBtn, shellArea.getText()));
        saveBtn.addActionListener(e -> saveClassBytes());
        return tab;
    }

    private JTextArea createTextArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }

    public void showResult(DesktopProbeShellGenerateResult result) {
        decompileGeneration++;
        this.current = result;
        // 结果变更：源码缓存与视图状态一并失效，回到 Base64 视图
        this.cachedSource = null;
        this.showingSource = false;
        sourceToggleBtn.setText("查看源码");

        ProbeShellResult r = result.getProbeShellResult();
        basicInfoPanel.setResult(result);
        shellNameLabel.setText(r.getShellClassName() + " (" + r.getShellSize() + " bytes)");
        shellArea.setText(r.getShellBytesBase64Str());
        shellArea.setCaretPosition(0);

        aggregateCombo.removeAllItems();
        if (result.isMultiResult()) {
            Map<String, String> entries = result.getPackResults();
            for (String key : entries.keySet()) {
                aggregateCombo.addItem(key);
            }
            aggregateCombo.setVisible(true);
            aggregateLabel.setVisible(true);
            Object first = aggregateCombo.getItemCount() > 0 ? aggregateCombo.getItemAt(0) : null;
            if (first != null) {
                aggregateCombo.setSelectedItem(first);
                String value = entries.get(String.valueOf(first));
                packResultArea.setText(value == null ? "" : value);
                packHeaderLabel.setText(result.getPackMethod() + " · " + first + " · " + (value == null ? 0 : value.length()));
            }
        } else {
            aggregateCombo.setVisible(false);
            aggregateLabel.setVisible(false);
            String text = result.getActivePackResult();
            packResultArea.setText(text);
            packHeaderLabel.setText(result.getPackMethod() + " · " + text.length());
        }
        packResultArea.setCaretPosition(0);
        setResultAvailable(true);
        // 生成后聚焦结果，避免停留在探测马旧页
        tabs.setSelectedIndex(0);
    }

    /**
     * 未生成 ↔ 有结果：两 Tab 统一切换空态/结果叠加层，并禁用/恢复复制保存按钮。
     */
    private void setResultAvailable(boolean available) {
        for (AbstractButton button : resultButtons) {
            button.setEnabled(available);
        }
        String card = available ? "result" : "empty";
        ((CardLayout) packStack.getLayout()).show(packStack, card);
        ((CardLayout) shellStack.getLayout()).show(shellStack, card);
    }

    public void clear() {
        decompileGeneration++;
        current = null;
        cachedSource = null;
        showingSource = false;
        sourceToggleBtn.setText("查看源码");
        basicInfoPanel.clear();
        packResultArea.setText("");
        shellArea.setText("");
        shellNameLabel.setText("");
        packHeaderLabel.setText("未生成");
        aggregateCombo.setVisible(false);
        aggregateLabel.setVisible(false);
        setResultAvailable(false);
    }

    /**
     * Base64 ↔ CFR 反编译源码就地切换。反编译在后台线程跑，期间显示占位文本；
     * 期间用户可能重新生成：令牌失配则丢弃过期结果，不污染新结果的缓存与视图。
     */
    private void toggleSourceView() {
        if (current == null) return;
        if (!showingSource) {
            showingSource = true;
            sourceToggleBtn.setText("查看 Base64");
            if (cachedSource != null) {
                shellArea.setText(cachedSource);
                shellArea.setCaretPosition(0);
                return;
            }
            final ProbeShellResult r = current.getProbeShellResult();
            final String className = r.getShellClassName();
            final String base64 = r.getShellBytesBase64Str();
            if (base64 == null || base64.trim().isEmpty()) {
                shellArea.setText("// 无可反编译的类字节码");
                return;
            }
            shellArea.setText("// 正在使用 CFR 反编译 " + className + " ...");
            final Object generationToken = current;
            final long requestGeneration = ++decompileGeneration;
            new SwingWorker<String, Void>() {
                @Override
                protected String doInBackground() {
                    byte[] bytes = Base64.getDecoder().decode(base64.trim());
                    return decompileService.decompile(className, bytes);
                }

                @Override
                protected void done() {
                    if (generationToken != current || requestGeneration != decompileGeneration) return;
                    String source;
                    boolean decompileSucceeded = false;
                    try {
                        source = get();
                        decompileSucceeded = true;
                    } catch (Exception ex) {
                        Throwable t = ex instanceof ExecutionException && ex.getCause() != null ? ex.getCause() : ex;
                        String message = t.getMessage() == null ? String.valueOf(t) : t.getMessage();
                        source = "// 反编译失败: " + message;
                        statusReporter.report("反编译失败: " + message, StatusReporter.Level.ERROR);
                    }
                    // Error text is a transient view state, never a successful source cache.
                    if (decompileSucceeded) {
                        cachedSource = source;
                    }
                    if (showingSource) {
                        shellArea.setText(source);
                        shellArea.setCaretPosition(0);
                    }
                }
            }.execute();
        } else {
            decompileGeneration++;
            showingSource = false;
            sourceToggleBtn.setText("查看源码");
            shellArea.setText(current.getProbeShellResult().getShellBytesBase64Str());
            shellArea.setCaretPosition(0);
        }
    }

    private void savePackResult() {
        if (current == null) return;
        try {
            if (current.isMultiResult()) {
                String payload = packResultArea.getText();
                if (interceptEmpty(payload)) return;
                Object item = aggregateCombo.getSelectedItem();
                String entry = item == null ? "entry" : String.valueOf(item);
                reportSaved(FileSaveUtil.saveText(this, current.getPackMethod() + "-" + entry + ".txt", payload));
            } else {
                String payload = packResultArea.getText();
                if (interceptEmpty(payload)) return;
                reportSaved(FileSaveUtil.saveText(this, current.getPackMethod() + ".txt", payload));
            }
        } catch (Exception ex) {
            SwingUiUtil.showError(this, "保存失败: " + ex.getMessage());
        }
    }

    private void saveClassBytes() {
        if (current == null) return;
        try {
            ProbeShellResult r = current.getProbeShellResult();
            String payload = r.getShellBytesBase64Str();
            if (interceptEmpty(payload)) return;
            reportSaved(FileSaveUtil.saveBase64AsBytes(this, FileSaveUtil.simpleFileName(r.getShellClassName(), ".class"), payload, "class"));
        } catch (Exception ex) {
            SwingUiUtil.showError(this, "保存失败: " + ex.getMessage());
        }
    }

    /**
     * 空内容拦截：不弹保存框，状态栏明示原因。
     */
    private boolean interceptEmpty(String payload) {
        if (payload == null || payload.trim().isEmpty()) {
            statusReporter.report("内容为空，未保存", StatusReporter.Level.INFO);
            return true;
        }
        return false;
    }

    private void reportSaved(File file) {
        if (file != null) {
            statusReporter.report("已保存：" + file.getAbsolutePath(), StatusReporter.Level.SUCCESS);
        }
    }
}
