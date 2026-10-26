package com.reajason.javaweb.desktop.memshell.ui.panel.probe;

import com.reajason.javaweb.desktop.memshell.model.DesktopProbeShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.service.CfrDecompileService;
import com.reajason.javaweb.desktop.memshell.util.Base64DisplayArea;
import com.reajason.javaweb.desktop.memshell.util.FileSaveUtil;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.probe.ProbeShellResult;
import net.miginfocom.swing.MigLayout;

import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
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
import java.util.concurrent.ExecutionException;

/**
 * 探测马结果面板：两页 Tab（生成结果 / 探测马类）。
 * 复制/保存作用于当前 Tab；未生成时两 Tab 统一显示引导空态且按钮禁用。
 * 探测马页的「查看源码」按钮就地切换 Base64 ↔ CFR 反编译源码（结果按生成结果缓存）。
 */
public class ProbeResultPanel extends JPanel {
    private final JTabbedPane tabs = new JTabbedPane();
    private final ProbeBasicInfoPanel basicInfoPanel = new ProbeBasicInfoPanel();
    private final CfrDecompileService decompileService = new CfrDecompileService();
    private final Base64DisplayArea packResultArea = new Base64DisplayArea();
    private final JLabel packHeaderLabel = new JLabel("未生成");
    private final Base64DisplayArea shellArea = new Base64DisplayArea();
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

        JPanel headerRow = new JPanel(new MigLayout("insets 0, fillx, gapx 6", "[grow,fill][][]", "[]"));
        headerRow.add(packHeaderLabel, "growx, pushx");
        JButton copyBtn = SwingUiUtil.actionButton("复制");
        JButton saveBtn = new JButton("保存");
        headerRow.add(copyBtn);
        headerRow.add(saveBtn);
        resultButtons.add(copyBtn);
        resultButtons.add(saveBtn);
        packWrap.add(headerRow, "growx, wrap");

        packStack.add(buildEmptyHint(), "empty");
        packStack.add(new JScrollPane(packResultArea), "result");
        packWrap.add(packStack, "grow, push");
        tab.add(packWrap, "grow, push");

        // 展示区是宽度跟随的显式换行形态，复制用原始单行串
        copyBtn.addActionListener(e -> SwingUiUtil.copyWithFeedback(copyBtn,
                current == null || current.getPackResult() == null ? "" : current.getPackResult()));
        saveBtn.addActionListener(e -> savePackResult());
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
        JButton copyBtn = SwingUiUtil.actionButton("复制");
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
        copyBtn.addActionListener(e -> copyShellPayload(copyBtn));
        saveBtn.addActionListener(e -> saveClassBytes());
        return tab;
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
        shellArea.showBase64(r.getShellBytesBase64Str());

        String text = result.getPackResult() == null ? "" : result.getPackResult();
        packResultArea.showAuto(text);
        packHeaderLabel.setText(result.getPackMethod() + " · " + text.length());
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
        packResultArea.showText("", false);
        shellArea.showText("", false);
        shellNameLabel.setText("");
        packHeaderLabel.setText("未生成");
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
            // 源码有空格与显式换行，按词换行展示；回到 Base64 视图时恢复宽度跟随的显式换行
            if (cachedSource != null) {
                shellArea.showText(cachedSource, true);
                return;
            }
            final ProbeShellResult r = current.getProbeShellResult();
            final String className = r.getShellClassName();
            final String base64 = r.getShellBytesBase64Str();
            if (base64 == null || base64.trim().isEmpty()) {
                shellArea.showText("// 无可反编译的类字节码", true);
                return;
            }
            shellArea.showText("// 正在使用 CFR 反编译 " + className + " ...", true);
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
                        shellArea.showText(source, true);
                    }
                }
            }.execute();
        } else {
            decompileGeneration++;
            showingSource = false;
            sourceToggleBtn.setText("查看源码");
            shellArea.showBase64(current.getProbeShellResult().getShellBytesBase64Str());
        }
    }

    /**
     * 复制探测马页：源码视图复制所见的源码；Base64 视图复制原始单行 Base64
     * （展示区的显式换行只是宽度适配形态，见 {@link Base64DisplayArea}）。
     */
    private void copyShellPayload(JButton copyBtn) {
        if (current == null) {
            return;
        }
        String text = showingSource ? shellArea.getText() : current.getProbeShellResult().getShellBytesBase64Str();
        SwingUiUtil.copyWithFeedback(copyBtn, text == null ? "" : text);
    }

    private void savePackResult() {
        if (current == null) return;
        try {
            // 展示区是宽度跟随的显式换行形态，保存用原始单行串
            String payload = current.getPackResult();
            if (interceptEmpty(payload)) return;
            reportSaved(FileSaveUtil.saveText(this, current.getPackMethod() + ".txt", payload));
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
