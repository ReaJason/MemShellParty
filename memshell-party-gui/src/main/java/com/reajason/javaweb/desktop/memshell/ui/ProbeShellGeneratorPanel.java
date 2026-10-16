package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.controller.ProbeShellFormController;
import com.reajason.javaweb.desktop.memshell.model.DesktopProbeShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.ProbeShellFormState;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.ProbeGenerationService;
import com.reajason.javaweb.desktop.memshell.ui.panel.probe.ProbeMainConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.probe.ProbePackageConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.probe.ProbeResultPanel;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.desktop.memshell.validation.ProbeShellValidator;
import net.miginfocom.swing.MigLayout;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.SwingWorker;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.util.Map;

/**
 * 探测马生成页：上配置（探测马配置 → 打包条）/ 下结果（结果 Tab），结构对齐内存马页。
 * 自成一体持有 controller/生成服务，状态栏消息通过 statusReporter 上报主窗口。
 */
public class ProbeShellGeneratorPanel extends JPanel {
    private final ProbeShellFormController controller;
    private final ProbeGenerationService generationService;
    private final ProbeMainConfigPanel mainConfigPanel;
    private final ProbePackageConfigPanel packageConfigPanel;
    private final ProbeResultPanel resultPanel;
    private final JButton generateButton = new JButton("生成探测马");
    private final StatusReporter statusReporter;

    public ProbeShellGeneratorPanel(StatusReporter statusReporter) {
        this.statusReporter = statusReporter;
        this.controller = new ProbeShellFormController(new ConfigCatalogService(), new ProbeShellValidator());
        this.generationService = new ProbeGenerationService();
        this.resultPanel = new ProbeResultPanel();
        this.mainConfigPanel = new ProbeMainConfigPanel(controller, this::refreshAll);
        this.packageConfigPanel = new ProbePackageConfigPanel(controller);

        setLayout(new BorderLayout(0, 4));
        add(buildTop(), BorderLayout.NORTH);
        add(resultPanel, BorderLayout.CENTER);
        resultPanel.setStatusReporter(statusReporter);

        generateButton.setFont(generateButton.getFont().deriveFont(Font.BOLD, 14f));
        generateButton.setToolTipText("生成探测马 (Ctrl/Cmd + Enter)"); // 拉丁段不被 CJK 夹中间，原因见 ResultPanel
        generateButton.addActionListener(e -> triggerGenerate());
        fixGenerateButtonWidth();
        resultPanel.clear();
        refreshAll();
    }

    private JComponent buildTop() {
        JPanel packBarInner = new JPanel(new MigLayout("insets 0 4 0 4, fillx, gapx 8", "[grow,fill][]", "[]"));
        packBarInner.add(packageConfigPanel, "growx, pushx");
        packBarInner.add(generateButton, "aligny center, gapright 4");

        JPanel top = new JPanel(new MigLayout("insets 4, fillx, wrap 1", "[grow,fill]", "[]4[]"));
        top.add(mainConfigPanel, "growx");
        top.add(packBarInner, "growx");
        return top;
    }

    public JButton getGenerateButton() {
        return generateButton;
    }

    /**
     * 生成入口：供按钮与主窗口 Ctrl/⌘ + Enter 快捷键共用（探测马 Tab 选中时由主窗口转发）。
     */
    public void triggerGenerate() {
        if (!generateButton.isEnabled()) {
            return;
        }
        // 快照必须在 EDT 侧拷贝，校验与生成共用同一份：
        // 后台线程读 live state 会与 EDT 上的表单写入竞争（撕裂快照 + TOCTOU）
        final ProbeShellFormState snapshot = controller.getState().copy();
        SwingUiUtil.clearFieldErrors(this);
        ProbeShellValidator.Result validation = controller.validate(snapshot);
        if (!validation.isValid()) {
            applyValidationErrors(validation.getFieldErrors());
            statusReporter.report("校验失败：" + joinMessages(validation), StatusReporter.Level.ERROR);
            focusFirstError(validation);
            return;
        }
        generateButton.setEnabled(false);
        generateButton.setText("生成中…");
        statusReporter.report("生成中…", StatusReporter.Level.BUSY);
        final long startTime = System.currentTimeMillis();

        SwingWorker<DesktopProbeShellGenerateResult, Void> worker = new SwingWorker<DesktopProbeShellGenerateResult, Void>() {
            @Override
            protected DesktopProbeShellGenerateResult doInBackground() {
                return generationService.generate(snapshot);
            }

            @Override
            protected void done() {
                generateButton.setEnabled(true);
                generateButton.setText("生成探测马");
                long elapsed = System.currentTimeMillis() - startTime;
                try {
                    DesktopProbeShellGenerateResult result = get();
                    resultPanel.showResult(result);
                    statusReporter.report("生成成功 · 耗时 " + elapsed + " ms", StatusReporter.Level.SUCCESS);
                } catch (Exception ex) {
                    statusReporter.report("生成失败", StatusReporter.Level.ERROR);
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    SwingUiUtil.showError(ProbeShellGeneratorPanel.this, "生成失败: " + cause.getMessage());
                }
            }
        };
        worker.execute();
    }

    /**
     * inline 校验：全部错误一次标完（红描边 + 行内红字），状态栏汇总，焦点跳首个错误字段。
     */
    private void applyValidationErrors(Map<String, String> errors) {
        mainConfigPanel.applyValidationErrors(errors);
        packageConfigPanel.applyValidationErrors(errors);
    }

    private void focusFirstError(ProbeShellValidator.Result validation) {
        for (String field : validation.getFieldErrors().keySet()) {
            JComponent target = mainConfigPanel.validationFocusTarget(field);
            if (target == null) {
                target = packageConfigPanel.validationFocusTarget(field);
            }
            if (target != null) {
                target.requestFocusInWindow();
                return;
            }
        }
    }

    private static String joinMessages(ProbeShellValidator.Result validation) {
        StringBuilder sb = new StringBuilder();
        for (String message : validation.getFieldErrors().values()) {
            if (sb.length() > 0) {
                sb.append("；");
            }
            sb.append(message);
        }
        return sb.toString();
    }

    /**
     * 生成中文案切换（生成探测马 ↔ 生成中…）会改变按钮首选宽度，
     * 打包条里按钮收缩会让左侧打包配置区宽度跟着闪烁；按两种文案最大宽度固定按钮尺寸。
     */
    private void fixGenerateButtonWidth() {
        String original = generateButton.getText();
        int width = 0;
        for (String text : new String[]{"生成探测马", "生成中…"}) {
            generateButton.setText(text);
            width = Math.max(width, generateButton.getPreferredSize().width);
        }
        generateButton.setText(original);
        Dimension size = generateButton.getPreferredSize();
        size.width = width;
        generateButton.setPreferredSize(size);
        generateButton.setMinimumSize(size);
    }

    public void refreshAll() {
        // 结构性变更后旧的错误标记已失真，统一清掉（字段内直接编辑由 bindText 单独清）
        SwingUiUtil.clearFieldErrors(this);
        mainConfigPanel.refreshFromController();
        packageConfigPanel.refreshFromController();
        revalidate();
        repaint();
    }
}
