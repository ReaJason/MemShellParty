package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.controller.ProbeShellFormController;
import com.reajason.javaweb.desktop.memshell.model.ProbeShellFormState;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.ProbeGenerationService;
import com.reajason.javaweb.desktop.memshell.ui.panel.probe.ProbeMainConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.probe.ProbePackageConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.probe.ProbeResultPanel;
import com.reajason.javaweb.desktop.memshell.util.AppVersion;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import com.reajason.javaweb.desktop.memshell.validation.ProbeShellValidator;
import net.miginfocom.swing.MigLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.util.Map;

/**
 * 探测马生成器：上配置（探测马配置 → 打包条）/ 下结果（结果 Tab），结构对齐
 * {@link MemShellGeneratorFrame}（内存马）—— SDK 暴露的另一个界面入口；
 * 窗口骨架与生成流程在 {@link MemShellFrame}。
 *
 * <p>用法与内存马 frame 相同：独立窗口直接 {@code new ProbeGeneratorFrame().setVisible(true)}；
 * 嵌进宿主布局则 {@code standalone = false} 构造后取 {@link #getRootPanel()}，
 * 再用 {@link #setStatusReporter} 接状态出口、{@link #installGenerateShortcut} 挂快捷键。
 */
public class ProbeGeneratorFrame extends MemShellFrame {

    private final ProbeShellFormController controller;
    private final ProbeGenerationService generationService;
    private final ProbeMainConfigPanel mainConfigPanel;
    private final ProbePackageConfigPanel packageConfigPanel;
    private final ProbeResultPanel resultPanel;

    public ProbeGeneratorFrame() {
        this(true);
    }

    /**
     * @param standalone {@code true} = 独立窗口：自带 EXIT_ON_CLOSE、按屏幕自适应尺寸、
     *                   默认按钮与 Ctrl/⌘ + Enter 挂在自己的 rootPane 上；
     *                   {@code false} = 界面归宿主：不设窗口属性（本窗口不会显示），
     *                   宿主取 {@link #getRootPanel()} 自己布局。
     */
    public ProbeGeneratorFrame(boolean standalone) {
        super("MemShellParty v" + AppVersion.get(), "生成探测马");
        this.controller = new ProbeShellFormController(new ConfigCatalogService(), new ProbeShellValidator());
        this.generationService = new ProbeGenerationService();
        this.resultPanel = new ProbeResultPanel();
        this.mainConfigPanel = new ProbeMainConfigPanel(controller, this::refreshAll);
        this.packageConfigPanel = new ProbePackageConfigPanel(controller);

        installContent(standalone);
    }

    @Override
    protected JPanel buildRootPanel() {
        JPanel packBarInner = new JPanel(new MigLayout("insets 0 4 0 4, fillx, gapx 8", "[grow,fill][]", "[]"));
        packBarInner.add(packageConfigPanel, "growx, pushx");
        packBarInner.add(prepareGenerateButton("生成探测马 (Ctrl/Cmd + Enter)"), "aligny center, gapright 4");

        JPanel top = new JPanel(new MigLayout("insets 4, fillx, wrap 1", "[grow,fill]", "[]4[]"));
        top.add(mainConfigPanel, "growx");
        top.add(packBarInner, "growx");

        JPanel content = new JPanel(new BorderLayout(0, 4));
        content.add(top, BorderLayout.NORTH);
        content.add(resultPanel, BorderLayout.CENTER);

        resultPanel.clear();
        refreshAll();
        return content;
    }

    @Override
    protected void applyStatusReporter(StatusReporter reporter) {
        resultPanel.setStatusReporter(reporter);
    }

    /**
     * 生成入口：按钮、快捷键、宿主程序都走它。
     */
    @Override
    public void triggerGenerate() {
        if (!getGenerateButton().isEnabled()) {
            return;
        }
        // 快照必须在 EDT 侧拷贝，校验与生成共用同一份：
        // 后台线程读 live state 会与 EDT 上的表单写入竞争（撕裂快照 + TOCTOU）
        final ProbeShellFormState snapshot = controller.getState().copy();
        clearFieldErrors();
        ProbeShellValidator.Result validation = controller.validate(snapshot);
        if (!validation.isValid()) {
            reportValidationFailure(validation.getFieldErrors());
            return;
        }
        runGenerate(() -> generationService.generate(snapshot), resultPanel::showResult);
    }

    @Override
    protected void applyValidationErrors(Map<String, String> errors) {
        mainConfigPanel.applyValidationErrors(errors);
        packageConfigPanel.applyValidationErrors(errors);
    }

    @Override
    protected JComponent validationFocusTarget(String field) {
        JComponent target = mainConfigPanel.validationFocusTarget(field);
        if (target == null) {
            target = packageConfigPanel.validationFocusTarget(field);
        }
        return target;
    }

    public void refreshAll() {
        // 结构性变更后旧的错误标记已失真，统一清掉（字段内直接编辑由 bindText 单独清）
        clearFieldErrors();
        mainConfigPanel.refreshFromController();
        packageConfigPanel.refreshFromController();
        revalidate();
        repaint();
    }
}
