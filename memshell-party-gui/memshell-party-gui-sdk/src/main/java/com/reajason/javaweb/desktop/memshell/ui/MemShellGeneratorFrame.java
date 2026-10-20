package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.MemShellGui;
import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.extension.GuiExtension;
import com.reajason.javaweb.desktop.memshell.extension.ResultAction;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.GenerationService;
import com.reajason.javaweb.desktop.memshell.ui.panel.MemShellConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.PackageConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.ResultPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.RefreshableToolPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.ToolPanelRegistry;
import com.reajason.javaweb.desktop.memshell.util.AppVersion;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.PackerRegistry;
import net.miginfocom.swing.MigLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * 内存马生成器：上配置（{@link MemShellConfigPanel}：核心配置 → 内存马功能 + 打包条）/
 * 下结果（结果 Tab）。自成一体持有生成服务，是 SDK 暴露的两个界面入口之一（另一个是
 * {@link ProbeGeneratorFrame}）—— 页签布局、状态栏、关于弹窗这些外壳由宿主自己实现；
 * 窗口骨架与生成流程在 {@link MemShellFrame}。
 *
 * <p>两种用法：
 * <ul>
 *   <li><b>独立窗口</b>：{@code new MemShellGeneratorFrame(extensions).setVisible(true)}，
 *       自带窗口属性（EXIT_ON_CLOSE、按屏幕自适应尺寸、Ctrl/⌘ + Enter 快捷键）；</li>
 *   <li><b>嵌进宿主的布局</b>：{@code standalone = false} 构造后取 {@link #getRootPanel()}
 *       放进自己的页签/面板，再用 {@link #setStatusReporter} 接自己的状态出口、
 *       {@link #installGenerateShortcut} 把快捷键与默认按钮挂到承载窗口上。</li>
 * </ul>
 *
 * <p>{@code withPacker = false} 时省略打包条：生成结果固定等价 {@code DefaultBase64}，
 * 供拿到 {@link MemShellResult} 后直接注入的宿主使用；默认仍展示打包选择。
 *
 * <p>只要配置表单、不要生成按钮与结果区的宿主（如综合利用工具的注入面板），
 * 直接嵌 {@link MemShellConfigPanel} 即可，不必挂整个 frame。
 *
 * <p>一般通过 {@link MemShellGui#createMemShellFrame(GuiExtension...)} 构造（带 SPI 扩展发现）。
 */
public class MemShellGeneratorFrame extends MemShellFrame {

    private final MemShellConfigPanel configPanel;
    private final GenerationService generationService;
    /** 无打包模式（内嵌注入场景）下为 null，不构建也不展示打包配置。 */
    private final PackageConfigPanel packageConfigPanel;
    private final ResultPanel resultPanel;
    private final List<GuiExtension> extensions;
    private final boolean withPacker;

    public MemShellGeneratorFrame() {
        this(Collections.<GuiExtension>emptyList());
    }

    /**
     * 带扩展的独立窗口：扩展可以接管应用标题，为工具（含 SPI 插件工具）提供专用参数面板、
     * 追加结果动作、接收生成结果回调。
     */
    public MemShellGeneratorFrame(List<GuiExtension> extensions) {
        this(extensions, true);
    }

    /**
     * @param standalone {@code true} = 独立窗口：自带 EXIT_ON_CLOSE、按屏幕自适应尺寸、
     *                   默认按钮与 Ctrl/⌘ + Enter 挂在自己的 rootPane 上；
     *                   {@code false} = 界面归宿主：不设窗口属性（本窗口不会显示），
     *                   宿主取 {@link #getRootPanel()} 自己布局。
     */
    public MemShellGeneratorFrame(List<GuiExtension> extensions, boolean standalone) {
        this(extensions, standalone, true);
    }

    /**
     * @param withPacker {@code false} = 无打包模式：不展示打包分类/变体，生成结果固定按
     *                   Base64 展示（等价 {@code DefaultBase64}），适合拿到
     *                   {@link MemShellResult} 后直接注入的宿主（如 Godzilla 插件）。
     */
    public MemShellGeneratorFrame(List<GuiExtension> extensions, boolean standalone, boolean withPacker) {
        super(MemShellGui.applicationTitle(extensions, "MemShellParty v" + AppVersion.get()), "生成内存马");
        this.extensions = extensions == null ? Collections.<GuiExtension>emptyList() : extensions;
        this.withPacker = withPacker;
        this.configPanel = new MemShellConfigPanel(this.extensions);
        this.generationService = new GenerationService();

        this.resultPanel = new ResultPanel();
        // 无 packer 模块时目录为空：不展示打包条，生成结果直接是 raw Base64
        this.packageConfigPanel = withPacker && !PackerRegistry.getInstance().getTree().isEmpty()
                ? new PackageConfigPanel(configPanel.getController(), configPanel::refreshAll)
                : null;
        // 打包树随 server/tool/shellType 过滤（对齐 web）：pack 面板不属于 configPanel，
        // 必须挂到结构变更监听上，否则切换服务端/类型后打包分类还是旧的一份
        if (packageConfigPanel != null) {
            configPanel.addRefreshListener(packageConfigPanel::refreshFromController);
        }
        resultPanel.setResultActions(resultActions(this.extensions));

        installContent(standalone);
    }

    @Override
    protected JPanel buildRootPanel() {
        // 布局：上半配置表单（核心配置 → 内存马功能）→ 打包条（分类+变体+生成按钮一行），
        // 纵向堆叠为固定高度的配置区；下半结果 Tab 占据全部剩余空间（无可拖拽分隔条）。
        // 无打包模式下打包条只剩生成按钮（注入宿主不需要打包产物）。
        JPanel packBarInner = new JPanel(new MigLayout("insets 0 4 0 4, fillx, gapx 8", "[grow,fill][]", "[]"));
        if (packageConfigPanel != null) {
            packBarInner.add(packageConfigPanel, "growx, pushx");
        } else {
            // 无打包模式：留一个透明占位把生成按钮推到右侧，与带打包条时的位置一致
            packBarInner.add(new JPanel(), "growx, pushx");
        }
        packBarInner.add(prepareGenerateButton("生成内存马 (Ctrl/Cmd + Enter)"), "aligny center, gapright 4");

        JPanel top = new JPanel(new MigLayout("insets 4, fillx, wrap 1", "[grow,fill]", "[]4[]"));
        top.add(configPanel, "growx");
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
     * 运行时注册/替换工具面板（同名覆盖，立即生效并刷新）：内置面板与扩展面板都在构造期注册好了，
     * 一般不用手动调；宿主程序动态生成面板时才需要。
     *
     * @return 被顶掉的旧面板，没有则 null
     */
    public RefreshableToolPanel registerToolPanel(String shellTool, RefreshableToolPanel panel) {
        return configPanel.registerToolPanel(shellTool, panel);
    }

    private static List<ResultAction> resultActions(List<GuiExtension> extensions) {
        List<ResultAction> actions = new ArrayList<ResultAction>();
        for (GuiExtension extension : extensions) {
            actions.addAll(extension.resultActions());
        }
        return actions;
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
        final MemShellFormState snapshot = getController().getState().copy();
        if (!withPacker) {
            // 宿主只要原始结果：空打包方式 = raw Base64
            snapshot.setPackingMethod(PackerRegistry.RAW);
        }
        clearFieldErrors();
        MemShellValidator.Result validation = getController().validate(snapshot);
        if (!validation.isValid()) {
            reportValidationFailure(validation.getFieldErrors());
            return;
        }
        runGenerate(() -> generationService.generate(snapshot), result -> {
            resultPanel.showResult(result);
            notifyResultGenerated(result);
        });
    }

    @Override
    protected void applyValidationErrors(Map<String, String> errors) {
        configPanel.applyValidationErrors(errors);
        if (packageConfigPanel != null) {
            packageConfigPanel.applyValidationErrors(errors);
        }
    }

    @Override
    protected JComponent validationFocusTarget(String field) {
        JComponent target = configPanel.validationFocusTarget(field);
        if (target == null && packageConfigPanel != null) {
            target = packageConfigPanel.validationFocusTarget(field);
        }
        return target;
    }

    /**
     * 生成成功后通知扩展（自动同步宿主数据结构用）；扩展抛异常不影响结果展示，只在状态出口标出来。
     */
    private void notifyResultGenerated(DesktopMemShellGenerateResult result) {
        for (GuiExtension extension : extensions) {
            try {
                extension.onResultGenerated(result);
            } catch (Throwable t) {
                statusReporter().report("扩展 " + extension.name() + " 处理生成结果失败: " + t,
                        StatusReporter.Level.ERROR);
            }
        }
    }

    /**
     * 结构性变更后旧的错误标记已失真，统一清掉（字段内直接编辑由 bindText 单独清）。
     */
    @Override
    protected void clearFieldErrors() {
        configPanel.clearFieldErrors();
        if (packageConfigPanel != null) {
            SwingUiUtil.clearFieldErrors(packageConfigPanel);
        }
    }

    public void refreshAll() {
        // 打包条挂在 configPanel 的结构变更监听上，会随这里一起刷新
        configPanel.refreshAll();
        revalidate();
        repaint();
    }

    /**
     * 宿主程序内嵌时常用：拿到控制器做预填/联动。
     */
    public MemShellFormController getController() {
        return configPanel.getController();
    }

    /**
     * 工具面板注册表（含扩展面板）：宿主程序/测试可以按工具名取面板。
     */
    public ToolPanelRegistry getToolPanelRegistry() {
        return configPanel.getToolPanelRegistry();
    }
}
