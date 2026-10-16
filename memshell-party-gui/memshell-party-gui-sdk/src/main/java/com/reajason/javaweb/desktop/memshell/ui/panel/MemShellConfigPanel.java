package com.reajason.javaweb.desktop.memshell.ui.panel;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.extension.GuiExtension;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.CustomClassNameParser;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.AbstractToolPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.RefreshableToolPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.ToolPanelRegistry;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.ToolPanels;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Component;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 可独立内嵌的内存马配置表单：核心配置（{@link MainConfigPanel}）+ 内存马功能区
 * （按工具切换的参数卡，内置 {@code @ConfigField} 动态表单与扩展专用面板）。
 * 打包条与结果区不属于这里 —— 它们在 {@code MemShellGeneratorFrame} 的打包条/结果 Tab 里；
 * 只需要「配置出一个内存马」的宿主（如 Shiro 综合利用工具的注入面板）可以单独嵌本面板。
 *
 * <p>用法：{@code new MemShellConfigPanel(extensions)} 挂进自己的布局，
 * {@link #getController()} 取控制器做预填/读快照，{@link #addRefreshListener(Runnable)}
 * 监听表单结构性变更（server/tool/shellType 切换后触发）。
 */
public class MemShellConfigPanel extends JPanel {

    private final MemShellFormController controller;
    private final MainConfigPanel mainConfigPanel;
    private final JPanel toolCardPanel = new JPanel(new VisibleCardLayout());
    private final ToolPanelRegistry toolPanelRegistry;
    private final TitledBorder toolWrapBorder = BorderFactory.createTitledBorder("内存马功能");
    private final List<Runnable> refreshListeners = new CopyOnWriteArrayList<Runnable>();

    public MemShellConfigPanel() {
        this(Collections.<GuiExtension>emptyList());
    }

    public MemShellConfigPanel(List<GuiExtension> extensions) {
        super(new MigLayout("insets 0, fillx, wrap 1", "[grow,fill]", "[]4[]"));
        this.controller = new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
        CustomClassNameParser customClassNameParser = new CustomClassNameParser();
        this.mainConfigPanel = new MainConfigPanel(controller, this::refreshAll);
        // 内置面板 + 扩展面板（同名扩展顶掉内置），逐个挂进 CardLayout
        this.toolPanelRegistry = ToolPanels.createRegistry(controller, this::refreshAll, customClassNameParser, extensions);
        for (Map.Entry<String, RefreshableToolPanel> entry : toolPanelRegistry.panels().entrySet()) {
            toolCardPanel.add((Component) entry.getValue(), entry.getKey());
        }

        JPanel toolWrap = new JPanel(new BorderLayout());
        toolWrap.setBorder(toolWrapBorder);
        toolWrap.add(toolCardPanel, BorderLayout.NORTH);

        add(mainConfigPanel, "growx");
        add(toolWrap, "growx");
        refreshAll();
    }

    /**
     * 表单控制器：宿主程序做预填/联动/取快照用。
     */
    public MemShellFormController getController() {
        return controller;
    }

    /**
     * 工具面板注册表（含扩展面板）：宿主程序/测试可以按工具名取面板。
     */
    public ToolPanelRegistry getToolPanelRegistry() {
        return toolPanelRegistry;
    }

    /**
     * 运行时注册/替换工具面板（同名覆盖，立即生效并刷新）：内置面板与扩展面板都在构造期注册好了，
     * 一般不用手动调；宿主程序动态生成面板时才需要。
     *
     * @return 被顶掉的旧面板，没有则 null
     */
    public RefreshableToolPanel registerToolPanel(String shellTool, RefreshableToolPanel panel) {
        RefreshableToolPanel previous = toolPanelRegistry.register(shellTool, panel);
        if (previous instanceof Component) {
            toolCardPanel.remove((Component) previous);
        }
        toolCardPanel.add((Component) panel, shellTool);
        refreshAll();
        return previous;
    }

    /**
     * 结构性变更（server/tool/shellType 切换等）完成后的回调：宿主需要跟随表单状态刷新
     * 自己的展示（如按当前 server 预估注入体积）时注册。回调在 EDT 上触发。
     */
    public void addRefreshListener(Runnable listener) {
        if (listener != null) {
            refreshListeners.add(listener);
        }
    }

    /**
     * 结构性变更后全量刷新：核心配置回填 + 工具卡切换 + 错误标记清理。
     * 无专用面板的工具（SPI 插件）懒挂一个反射生成的通用面板。
     */
    public void refreshAll() {
        // 结构性变更后旧的错误标记已失真，统一清掉（字段内直接编辑由 bindText 单独清）
        clearFieldErrors();
        mainConfigPanel.refreshFromController();
        CardLayout cardLayout = (CardLayout) toolCardPanel.getLayout();
        String shellTool = controller.getState().getShellTool();
        boolean alreadyRegistered = toolPanelRegistry.contains(shellTool);
        RefreshableToolPanel toolPanel = toolPanelRegistry.resolve(shellTool, controller, this::refreshAll);
        if (!alreadyRegistered && toolPanel != null) {
            toolCardPanel.add((Component) toolPanel, shellTool);
        }
        cardLayout.show(toolCardPanel, shellTool);
        // 边框标题跟随当前工具，让功能区与"内存马工具"下拉的联动可见
        toolWrapBorder.setTitle(shellTool == null ? "内存马功能" : "内存马功能 — " + shellTool);
        if (toolPanel != null) {
            toolPanel.refreshFromController();
        }
        revalidate();
        repaint();
        for (Runnable listener : refreshListeners) {
            listener.run();
        }
    }

    /**
     * inline 校验：全部错误一次标完（红描边 + 行内红字），核心配置与当前工具卡都覆盖。
     */
    public void applyValidationErrors(Map<String, String> errors) {
        mainConfigPanel.applyValidationErrors(errors);
        RefreshableToolPanel toolPanel = currentToolPanel();
        if (toolPanel instanceof AbstractToolPanel) {
            ((AbstractToolPanel) toolPanel).applyValidationErrors(errors);
        }
    }

    /**
     * 字段名 → 该字段所在组件；核心配置 → 工具面板的顺序找。
     */
    public JComponent validationFocusTarget(String field) {
        JComponent target = mainConfigPanel.validationFocusTarget(field);
        if (target == null) {
            RefreshableToolPanel toolPanel = currentToolPanel();
            if (toolPanel instanceof AbstractToolPanel) {
                target = ((AbstractToolPanel) toolPanel).validationFocusTarget(field);
            }
        }
        return target;
    }

    /**
     * 只清配置区的错误标记：工具面板在卡片里，逐个挑出来清，比整棵组件树递归窄。
     */
    public void clearFieldErrors() {
        SwingUiUtil.clearFieldErrors(mainConfigPanel);
        for (RefreshableToolPanel panel : toolPanelRegistry.panelList()) {
            if (panel instanceof AbstractToolPanel) {
                SwingUiUtil.clearFieldErrors((AbstractToolPanel) panel);
            }
        }
    }

    private RefreshableToolPanel currentToolPanel() {
        return toolPanelRegistry.get(controller.getState().getShellTool());
    }
}
