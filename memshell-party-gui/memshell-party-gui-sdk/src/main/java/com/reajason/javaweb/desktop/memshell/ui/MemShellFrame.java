package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.util.FrameShortcutUtil;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JRootPane;
import javax.swing.SwingWorker;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Consumer;

/**
 * 两个生成器界面（{@link MemShellGeneratorFrame} 内存马 / {@link ProbeGeneratorFrame} 探测马）
 * 共用的窗口骨架：内容懒构建、独立窗口与内嵌两种用法、状态出口、生成按钮与快捷键、
 * 生成过程的忙碌态与结果回报。两者只有配置区行数、校验器类型和生成服务不同，
 * 那部分留在子类，壳不再各写一遍。
 *
 * <p>子类构造：先建自己的面板字段，再 {@code super(标题, 按钮文案)}，最后
 * {@link #installContent(boolean)} —— 内容要用到子类字段，不能在基类构造里建。
 *
 * <p>宿主内嵌用法见 {@link #getRootPanel()} / {@link #setStatusReporter} /
 * {@link #installGenerateShortcut}。
 */
public abstract class MemShellFrame extends JFrame {

    /** 生成中的按钮文案：两种界面共用。 */
    private static final String BUSY_LABEL = "生成中…";

    /** 快捷键动作名：两个生成器共用（同一窗口里同时只装一个页的快捷键）。 */
    private static final String GENERATE_ACTION_KEY = "generateShell";

    private static final StatusReporter NO_OP_REPORTER = new StatusReporter() {
        @Override
        public void report(String message, StatusReporter.Level level) {
        }
    };

    /**
     * 结果区上报给宿主状态栏的出口：宿主（官方发行版外壳 / 自建客户端）自己决定怎么显示，
     * 不设时静默丢弃 —— 校验错误仍行内标红、生成失败仍有错误弹窗，只是没有状态行文案。
     */
    private StatusReporter statusReporter = NO_OP_REPORTER;

    /** 生成按钮的常态文案，生成中临时换成 {@link #BUSY_LABEL}。 */
    private final String generateLabel;
    private final JButton generateButton;
    private JPanel rootPanel;

    protected MemShellFrame(String title, String generateLabel) {
        super(title);
        this.generateLabel = generateLabel;
        this.generateButton = SwingUiUtil.actionButton(generateLabel);
    }

    /**
     * 子类构造末尾调用：把内容挂进窗口，standalone 时再补窗口属性与快捷键。
     *
     * <p>不在基类构造里做：那时子类字段还没赋值，{@link #buildRootPanel()} 会拿到 null。
     *
     * @param standalone {@code true} = 独立窗口：自带 EXIT_ON_CLOSE、按屏幕自适应尺寸、
     *                   默认按钮与 Ctrl/⌘ + Enter 挂在自己的 rootPane 上；
     *                   {@code false} = 界面归宿主：不设窗口属性（本窗口不会显示），
     *                   宿主取 {@link #getRootPanel()} 自己布局。
     */
    protected final void installContent(boolean standalone) {
        applyStatusReporter(statusReporter);
        setLayout(new BorderLayout());
        add(getRootPanel(), BorderLayout.CENTER);
        if (standalone) {
            setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
            SwingUiUtil.sizeToScreen(this);
            setLocationRelativeTo(null);
            // 默认按钮/快捷键挂在生成按钮已接线之后（buildRootPanel 里才加监听）
            installGenerateShortcut(getRootPane());
        }
    }

    /**
     * 界面内容（配置区 + 结果区），首次调用时构建、之后返回同一实例；独立窗口路径自己也走它。
     * 宿主程序把生成器嵌进自己的页签/面板时用它。
     *
     * <p>返回的组件是同一个实例，只能有一个父容器：内嵌了就别再 {@code setVisible(true)} 本窗口。
     */
    public final JPanel getRootPanel() {
        if (rootPanel == null) {
            rootPanel = buildRootPanel();
        }
        return rootPanel;
    }

    /**
     * 子类的界面内容，只在首次 {@link #getRootPanel()} 时调用一次。
     */
    protected abstract JPanel buildRootPanel();

    /**
     * 状态出口：宿主自己决定怎么显示（官方发行版外壳的共享状态栏 / 自建客户端的状态行）。
     * 不设或传 {@code null} 时静默丢弃。
     */
    public final void setStatusReporter(StatusReporter reporter) {
        this.statusReporter = reporter == null ? NO_OP_REPORTER : reporter;
        applyStatusReporter(this.statusReporter);
    }

    protected final StatusReporter statusReporter() {
        return statusReporter;
    }

    /**
     * 当前状态出口，供子类转给自己的结果区（结果区也有状态出口）。
     */
    protected abstract void applyStatusReporter(StatusReporter reporter);

    /**
     * 把生成快捷键（Ctrl/⌘ + Enter）与默认按钮（裸 Enter）挂到承载本界面的 rootPane 上：
     * 独立窗口模式构造期已挂好，内嵌时由宿主在窗口就绪后调用；同一窗口里换成别的页时，
     * 让当前页的 frame 再调一次即可把快捷键与默认按钮转移过去。
     *
     * @param rootPane 实际承载本界面的 rootPane（内嵌时是宿主窗口的）；为空则跳过
     */
    public final void installGenerateShortcut(JRootPane rootPane) {
        FrameShortcutUtil.install(rootPane, GENERATE_ACTION_KEY, new Runnable() {
            @Override
            public void run() {
                triggerGenerate();
            }
        }, generateButton);
    }

    /**
     * 撤销 {@link #installGenerateShortcut(JRootPane)}，把快捷键与默认按钮从 rootPane 上摘掉。
     *
     * <p>宿主在生成页之外还有别的页签时用：进入生成页装、离开就卸，
     * 免得在别的页里敲 Enter / Ctrl(⌘) + Enter 误触发一次生成。
     * 同一窗口里有多个生成页时先卸旧的、再装新的。
     *
     * @param rootPane 刚才装的 rootPane；为空则跳过
     */
    public final void uninstallGenerateShortcut(JRootPane rootPane) {
        FrameShortcutUtil.uninstall(rootPane, GENERATE_ACTION_KEY, generateButton);
    }

    public final JButton getGenerateButton() {
        return generateButton;
    }

    /**
     * 打包条里那颗生成按钮的固定打扮：加粗、tooltip、接线、固定宽度。
     * 子类把它 {@code add} 进自己的打包条后调一次即可。
     *
     * <p>tooltip 同样遵守「拉丁段不被 CJK 夹中间」规则（见 ResultPanel 空态提示的注释）。
     */
    protected final JButton prepareGenerateButton(String tooltip) {
        generateButton.setFont(generateButton.getFont().deriveFont(Font.BOLD, 14f));
        generateButton.setToolTipText(tooltip);
        generateButton.addActionListener(e -> triggerGenerate());
        fixGenerateButtonWidth();
        return generateButton;
    }

    /**
     * 生成入口：按钮、快捷键、宿主程序都走它。子类在这里取快照、跑校验，然后交给
     * {@link #runGenerate}。
     */
    public abstract void triggerGenerate();

    /**
     * 校验失败时的统一收尾：行内标红（子类实现 {@link #applyValidationErrors}）、
     * 状态出口汇总、焦点跳首个错误字段。
     */
    protected final void reportValidationFailure(Map<String, String> fieldErrors) {
        applyValidationErrors(fieldErrors);
        statusReporter.report("校验失败：" + joinMessages(fieldErrors), StatusReporter.Level.ERROR);
        for (String field : fieldErrors.keySet()) {
            JComponent target = validationFocusTarget(field);
            if (target != null) {
                target.requestFocusInWindow();
                return;
            }
        }
    }

    /**
     * inline 校验：全部错误一次标完（红描边 + 行内红字），子类把自己的面板都串进来。
     */
    protected abstract void applyValidationErrors(Map<String, String> errors);

    /**
     * 字段名 → 该字段所在组件；子类按 主配置 → 打包 → 工具面板 的顺序找。
     */
    protected abstract JComponent validationFocusTarget(String field);

    /**
     * 结构性变更后旧的错误标记已失真，统一清掉（字段内直接编辑由 bindText 单独清）。
     * 递归整棵组件树，工具面板在卡片里也一并覆盖。
     */
    protected void clearFieldErrors() {
        SwingUiUtil.clearFieldErrors(this);
    }

    /**
     * 生成骨架：按钮忙碌态 → 后台生成 → 结果展示 / 错误弹窗，状态出口全程回报耗时。
     *
     * @param task      后台生成（读的是子类在 EDT 上拷好的快照）
     * @param onSuccess 成功后在 EDT 上展示结果
     */
    protected final <R> void runGenerate(Callable<R> task, final Consumer<R> onSuccess) {
        generateButton.setEnabled(false);
        generateButton.setText(BUSY_LABEL);
        statusReporter.report(BUSY_LABEL, StatusReporter.Level.BUSY);
        final long startTime = System.currentTimeMillis();

        SwingWorker<R, Void> worker = new SwingWorker<R, Void>() {
            @Override
            protected R doInBackground() throws Exception {
                return task.call();
            }

            @Override
            protected void done() {
                generateButton.setEnabled(true);
                generateButton.setText(generateLabel);
                long elapsed = System.currentTimeMillis() - startTime;
                try {
                    R result = get();
                    // 先报成功再交给子类：子类可能继续通知扩展，扩展的报错要留在状态行上，不能被成功覆盖
                    statusReporter.report("生成成功 · 耗时 " + elapsed + " ms", StatusReporter.Level.SUCCESS);
                    onSuccess.accept(result);
                } catch (Exception ex) {
                    statusReporter.report("生成失败", StatusReporter.Level.ERROR);
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    SwingUiUtil.showError(MemShellFrame.this, "生成失败: " + cause.getMessage());
                }
            }
        };
        worker.execute();
    }

    private static String joinMessages(Map<String, String> fieldErrors) {
        StringBuilder sb = new StringBuilder();
        for (String message : fieldErrors.values()) {
            if (sb.length() > 0) {
                sb.append("；");
            }
            sb.append(message);
        }
        return sb.toString();
    }

    /**
     * 生成中文案切换（生成内存马 ↔ 生成中…）会改变按钮首选宽度，
     * 打包条里按钮收缩会让左侧打包配置区宽度跟着闪烁；按两种文案最大宽度固定按钮尺寸。
     */
    private void fixGenerateButtonWidth() {
        String original = generateButton.getText();
        int width = 0;
        for (String text : new String[]{generateLabel, BUSY_LABEL}) {
            generateButton.setText(text);
            width = Math.max(width, generateButton.getPreferredSize().width);
        }
        generateButton.setText(original);
        Dimension size = generateButton.getPreferredSize();
        size.width = width;
        generateButton.setPreferredSize(size);
        generateButton.setMinimumSize(size);
    }
}
