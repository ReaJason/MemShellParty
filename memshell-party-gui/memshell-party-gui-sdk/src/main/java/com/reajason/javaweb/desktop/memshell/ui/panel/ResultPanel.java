package com.reajason.javaweb.desktop.memshell.ui.panel;

import com.reajason.javaweb.desktop.memshell.extension.ResultAction;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.service.CfrDecompileService;
import com.reajason.javaweb.desktop.memshell.util.Base64DisplayArea;
import com.reajason.javaweb.desktop.memshell.util.FileSaveUtil;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.memshell.MemShellResult;
import net.miginfocom.swing.MigLayout;

import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.io.File;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;

/**
 * ④ 结果面板：生成结果 / 内存马 / 注入器三个固定 Tab，带 helper 的结果（如 RawWebSocket）
 * 会在内存马与注入器之间动态插入「辅助类」Tab。
 * 复制/保存作用于当前 Tab；未生成时各 Tab 统一显示引导空态且按钮禁用。
 * 类字节页均可在当前结果区内切换 Base64 与 CFR 反编译源码。
 */
public class ResultPanel extends JPanel {
    private final JTabbedPane tabs = new JTabbedPane();
    private final BasicInfoPanel basicInfoPanel = new BasicInfoPanel();
    private final CfrDecompileService decompileService = new CfrDecompileService();
    private final Base64DisplayArea packResultArea = new Base64DisplayArea();    private final JLabel packHeaderLabel = new JLabel("未生成");
    private final ClassTab shellTab = new ClassTab(ClassTabKind.SHELL);
    private final ClassTab helperTab = new ClassTab(ClassTabKind.HELPER);
    private final ClassTab injectorTab = new ClassTab(ClassTabKind.INJECTOR);
    private final JPanel helperTabComponent;
    private boolean helperTabVisible;
    private final JPanel packStack = new JPanel(new CardLayout());
    private final List<AbstractButton> resultButtons = new ArrayList<AbstractButton>();
    /** 扩展动作按钮 → 它的动作，置灰时要问 {@link ResultAction#supports} 这份结果适不适用。 */
    private final Map<AbstractButton, ResultAction> extensionActions =
            new LinkedHashMap<AbstractButton, ResultAction>();
    /** 正处在忙碌态（点击后、动作回调完成前）的扩展动作按钮：期间即使重新生成也保持置灰。 */
    private final Set<AbstractButton> busyExtensionButtons =
            Collections.newSetFromMap(new IdentityHashMap<AbstractButton, Boolean>());
    private final JPanel extensionActionBar = new JPanel(new MigLayout("insets 0, gapx 6, hidemode 3", "[]", "[]"));
    private StatusReporter statusReporter = new StatusReporter() {
        @Override
        public void report(String message, StatusReporter.Level level) {
        }
    };
    private DesktopMemShellGenerateResult current;

    private enum ClassTabKind {
        SHELL, HELPER, INJECTOR
    }

    /**
     * 内存马/辅助类/注入器三个类字节 Tab 的组件与视图状态（源码/Base64 切换、反编译代际令牌）。
     */
    private final class ClassTab {
        final ClassTabKind kind;
        final Base64DisplayArea area = new Base64DisplayArea();
        final JLabel nameLabel = new JLabel("");
        final JButton sourceToggleBtn = new JButton("查看源码");
        final JPanel stack = new JPanel(new CardLayout());
        boolean showingSource;
        String source;
        long decompileGeneration;

        ClassTab(ClassTabKind kind) {
            this.kind = kind;
        }

        String className(MemShellResult r) {
            switch (kind) {
                case SHELL:
                    return r.getShellClassName();
                case HELPER:
                    return r.getHelperClassName();
                default:
                    return r.getInjectorClassName();
            }
        }

        String base64(MemShellResult r) {
            switch (kind) {
                case SHELL:
                    return r.getShellBytesBase64Str();
                case HELPER:
                    return r.getHelperBytesBase64Str();
                default:
                    return r.getInjectorBytesBase64Str();
            }
        }

        long size(MemShellResult r) {
            switch (kind) {
                case SHELL:
                    return r.getShellSize();
                case HELPER:
                    return r.getHelperSize();
                default:
                    return r.getInjectorSize();
            }
        }

        /** 过期进行中的反编译并回到 Base64 视图（新结果/清空时调用）。 */
        void reset() {
            decompileGeneration++;
            source = null;
            showingSource = false;
            sourceToggleBtn.setText("查看源码");
        }

        void clearView() {
            reset();
            area.showText("", false);
            nameLabel.setText("");
            nameLabel.setToolTipText(null);
        }
    }

    public ResultPanel() {
        setLayout(new BorderLayout());
        tabs.addTab("生成结果", buildPackTab());
        tabs.addTab("内存马", buildClassTab("内存马类字节(Base64)", shellTab));
        helperTabComponent = buildClassTab("辅助类字节(Base64)", helperTab);
        tabs.addTab("注入器", buildClassTab("注入器类字节(Base64)", injectorTab));
        add(tabs, BorderLayout.CENTER);
        setResultAvailable(false);
    }

    /**
     * 有辅助类的结果在内存马与注入器之间插入「辅助类」Tab，没有则摘掉。
     */
    private void syncHelperTab(boolean hasHelper) {
        if (hasHelper && !helperTabVisible) {
            tabs.insertTab("辅助类", null, helperTabComponent, null, 2);
            helperTabVisible = true;
        } else if (!hasHelper && helperTabVisible) {
            tabs.remove(helperTabComponent);
            helperTabVisible = false;
        }
    }

    /**
     * 保存成功/空内容拦截等结果区消息上报给主窗口状态栏。
     */
    public void setStatusReporter(StatusReporter statusReporter) {
        this.statusReporter = statusReporter == null ? this.statusReporter : statusReporter;
    }

    /**
     * 挂上扩展提供的结果动作按钮（如"加入我的 Shell 列表"）：没有动作时整条隐藏，不占位置；
     * 按钮与复制/保存一起随"是否有结果"启用/禁用。
     *
     * <p>{@link ResultAction#alignRight()} 为 {@code true} 的动作贴右边（MigLayout 的
     * {@code pushx} 把多余宽度塞进它左侧的间隙），靠左的照旧排在前面；
     * {@link ResultAction#supports} 为 {@code false} 的动作在当前结果下保持置灰；
     * 声明了 {@link ResultAction#busyLabel()} 的动作点击后进入忙碌态，完成后自动恢复。
     */
    public void setResultActions(List<ResultAction> actions) {
        extensionActionBar.removeAll();
        for (final ResultAction action : actions) {
            // 与内置动作按钮一致：不参与焦点遍历，点击后不会留下蓝色焦点框（看着像文字被选中），
            // 忙碌态禁用时也不会把焦点甩给下一个输入框
            final JButton button = SwingUiUtil.actionButton(action.label());
            fixBusyButtonWidth(button, action);
            button.addActionListener(e -> performExtensionAction(button, action));
            resultButtons.add(button);
            extensionActions.put(button, action);
            extensionActionBar.add(button, action.alignRight() ? "pushx, align right" : "");
        }
        extensionActionBar.setVisible(!actions.isEmpty());
        setResultAvailable(current != null);
        revalidate();
        repaint();
    }

    /**
     * 忙碌态文案切换会改变按钮首选宽度，结果动作行会跟着抖动；按两种文案的最大宽度固定按钮尺寸
     * （与生成按钮的 {@code fixGenerateButtonWidth} 同一处理）。
     */
    private static void fixBusyButtonWidth(JButton button, ResultAction action) {
        String busyLabel = action.busyLabel();
        if (busyLabel == null) {
            return;
        }
        Dimension size = button.getPreferredSize();
        button.setText(busyLabel);
        size.width = Math.max(size.width, button.getPreferredSize().width);
        button.setText(action.label());
        button.setPreferredSize(size);
        button.setMinimumSize(size);
    }

    /**
     * 点击扩展动作：声明了 {@link ResultAction#busyLabel()} 的动作进入忙碌态（置灰 + 文案切换），
     * 等动作通过完成回调报告结束后再恢复。回调可能来自后台线程，统一切回 EDT 处理。
     */
    private void performExtensionAction(final AbstractButton button, final ResultAction action) {
        final DesktopMemShellGenerateResult result = current;
        if (result == null) {
            return;
        }
        final String busyLabel = action.busyLabel();
        if (busyLabel == null) {
            action.perform(result, new Runnable() {
                @Override
                public void run() {
                }
            });
            return;
        }
        busyExtensionButtons.add(button);
        button.setText(busyLabel);
        button.setEnabled(false);
        action.perform(result, new Runnable() {
            @Override
            public void run() {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        busyExtensionButtons.remove(button);
                        button.setText(action.label());
                        button.setEnabled(current != null && action.supports(current));
                    }
                });
            }
        });
    }

    /**
     * 未生成时的引导空态：说明操作路径与快捷键。三 Tab 各持有一份实例（组件只能有一个父容器）。
     * 背景跟随 TextArea.background，暗色主题切换不翻车。
     */
    private JPanel buildEmptyHint() {
        JLabel title = new JLabel("尚未生成");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 15f));
        title.setHorizontalAlignment(SwingConstants.CENTER);
        // 启动期可见字符串不要让拉丁段被 CJK/全角字符夹在中间（如 （Ctrl…）或 ⌘）：
        // macOS 26 + JDK<26 下这种 CJK→拉丁→CJK 交替渲染会污染 Helvetica Neue 字形缓存，整窗缺字。
        // 拉丁段放句尾/句首（单一边界）或括号用半角即可规避，见 PieceTest p1/p6/p10/p11
        final JLabel hint = new JLabel("<html><div style='text-align: center;'>配置上方表单后点击 <b>生成内存马</b> (Ctrl, Cmd + Enter)<br>结果、内存马与注入器字节码将在此展示，均可复制或保存</div></html>");
        hint.setHorizontalAlignment(SwingConstants.CENTER);
        // JLabel 的最小宽度等于 HTML 首选宽度（约 1000px）；空态和结果页叠在同一个 CardLayout 里，
        // 而 CardLayout 的最小宽取所有卡片的较大值——生成后即使空态已隐藏，仍会把整个结果区的最小
        // 宽度撑到 1000+，窄窗口下右侧的注入/复制/保存按钮被顶出窗口。显式压掉最小宽度。
        hint.setMinimumSize(new Dimension(0, hint.getPreferredSize().height));

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
     * 生成结果页靠 MigLayout insets 实现，类字节页靠 titled border 外的 EmptyBorder 实现。
     */
    private static final String TAB_OUTER_INSETS = "insets 4 8 8 8";

    private JPanel buildPackTab() {
        JPanel tab = new JPanel(new MigLayout(TAB_OUTER_INSETS + ", fill, wrap 1", "[grow,fill]", "[][][grow]"));

        JPanel infoWrap = new JPanel(new MigLayout("insets 0, fillx", "[grow,fill]", "[]"));
        infoWrap.setBorder(BorderFactory.createTitledBorder("基本信息（值可点击复制）"));
        infoWrap.add(basicInfoPanel, "growx");
        tab.add(infoWrap, "growx");

        // 扩展结果动作（如"加入我的 Shell 列表"）：没有动作时整行隐藏
        extensionActionBar.setVisible(false);
        tab.add(extensionActionBar, "growx");

        JPanel packWrap = new JPanel(new MigLayout("insets 4, fill, wrap 1", "[grow,fill]", "[][grow]"));
        packWrap.setBorder(BorderFactory.createTitledBorder("打包结果"));

        JPanel headerRow = new JPanel(new MigLayout("insets 0, fillx, gapx 6", "[grow,fill][][]", "[]"));
        headerRow.add(packHeaderLabel, "growx, pushx, wmin 0");
        JButton copyBtn = SwingUiUtil.actionButton("复制");
        JButton saveBtn = new JButton("保存");
        headerRow.add(copyBtn);
        headerRow.add(saveBtn);
        resultButtons.add(copyBtn);
        resultButtons.add(saveBtn);
        packWrap.add(headerRow, "growx, wrap");

        // 空态与结果区叠加：未生成显示引导，生成后切换到结果
        packStack.add(buildEmptyHint(), "empty");
        packStack.add(new JScrollPane(packResultArea), "result");
        packWrap.add(packStack, "grow, push");
        tab.add(packWrap, "grow, push");

        copyBtn.addActionListener(e -> copyPackResult(copyBtn));
        saveBtn.addActionListener(e -> savePackResult());
        return tab;
    }

    private JPanel buildClassTab(String title, final ClassTab classTab) {
        // 组内边距与「打包结果」组一致（insets 4）；标题边框挂 tab 面板会贴边，外层按统一值补 margin
        JPanel tab = new JPanel(new MigLayout("insets 4, fill, wrap 1", "[grow,fill]", "[grow]"));
        tab.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(4, 8, 8, 8),
                BorderFactory.createTitledBorder(title)));

        JPanel content = new JPanel(new MigLayout("insets 4, fill, wrap 1", "[grow,fill]", "[][grow]"));
        JPanel headerRow = new JPanel(new MigLayout("insets 0, fillx, gapx 6", "[][grow,fill][][][]", "[]"));
        // 类名可能很长：允许收缩到 0，窄窗口下优先保住右侧的查看源码/复制/保存
        headerRow.add(classTab.nameLabel, "wmin 0");
        headerRow.add(new JLabel(""), "growx");
        JButton copyBtn = SwingUiUtil.actionButton("复制");
        JButton saveBtn = new JButton("保存 .class");
        headerRow.add(classTab.sourceToggleBtn);
        headerRow.add(copyBtn);
        headerRow.add(saveBtn);
        resultButtons.add(classTab.sourceToggleBtn);
        resultButtons.add(copyBtn);
        resultButtons.add(saveBtn);
        content.add(headerRow, "growx, wrap");
        content.add(new JScrollPane(classTab.area), "grow, push");

        classTab.stack.add(buildEmptyHint(), "empty");
        classTab.stack.add(content, "result");
        tab.add(classTab.stack, "grow, push");

        classTab.sourceToggleBtn.setToolTipText("在 Base64 与 CFR 反编译源码之间切换");
        classTab.sourceToggleBtn.addActionListener(e -> toggleSourceView(classTab));
        copyBtn.addActionListener(e -> copyClassTab(classTab, copyBtn));
        saveBtn.addActionListener(e -> saveClassBytes(classTab));
        return tab;
    }

    public void showResult(DesktopMemShellGenerateResult result) {
        this.current = result;
        shellTab.reset();
        helperTab.reset();
        injectorTab.reset();
        MemShellResult r = result.getMemShellResult();

        boolean hasHelper = r.getHelperBytesBase64Str() != null && !r.getHelperBytesBase64Str().isEmpty();
        syncHelperTab(hasHelper);

        basicInfoPanel.setResult(result);
        populateClassTab(shellTab, r);
        populateClassTab(injectorTab, r);
        if (hasHelper) {
            populateClassTab(helperTab, r);
        }

        boolean usageText = result.isJarOutput() || result.isAgentOutput();
        String packText = displayPackText(result);
        // Base64 类产物按组件宽度显式换行展示；使用步骤有空格和真实换行，按词换行
        if (usageText) {
            packResultArea.showText(packText, true);
        } else {
            packResultArea.showAuto(packText);
        }
        packHeaderLabel.setText(result.getPackMethod()
                + (result.getPackResult() == null ? "" : " · " + packSizeText(result)));
        setResultAvailable(true);
        // 生成后聚焦结果，避免停留在内存马/注入器旧页
        tabs.setSelectedIndex(0);
    }

    private void populateClassTab(ClassTab tab, MemShellResult r) {
        tab.nameLabel.setText(tab.className(r) + " (" + tab.size(r) + " bytes)");
        tab.nameLabel.setToolTipText(tab.nameLabel.getText());
        tab.area.showBase64(tab.base64(r));
    }

    /**
     * 未生成 ↔ 有结果：各 Tab 统一切换空态/结果叠加层，并禁用/恢复复制保存按钮。
     * 扩展动作还要过一遍 {@link ResultAction#supports}：不适用的动作保持置灰。
     */
    private void setResultAvailable(boolean available) {
        for (AbstractButton button : resultButtons) {
            ResultAction action = extensionActions.get(button);
            // 判定要用生成结果，所以没结果时一律置灰；忙碌中的动作按钮等完成回调再恢复
            boolean supported = action == null || (current != null && action.supports(current));
            button.setEnabled(available && supported && !busyExtensionButtons.contains(button));
        }
        String card = available ? "result" : "empty";
        ((CardLayout) packStack.getLayout()).show(packStack, card);
        ((CardLayout) shellTab.stack.getLayout()).show(shellTab.stack, card);
        ((CardLayout) helperTab.stack.getLayout()).show(helperTab.stack, card);
        ((CardLayout) injectorTab.stack.getLayout()).show(injectorTab.stack, card);
    }

    public void clear() {
        current = null;
        syncHelperTab(false);
        shellTab.clearView();
        helperTab.clearView();
        injectorTab.clearView();
        basicInfoPanel.clear();
        packResultArea.showText("", false);
        packHeaderLabel.setText("未生成");
        setResultAvailable(false);
    }

    /**
     * 打包结果大小展示：Jar/Agent 产物是 Base64 文本，换算解码后字节数以 KB/MB 显示；
     * 其余文本产物（脚本等）仍显示字符长度。
     */
    private static String packSizeText(DesktopMemShellGenerateResult result) {
        String packResult = result.getPackResult();
        if (packResult == null) {
            return "";
        }
        if (result.isJarOutput() || result.isAgentOutput()) {
            return formatSize(base64DecodedSize(packResult));
        }
        return String.valueOf(packResult.length());
    }

    /**
     * 按 Base64 文本长度推算解码后字节数，避免仅为显示大小而解码整个 Jar。
     */
    private static long base64DecodedSize(String base64) {
        int len = base64.length();
        long size = (len / 4) * 3L;
        if (len > 0 && base64.charAt(len - 1) == '=') size--;
        if (len > 1 && base64.charAt(len - 2) == '=') size--;
        return size;
    }

    private static String formatSize(long bytes) {
        if (bytes >= 1024 * 1024) {
            return String.format("%.1f MB", bytes / 1024.0 / 1024.0);
        }
        if (bytes >= 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        }
        return bytes + " B";
    }

    /**
     * 在当前结果页内切换 Base64 与 CFR 源码；每个类字节 Tab 各自维护缓存与过期令牌。
     */
    private void toggleSourceView(final ClassTab tab) {
        if (current == null) {
            return;
        }

        if (!tab.showingSource) {
            tab.showingSource = true;
            tab.sourceToggleBtn.setText("查看 Base64");
            // 源码有空格与显式换行，按词换行展示；回到 Base64 视图时恢复宽度跟随的显式换行
            if (tab.source != null) {
                tab.area.showText(tab.source, true);
                return;
            }

            final MemShellResult result = current.getMemShellResult();
            final String className = tab.className(result);
            final String base64 = tab.base64(result);
            if (base64 == null || base64.trim().isEmpty()) {
                tab.area.showText("// 无可反编译的类字节码", true);
                return;
            }
            tab.area.showText("// 正在使用 CFR 反编译 " + className + " ...", true);
            final Object generationToken = current;
            final long requestGeneration = ++tab.decompileGeneration;
            new SwingWorker<String, Void>() {
                @Override
                protected String doInBackground() {
                    byte[] bytes = Base64.getDecoder().decode(base64.trim());
                    return decompileService.decompile(className, bytes);
                }

                @Override
                protected void done() {
                    boolean currentRequest = generationToken == current
                            && requestGeneration == tab.decompileGeneration;
                    if (!currentRequest) {
                        return;
                    }
                    String source;
                    boolean decompileSucceeded = false;
                    try {
                        source = get();
                        decompileSucceeded = true;
                    } catch (Exception ex) {
                        Throwable cause = ex instanceof ExecutionException && ex.getCause() != null
                                ? ex.getCause() : ex;
                        String message = cause.getMessage() == null ? String.valueOf(cause) : cause.getMessage();
                        source = "// 反编译失败: " + message;
                        statusReporter.report("反编译失败: " + message, StatusReporter.Level.ERROR);
                    }
                    if (decompileSucceeded) {
                        tab.source = source;
                    }
                    if (tab.showingSource) {
                        tab.area.showText(source, true);
                    }
                }
            }.execute();
        } else {
            tab.decompileGeneration++;
            tab.showingSource = false;
            tab.sourceToggleBtn.setText("查看源码");
            tab.area.showBase64(tab.base64(current.getMemShellResult()));
        }
    }

    /**
     * Jar/Agent 打包显示使用步骤，其余显示打包产物。
     */
    private String displayPackText(DesktopMemShellGenerateResult result) {
        if (result.isAgentOutput()) {
            return agentUsageText(result);
        }
        if (result.isJarOutput()) {
            return "1. 点击「保存」导出 Jar\n"
                    + "2. 按目标环境触发类加载 (放入 classpath 或对应加载流程)\n"
                    + "3. 使用基本信息中的参数连接内存马\n\n"
                    + "(「保存」按钮会将打包后的 Jar 以 .jar 文件保存)";
        }
        String packResult = result.getPackResult();
        return packResult == null ? "" : packResult;
    }

    /**
     * Agent 使用步骤（对齐 web agent.tsx）：纯 AgentJar 无 main 方法，需配合 jattach 注入；
     * 带 Attacher 的变体（AgentJarWithJDKAttacher/AgentJarWithJREAttacher）可直接 java -jar 自注入。
     */
    private String agentUsageText(DesktopMemShellGenerateResult result) {
        String size = packSizeText(result);
        String steps;
        if (result.isPureAgentOutput()) {
            steps = "1. 点击「保存」导出 MemShellAgent.jar (" + size + ")\n"
                    + "2. 下载 jattach 工具: https://github.com/jattach/jattach/releases\n"
                    + "3. 将 MemShellAgent.jar 和 jattach 上传到目标服务器磁盘\n"
                    + "4. 获取目标 JVM 进程 pid (使用 jps 或 ps)\n"
                    + "5. 执行命令进行注入: /path/to/jattach <pid> load instrument false /path/to/agent.jar\n"
                    + "6. 按基本信息中的参数连接或触发内存马";
        } else {
            steps = "1. 点击「保存」导出 MemShellAgent.jar (" + size + ")\n"
                    + "2. 将 MemShellAgent.jar 上传到目标服务器磁盘\n"
                    + "3. 获取目标 JVM 进程 pid (使用 jps, ps 或 java -jar agent.jar 列出)\n"
                    + "4. 执行命令进行注入: java -jar /path/to/agent.jar <pid> (注入指定进程)\n"
                    + "   或 java -jar /path/to/agent.jar all (注入所有 Java 进程)\n"
                    + "5. 按基本信息中的参数连接或触发内存马";
        }
        return steps + "\n\n(「保存」按钮会将打包后的 Jar 以 .jar 文件保存)";
    }

    /**
     * 复制打包结果：Jar/Agent 页展示的是使用步骤，复制所见文本；
     * Base64 类产物展示区有显式换行，复制原始单行串。
     */
    private void copyPackResult(JButton copyBtn) {
        if (current == null) {
            return;
        }
        boolean usageText = current.isJarOutput() || current.isAgentOutput();
        String text = usageText ? packResultArea.getText() : current.getPackResult();
        SwingUiUtil.copyWithFeedback(copyBtn, text == null ? "" : text);
    }

    /**
     * 复制类字节 Tab：源码视图复制所见的源码；Base64 视图复制原始单行 Base64
     * （展示区的显式换行只是宽度适配形态，见 {@link Base64DisplayArea}）。
     */
    private void copyClassTab(ClassTab tab, JButton copyBtn) {
        if (current == null) {
            return;
        }
        String text = tab.showingSource ? tab.area.getText() : tab.base64(current.getMemShellResult());
        SwingUiUtil.copyWithFeedback(copyBtn, text == null ? "" : text);
    }

    private void savePackResult() {
        if (current == null) return;
        try {
            if (current.isJarOutput() || current.isAgentOutput()) {
                String payload = current.getPackResult();
                if (interceptEmpty(payload)) return;
                String baseName = current.getMemShellResult().getShellConfig().getServer()
                        + current.getMemShellResult().getShellConfig().getShellTool()
                        + (current.isAgentOutput() ? "MemShellAgent" : "MemShell");
                reportSaved(FileSaveUtil.saveBase64AsBytes(this, baseName + ".jar", payload, "jar"));
            } else {
                // 展示区是宽度跟随的显式换行形态，保存用原始单行串
                String payload = current.getPackResult();
                if (interceptEmpty(payload)) return;
                reportSaved(FileSaveUtil.saveText(this, current.getPackMethod() + ".txt", payload));
            }
        } catch (Exception ex) {
            SwingUiUtil.showError(this, "保存失败: " + ex.getMessage());
        }
    }

    private void saveClassBytes(ClassTab tab) {
        if (current == null) return;
        try {
            MemShellResult r = current.getMemShellResult();
            String payload = tab.base64(r);
            if (interceptEmpty(payload)) return;
            reportSaved(FileSaveUtil.saveBase64AsBytes(this, FileSaveUtil.simpleFileName(tab.className(r), ".class"), payload, "class"));
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
