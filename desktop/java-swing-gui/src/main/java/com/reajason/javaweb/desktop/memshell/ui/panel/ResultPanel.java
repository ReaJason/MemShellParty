package com.reajason.javaweb.desktop.memshell.ui.panel;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.util.FileSaveUtil;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.memshell.MemShellResult;
import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.util.Map;

/**
 * ④ 结果面板：三页 Tab（生成结果 / 内存马 / 注入器）。
 * 复制/保存作用于当前 Tab 与当前聚合条目；未生成时显示引导空态。
 */
public class ResultPanel extends JPanel {
    private final JTabbedPane tabs = new JTabbedPane();
    private final BasicInfoPanel basicInfoPanel = new BasicInfoPanel();
    private final JTextArea packResultArea = createTextArea();
    private final JComboBox<String> aggregateCombo = new JComboBox<String>();
    private final JLabel aggregateLabel = new JLabel("聚合条目");
    private final JLabel packHeaderLabel = new JLabel("未生成");
    private final JTextArea shellArea = createTextArea();
    private final JTextArea injectorArea = createTextArea();
    private final JLabel shellNameLabel = new JLabel("");
    private final JLabel injectorNameLabel = new JLabel("");
    private final JPanel emptyHint = buildEmptyHint();
    private DesktopMemShellGenerateResult current;

    public ResultPanel() {
        setLayout(new BorderLayout());
        tabs.addTab("生成结果", buildPackTab());
        tabs.addTab("内存马", buildBase64Tab("内存马类字节(Base64)", shellArea, shellNameLabel, true));
        tabs.addTab("注入器", buildBase64Tab("注入器类字节(Base64)", injectorArea, injectorNameLabel, false));
        add(tabs, BorderLayout.CENTER);
    }

    /**
     * 未生成时的引导空态：说明操作路径与快捷键。
     */
    private JPanel buildEmptyHint() {
        JLabel title = new JLabel("尚未生成");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 15f));
        title.setHorizontalAlignment(SwingConstants.CENTER);
        JLabel hint = new JLabel("<html><div style='text-align: center;'>配置上方表单后点击 <b>生成内存马</b>（Ctrl/⌘ + Enter）<br>结果、内存马与注入器字节码将在此展示，均可复制或保存</div></html>");
        hint.setHorizontalAlignment(SwingConstants.CENTER);
        hint.setForeground(SwingUiUtil.mutedColor());

        JPanel p = new JPanel(new MigLayout("insets 24, fill, wrap 1, align center", "[grow,fill]", "[]8[]"));
        p.add(title, "growx");
        p.add(hint, "growx");
        p.setBackground(Color.WHITE);
        return p;
    }

    /**
     * 结果 Tab 统一外边距：上 4（上方已有 Tab 标签）、左右下 8。
     * 生成结果页靠 MigLayout insets 实现，内存马/注入器页靠 titled border 外的 EmptyBorder 实现。
     */
    private static final String TAB_OUTER_INSETS = "insets 4 8 8 8";

    private JPanel buildPackTab() {
        JPanel tab = new JPanel(new MigLayout(TAB_OUTER_INSETS + ", fill, wrap 1", "[grow,fill]", "[][grow]")) {
            @Override
            public void updateUI() {
                super.updateUI();
                emptyHint.setBackground(Color.WHITE);
            }
        };

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
        aggregateCombo.setVisible(false);
        aggregateLabel.setVisible(false);
        packWrap.add(headerRow, "growx, wrap");

        // 空态与结果区叠加：未生成显示引导，生成后切换到结果
        JPanel stack = new JPanel(new CardLayout());
        stack.add(new JScrollPane(packResultArea), "result");
        stack.add(emptyHint, "empty");
        packWrap.add(stack, "grow, push");
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
        tab.putClientProperty("resultStack", stack);
        return tab;
    }

    private JPanel buildBase64Tab(String title, JTextArea area, JLabel nameLabel, boolean shell) {
        // 组内边距与「打包结果」组一致（insets 4）；标题边框挂 tab 面板会贴边，外层按统一值补 margin
        JPanel tab = new JPanel(new MigLayout("insets 4, fill, wrap 1", "[grow,fill]", "[][grow]"));
        tab.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(4, 8, 8, 8),
                BorderFactory.createTitledBorder(title)));

        JPanel headerRow = new JPanel(new MigLayout("insets 0, fillx, gapx 6", "[][grow,fill][]", "[]"));
        headerRow.add(nameLabel);
        headerRow.add(new JLabel(""), "growx");
        JButton copyBtn = new JButton("复制");
        JButton saveBtn = new JButton("保存 .class");
        headerRow.add(copyBtn);
        headerRow.add(saveBtn);
        tab.add(headerRow, "growx, wrap");
        tab.add(new JScrollPane(area), "grow, push");

        copyBtn.addActionListener(e -> SwingUiUtil.copyWithFeedback(copyBtn, area.getText()));
        saveBtn.addActionListener(e -> {
            if (current == null) return;
            try {
                MemShellResult r = current.getMemShellResult();
                if (shell) {
                    FileSaveUtil.saveBase64AsBytes(this, simpleClassFileName(r.getShellClassName()), r.getShellBytesBase64Str(), "class");
                } else {
                    FileSaveUtil.saveBase64AsBytes(this, simpleClassFileName(r.getInjectorClassName()), r.getInjectorBytesBase64Str(), "class");
                }
            } catch (Exception ex) {
                SwingUiUtil.showError(this, "保存失败: " + ex.getMessage());
            }
        });
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

    public void showResult(DesktopMemShellGenerateResult result) {
        this.current = result;
        MemShellResult r = result.getMemShellResult();

        basicInfoPanel.setResult(result);
        shellNameLabel.setText(r.getShellClassName() + " (" + r.getShellSize() + " bytes)");
        injectorNameLabel.setText(r.getInjectorClassName() + " (" + r.getInjectorSize() + " bytes)");
        shellArea.setText(r.getShellBytesBase64Str());
        injectorArea.setText(r.getInjectorBytesBase64Str());

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
            packResultArea.setText(displayPackText(result));
            packHeaderLabel.setText(result.getPackMethod()
                    + (result.getPackResult() == null ? "" : " · " + packSizeText(result)));
        }
        packResultArea.setCaretPosition(0);
        showResultStack(true);
        // 生成后聚焦结果，避免停留在内存马/注入器旧页
        tabs.setSelectedIndex(0);
    }

    /**
     * 切换打包结果 Tab 内「空态 / 结果」叠加层。
     */
    private void showResultStack(boolean hasResult) {
        Component tab = tabs.getComponentAt(0);
        JPanel stack = tab instanceof JComponent ? (JPanel) tab : null;
        if (stack instanceof JPanel && ((JPanel) stack).getClientProperty("resultStack") instanceof JPanel) {
            JPanel cards = (JPanel) ((JPanel) stack).getClientProperty("resultStack");
            ((CardLayout) cards.getLayout()).show(cards, hasResult ? "result" : "empty");
        }
    }

    public void clear() {
        current = null;
        basicInfoPanel.clear();
        packResultArea.setText("");
        shellArea.setText("");
        injectorArea.setText("");
        shellNameLabel.setText("");
        injectorNameLabel.setText("");
        packHeaderLabel.setText("未生成");
        aggregateCombo.setVisible(false);
        aggregateLabel.setVisible(false);
        showResultStack(false);
    }

    /**
     * 打包结果大小展示：Jar/Agent 产物是 Base64 文本，换算解码后字节数以 KB/MB 显示；
     * 其余文本产物（聚合条目、脚本等）仍显示字符长度。
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
     * Jar/Agent 打包显示使用步骤，其余显示打包产物。
     */
    private String displayPackText(DesktopMemShellGenerateResult result) {
        if (result.isAgentOutput()) {
            return agentUsageText(result);
        }
        if (result.isJarOutput()) {
            return "1. 点击「保存」导出 Jar\n"
                    + "2. 按目标环境触发类加载（放入 classpath 或对应加载流程）\n"
                    + "3. 使用基本信息中的参数连接内存马\n\n"
                    + "（「保存」按钮会将打包后的 Jar 以 .jar 文件保存）";
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
            steps = "1. 点击「保存」导出 MemShellAgent.jar（" + size + "）\n"
                    + "2. 下载 jattach 工具: https://github.com/jattach/jattach/releases\n"
                    + "3. 将 MemShellAgent.jar 和 jattach 上传到目标服务器磁盘\n"
                    + "4. 获取目标 JVM 进程 pid（使用 jps 或 ps）\n"
                    + "5. 执行命令进行注入: /path/to/jattach <pid> load instrument false /path/to/agent.jar\n"
                    + "6. 按基本信息中的参数连接/触发内存马";
        } else {
            steps = "1. 点击「保存」导出 MemShellAgent.jar（" + size + "）\n"
                    + "2. 将 MemShellAgent.jar 上传到目标服务器磁盘\n"
                    + "3. 获取目标 JVM 进程 pid（使用 jps、ps 或 java -jar agent.jar 列出）\n"
                    + "4. 执行命令进行注入: java -jar /path/to/agent.jar <pid>（注入指定进程）\n"
                    + "   或 java -jar /path/to/agent.jar all（注入所有 Java 进程）\n"
                    + "5. 按基本信息中的参数连接/触发内存马";
        }
        return steps + "\n\n（「保存」按钮会将打包后的 Jar 以 .jar 文件保存）";
    }

    private void savePackResult() {
        if (current == null) return;
        try {
            if (current.isJarOutput() || current.isAgentOutput()) {
                String baseName = current.getMemShellResult().getShellConfig().getServer()
                        + current.getMemShellResult().getShellConfig().getShellTool()
                        + (current.isAgentOutput() ? "MemShellAgent" : "MemShell");
                FileSaveUtil.saveBase64AsBytes(this, baseName + ".jar", current.getPackResult(), "jar");
            } else if (current.isMultiResult()) {
                Object item = aggregateCombo.getSelectedItem();
                String entry = item == null ? "entry" : String.valueOf(item);
                FileSaveUtil.saveText(this, current.getPackMethod() + "-" + entry + ".txt", packResultArea.getText());
            } else {
                FileSaveUtil.saveText(this, current.getPackMethod() + ".txt", packResultArea.getText());
            }
        } catch (Exception ex) {
            SwingUiUtil.showError(this, "保存失败: " + ex.getMessage());
        }
    }

    private static String simpleClassFileName(String className) {
        if (className == null || className.trim().isEmpty()) return "output.class";
        int idx = className.lastIndexOf('.');
        return (idx >= 0 ? className.substring(idx + 1) : className) + ".class";
    }
}
