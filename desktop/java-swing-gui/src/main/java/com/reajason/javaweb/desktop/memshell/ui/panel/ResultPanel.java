package com.reajason.javaweb.desktop.memshell.ui.panel;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.util.ClipboardUtil;
import com.reajason.javaweb.desktop.memshell.util.FileSaveUtil;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.config.*;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.io.IOException;

public class ResultPanel extends JPanel {
    private final JTabbedPane tabs = new JTabbedPane();
    private final BasicInfoView basicInfoView = new BasicInfoView();
    private final JTextArea packResultArea = createTextArea();
    private final JTextArea shellArea = createTextArea();
    private final JTextArea injectorArea = createTextArea();
    private final JLabel packHeaderLabel = new JLabel("未生成");
    private DesktopMemShellGenerateResult current;

    public ResultPanel() {
        super(new BorderLayout());

        JPanel packTab = new JPanel(new MigLayout("insets 6, fill, wrap 1", "[grow,fill]", "[][grow]"));
        packTab.add(wrapBasicInfoPanel(), "growx");
        packTab.add(wrapPackResultPanel(), "grow, push");

        tabs.addTab("生成结果", packTab);
        tabs.addTab("内存马", wrapBase64Panel("内存马类字节(Base64)", shellArea, true, true));
        tabs.addTab("注入器", wrapBase64Panel("注入器类字节(Base64)", injectorArea, false, true));
        add(tabs, BorderLayout.CENTER);
    }

    private JPanel wrapBasicInfoPanel() {
        JPanel p = new JPanel(new BorderLayout());
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        top.add(new JLabel("基本信息"));

        Border cardBorder = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor") == null ? Color.LIGHT_GRAY : UIManager.getColor("Component.borderColor")),
                BorderFactory.createEmptyBorder(6, 6, 6, 6)
        );
        p.setBorder(cardBorder);
        p.add(top, BorderLayout.NORTH);
        p.add(basicInfoView, BorderLayout.CENTER);
        return p;
    }

    private JPanel wrapPackResultPanel() {
        JPanel p = new JPanel(new BorderLayout());
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        JButton copyBtn = new JButton("复制");
        JButton saveBtn = new JButton("保存");
        copyBtn.addActionListener(e -> ClipboardUtil.copyText(packResultArea.getText()));
        saveBtn.addActionListener(e -> savePackResult());
        top.add(new JLabel("打包结果"));
        top.add(packHeaderLabel);
        top.add(copyBtn);
        top.add(saveBtn);
        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(packResultArea), BorderLayout.CENTER);
        return p;
    }

    private JPanel wrapBase64Panel(String title, JTextArea area, boolean shell, boolean saveClass) {
        JPanel p = new JPanel(new BorderLayout());
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        JButton copyBtn = new JButton("复制");
        JButton saveBtn = new JButton(saveClass ? "保存 .class" : "保存");
        copyBtn.addActionListener(e -> ClipboardUtil.copyText(area.getText()));
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
        top.add(new JLabel(title));
        top.add(copyBtn);
        top.add(saveBtn);
        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(area), BorderLayout.CENTER);
        return p;
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
        basicInfoView.setResult(result);
        packHeaderLabel.setText(result.getPackMethod() + (result.getPackResult() == null ? "" : " (" + result.getPackResult().length() + ")"));
        if (result.isJarOutput() || result.isAgentOutput()) {
            packResultArea.setText(buildUsageText(result));
        } else {
            packResultArea.setText(result.getPackResult());
        }
        shellArea.setText(r.getShellBytesBase64Str());
        injectorArea.setText(r.getInjectorBytesBase64Str());
    }

    public void clear() {
        current = null;
        basicInfoView.clear();
        packResultArea.setText("");
        shellArea.setText("");
        injectorArea.setText("");
        packHeaderLabel.setText("未生成");
    }

    private String buildUsageText(DesktopMemShellGenerateResult result) {
        if (result.isAgentOutput()) {
            return "1. 点击保存导出 Agent Jar\n2. 上传到目标机器\n3. 使用 jattach/attach 方式加载\n4. 按生成配置尝试连接/触发\n\n(下方“保存”按钮会保存打包后的 Jar)";
        }
        return "1. 点击保存导出 Jar\n2. 按目标环境触发类加载\n3. 使用基本信息中的参数连接内存马\n\n(下方“保存”按钮会保存打包后的 Jar)";
    }

    private void savePackResult() {
        if (current == null) return;
        try {
            if (current.isJarOutput() || current.isAgentOutput()) {
                String baseName = current.getMemShellResult().getShellConfig().getServer() + current.getMemShellResult().getShellConfig().getShellTool() + (current.isAgentOutput() ? "MemShellAgent" : "MemShell");
                FileSaveUtil.saveBase64AsBytes(this, baseName + ".jar", current.getPackResult(), "jar");
            } else {
                FileSaveUtil.saveText(this, current.getPackMethod() + ".txt", current.getPackResult());
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

    public JComponent getBasicInfoComponent() {
        return basicInfoView;
    }

    static final class BasicInfoView extends JPanel {
        private final JPanel content = new JPanel(new MigLayout("insets 0, fillx, gapx 10, gapy 2, wrap 2", "[right]10[grow,fill]", "[]"));

        BasicInfoView() {
            super(new BorderLayout());
            add(content, BorderLayout.CENTER);
            clear();
        }

        void clear() {
            content.removeAll();
            content.revalidate();
            content.repaint();
        }

        void setResult(DesktopMemShellGenerateResult result) {
            content.removeAll();
            MemShellResult r = result.getMemShellResult();
            ShellConfig shellConfig = r.getShellConfig();
            ShellToolConfig toolConfig = r.getShellToolConfig();
            appendToolRows(shellConfig, toolConfig);
            row("注入器类名", r.getInjectorClassName() + " (" + r.getInjectorSize() + " bytes)");
            row("内存马类名", r.getShellClassName() + " (" + r.getShellSize() + " bytes)");
            content.revalidate();
            content.repaint();
        }

        private void appendToolRows(ShellConfig shellConfig, ShellToolConfig toolConfig) {
            if (toolConfig == null) {
                row("参数", "无");
                return;
            }
            String tool = shellConfig == null ? null : shellConfig.getShellTool();
            if (toolConfig instanceof GodzillaConfig) {
                GodzillaConfig c = (GodzillaConfig) toolConfig;
                row("密码", c.getPass());
                row("密钥", c.getKey());
                row("请求头", c.getHeaderName() + ": " + c.getHeaderValue());
            } else if (toolConfig instanceof BehinderConfig) {
                BehinderConfig c = (BehinderConfig) toolConfig;
                row("密码", c.getPass());
                row("请求头", c.getHeaderName() + ": " + c.getHeaderValue());
            } else if (toolConfig instanceof CommandConfig) {
                CommandConfig c = (CommandConfig) toolConfig;
                row("参数名", c.getParamName());
                row("请求头", c.getHeaderName() + ": " + c.getHeaderValue());
                row("加密器", c.getEncryptor() == null ? "" : c.getEncryptor().name());
                row("实现类", c.getImplementationClass() == null ? "" : c.getImplementationClass().name());
                if (c.getTemplate() != null) {
                    row("命令模板", c.getTemplate());
                }
            } else if (toolConfig instanceof AntSwordConfig) {
                AntSwordConfig c = (AntSwordConfig) toolConfig;
                row("密码", c.getPass());
                row("请求头", c.getHeaderName() + ": " + c.getHeaderValue());
            } else if (toolConfig instanceof Suo5Config) {
                Suo5Config c = (Suo5Config) toolConfig;
                row("请求头", c.getHeaderName() + ": " + c.getHeaderValue());
            } else if (toolConfig instanceof ProxyConfig) {
                ProxyConfig c = (ProxyConfig) toolConfig;
                row("请求头", c.getHeaderName() + ": " + c.getHeaderValue());
            } else if (toolConfig instanceof NeoreGeorgConfig) {
                NeoreGeorgConfig c = (NeoreGeorgConfig) toolConfig;
                row("请求头", c.getHeaderName() + ": " + c.getHeaderValue());
            } else if (toolConfig instanceof CustomConfig) {
                CustomConfig c = (CustomConfig) toolConfig;
                String v = c.getShellClassBase64();
                row("自定义类(Base64)", v == null ? "" : (v.length() > 32 ? v.substring(0, 32) + "..." : v));
            } else if (tool != null) {
                row("工具类型", tool);
            }
        }

        private void row(String key, String value) {
            addValueRow(key, value);
        }

        private void addValueRow(String key, String value) {
            String text = value == null ? "" : value;
            content.add(new JLabel(key));
            JTextField tf = new JTextField(text);
            tf.setEditable(false);
            tf.setBorder(BorderFactory.createEmptyBorder(1, 4, 1, 4));
            tf.setOpaque(true);
            tf.setBackground(UIManager.getColor("Panel.background"));
            tf.setToolTipText(value == null ? "" : value);
            tf.setToolTipText(text);
            content.add(tf, "growx, wrap");
        }
    }
}
