package com.reajason.javaweb.desktop.memshell.ui.panel;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.util.ClipboardUtil;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.AntSwordConfig;
import com.reajason.javaweb.memshell.config.BehinderConfig;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.CustomConfig;
import com.reajason.javaweb.memshell.config.GodzillaConfig;
import com.reajason.javaweb.memshell.config.NeoreGeorgConfig;
import com.reajason.javaweb.memshell.config.ProxyConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.config.Suo5Config;
import net.miginfocom.swing.MigLayout;

import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Cursor;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

/**
 * 生成结果基本信息：摘要行（label: value 对），值可点击复制。
 * 行集对齐 web basic-info.tsx。
 */
public class BasicInfoPanel extends JPanel {
    private final JPanel content = new JPanel(new MigLayout("insets 0, fillx, gapx 10, gapy 2, wrap 2", "[right]6[grow,fill]", "[]"));

    public BasicInfoPanel() {
        setLayout(new MigLayout("insets 0, fillx", "[grow,fill]", "[]"));
        add(content, "growx, wrap");
    }

    public void clear() {
        content.removeAll();
        content.revalidate();
        content.repaint();
    }

    public void setResult(DesktopMemShellGenerateResult result) {
        content.removeAll();
        MemShellResult r = result.getMemShellResult();
        ShellConfig shellConfig = r.getShellConfig();
        ShellToolConfig toolConfig = r.getShellToolConfig();

        // 服务类型/工具/挂载类型/urlPattern 即上方表单所填项，不重复展示；
        // 只展示生成后才知道的值（随机密码/密钥、派生加密器、实际类名与大小等）
        appendToolRows(shellConfig, toolConfig);

        row("注入器类名", r.getInjectorClassName() + " (" + r.getInjectorSize() + " bytes)", r.getInjectorClassName());
        row("内存马类名", r.getShellClassName() + " (" + r.getShellSize() + " bytes)", r.getShellClassName());
        content.revalidate();
        content.repaint();
    }

    private void appendToolRows(ShellConfig shellConfig, ShellToolConfig toolConfig) {
        if (toolConfig == null) {
            return;
        }
        String shellType = shellConfig == null ? "" : shellConfig.getShellType();
        if (toolConfig instanceof GodzillaConfig) {
            GodzillaConfig c = (GodzillaConfig) toolConfig;
            row("密码", c.getPass());
            row("密钥", c.getKey());
            row("加密器", deriveGodzillaEncryptor(shellType));
            row("请求头", c.getHeaderName() + ": " + c.getHeaderValue());
        } else if (toolConfig instanceof BehinderConfig) {
            BehinderConfig c = (BehinderConfig) toolConfig;
            row("密码", c.getPass());
            row("请求头", c.getHeaderName() + ": " + c.getHeaderValue());
        } else if (toolConfig instanceof CommandConfig) {
            CommandConfig c = (CommandConfig) toolConfig;
            if (shellType == null || !shellType.contains("WebSocket")) {
                row("参数名", c.getParamName());
            }
            if ("BypassNginxWebSocket".equals(shellType) || "BypassNginxJakartaWebSocket".equals(shellType)) {
                row("请求头", c.getHeaderName() + ": " + c.getHeaderValue());
            }
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
            // 展示截断、复制取完整值（两参 row 会把截断废串复制出去）
            row("自定义类(Base64)", v == null ? "" : (v.length() > 64 ? v.substring(0, 64) + "..." : v), v);
        }
    }

    /**
     * 对齐 web basic-info 的 Godzilla 派生加密器展示。
     */
    private static String deriveGodzillaEncryptor(String shellType) {
        if (shellType != null && shellType.contains("WebSocket")) {
            return "JAVA_WEBSOCKET_AES_RAW";
        }
        if (shellType != null && shellType.contains("Dubbo")) {
            return "DUBBO_XOR_BASE64";
        }
        return "JAVA_AES_BASE64";
    }

    private void row(String key, String value) {
        row(key, value, value);
    }

    /**
     * displayValue 用于展示，copyValue 用于点击复制（如类名行展示带大小、复制只取类名）。
     */
    private void row(String key, String displayValue, String copyValue) {
        String text = displayValue == null ? "" : displayValue;
        final String copyText = copyValue == null ? "" : copyValue;
        content.add(new JLabel(key + ":"));
        final JLabel valueLabel = new JLabel(text);
        valueLabel.setToolTipText(text + "（点击复制）");
        valueLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        valueLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                ClipboardUtil.copyText(copyText);
                SwingUiUtil.flashLabel(valueLabel, SwingUiUtil.successColor());
            }
        });
        content.add(valueLabel, "growx, wrap");
    }
}
