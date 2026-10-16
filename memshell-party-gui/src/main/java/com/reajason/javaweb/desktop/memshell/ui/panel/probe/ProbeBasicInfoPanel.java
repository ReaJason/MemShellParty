package com.reajason.javaweb.desktop.memshell.ui.panel.probe;

import com.reajason.javaweb.desktop.memshell.model.DesktopProbeShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.DnsLogConfig;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import com.reajason.javaweb.probe.config.ResponseBodyConfig;
import com.reajason.javaweb.probe.config.SleepConfig;
import net.miginfocom.swing.MigLayout;

import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Cursor;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * 探测马生成结果基本信息：摘要行（label: value 对），值可点击复制。
 * 行集对齐 web probeshell/basic-info.tsx：表单已填项不重复展示，只展示生成后才知道的值。
 */
public class ProbeBasicInfoPanel extends JPanel {
    private final JPanel content = new JPanel(new MigLayout("insets 0, fillx, gapx 10, gapy 2, wrap 2", "[right]6[grow,fill]", "[]"));

    public ProbeBasicInfoPanel() {
        setLayout(new MigLayout("insets 0, fillx", "[grow,fill]", "[]"));
        add(content, "growx, wrap");
    }

    public void clear() {
        content.removeAll();
        content.revalidate();
        content.repaint();
    }

    public void setResult(DesktopProbeShellGenerateResult result) {
        content.removeAll();
        ProbeShellResult r = result.getProbeShellResult();
        ProbeConfig probeConfig = r.getProbeConfig();
        ProbeContentConfig contentConfig = r.getProbeContentConfig();

        if (probeConfig != null) {
            row("探测方式", probeConfig.getProbeMethod() == null ? "" : probeConfig.getProbeMethod().name());
            row("探测内容", probeConfig.getProbeContent() == null ? "" : probeConfig.getProbeContent().name());
        }
        // 参数名为生成期随机值（用户留空时），属于"生成后才知道"的展示项
        if (contentConfig instanceof ResponseBodyConfig) {
            ResponseBodyConfig c = (ResponseBodyConfig) contentConfig;
            row("目标服务", c.getServer());
            row("参数名", c.getReqParamName());
            if (c.getCommandTemplate() != null) {
                row("命令模板", c.getCommandTemplate());
            }
        } else if (contentConfig instanceof DnsLogConfig) {
            row("DNSLog 域名", ((DnsLogConfig) contentConfig).getHost());
        } else if (contentConfig instanceof SleepConfig) {
            SleepConfig c = (SleepConfig) contentConfig;
            row("休眠服务", c.getServer());
            row("休眠秒数", String.valueOf(c.getSeconds()));
        }
        row("探测马类名", r.getShellClassName() + " (" + r.getShellSize() + " bytes)", r.getShellClassName());
        content.revalidate();
        content.repaint();
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
                SwingUiUtil.copyLabelWithFeedback(valueLabel, copyText);
            }
        });
        content.add(valueLabel, "growx, wrap");
    }
}
