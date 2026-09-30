package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.util.AppVersion;
import com.reajason.javaweb.desktop.memshell.util.ClipboardUtil;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import net.miginfocom.swing.MigLayout;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.UIManager;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Font;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;

/**
 * 关于弹窗：应用名 / 版本 / 简介 / 作者 / 项目地址 / 许可证。
 * 项目地址点击后尝试打开浏览器，失败则复制到剪贴板兜底；Esc / 关闭按钮仅隐藏，实例可复用。
 */
public class AboutDialog extends JDialog {
    private static final String PROJECT_URL = "https://github.com/ReaJason/MemShellParty";
    private static final Color FALLBACK_LINK = new Color(0x2A, 0x65, 0xB8);

    public AboutDialog(Window owner) {
        super(owner, "关于 MemShellParty", ModalityType.APPLICATION_MODAL);
        setDefaultCloseOperation(HIDE_ON_CLOSE);
        setResizable(false);

        JLabel titleLabel = new JLabel("MemShellParty");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 20f));
        JLabel versionLabel = mutedLabel("版本 v" + AppVersion.get());
        JLabel descLabel = new JLabel("专注于主流 Web 中间件的内存马快速生成工具");
        JLabel authorLabel = new JLabel("作者：ReaJason");
        JLabel linkLabel = createLinkLabel();
        JLabel licenseLabel = mutedLabel("MIT License · Copyright © 2024 ReaJason");

        JButton closeButton = new JButton("关闭");
        closeButton.addActionListener(e -> setVisible(false));

        JPanel content = new JPanel(new MigLayout("insets 20 28 14 28, fillx, wrap 1", "[center]", "[]2[]10[]4[]2[]14[]12[]"));
        content.add(titleLabel);
        content.add(versionLabel);
        content.add(descLabel);
        content.add(authorLabel);
        content.add(linkLabel);
        content.add(licenseLabel);
        content.add(closeButton, "align right");
        setContentPane(content);

        getRootPane().setDefaultButton(closeButton);
        bindEscape();
        pack();
    }

    /**
     * Esc 关闭：仅隐藏不销毁，菜单重复打开时复用同一实例。
     */
    private void bindEscape() {
        getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "closeAboutDialog");
        getRootPane().getActionMap().put("closeAboutDialog", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                setVisible(false);
            }
        });
    }

    /**
     * 链接样式标签：前景色走 UIManager/FlatLaf 调色板（updateUI 随主题刷新），点击打开项目主页。
     */
    private JLabel createLinkLabel() {
        JLabel linkLabel = new JLabel(PROJECT_URL) {
            @Override
            public void updateUI() {
                super.updateUI();
                Color color = UIManager.getColor("Component.linkColor");
                setForeground(color != null ? color : FALLBACK_LINK);
            }
        };
        linkLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        linkLabel.setToolTipText("在浏览器中打开项目主页");
        linkLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                openProjectPage();
            }
        });
        return linkLabel;
    }

    private void openProjectPage() {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI(PROJECT_URL));
                return;
            }
        } catch (Exception ignored) {
            // 落到复制兜底
        }
        ClipboardUtil.copyText(PROJECT_URL);
        JOptionPane.showMessageDialog(this, "无法打开浏览器，项目地址已复制到剪贴板", "提示", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * 次要信息标签：前景色随主题（updateUI 时重读调色板），暗色切换不留亮色残影。
     */
    private static JLabel mutedLabel(String text) {
        return new JLabel(text) {
            @Override
            public void updateUI() {
                super.updateUI();
                setForeground(SwingUiUtil.mutedColor());
            }
        };
    }
}
