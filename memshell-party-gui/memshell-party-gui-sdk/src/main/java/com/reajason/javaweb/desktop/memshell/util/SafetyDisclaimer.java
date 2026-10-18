package com.reajason.javaweb.desktop.memshell.util;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;

/**
 * 主窗口顶部常驻的安全使用声明：单行红字加粗，不随页签切换消失。
 *
 * <p>颜色走 {@link SwingUiUtil#errorColor()} 的 FlatLaf 调色板键，暗色切换到
 * {@code updateUI()} 时自动重读。发行版外壳与 Shiro 利用工具共用同一份实现。
 */
public final class SafetyDisclaimer {

    public static final String TEXT =
            "本工具仅供安全研究和已授权的渗透测试使用，未经授权的攻击行为均属违法，使用者需自行承担法律责任。";

    private SafetyDisclaimer() {
    }

    /**
     * 创建声明条（放在窗口 NORTH）：淡红底、红色底边、单行加粗红字。
     */
    public static JPanel createBanner() {
        JPanel banner = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 5)) {
            @Override
            public void updateUI() {
                super.updateUI();
                setBackground(tintColor());
                setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, SwingUiUtil.errorColor()));
            }
        };
        JLabel line = new JLabel(TEXT) {
            @Override
            public void updateUI() {
                super.updateUI();
                setForeground(SwingUiUtil.errorColor());
                Font font = getFont();
                if (font != null) {
                    setFont(font.deriveFont(Font.BOLD));
                }
            }
        };
        line.setFocusable(false);
        banner.add(line);
        banner.setFocusable(false);
        banner.setName("safetyDisclaimer");
        return banner;
    }

    /**
     * 淡红底：取错误色的 RGB 加低透明度，亮/暗主题下都能看出底色但不压住红字。
     */
    private static Color tintColor() {
        Color red = SwingUiUtil.errorColor();
        return new Color(red.getRed(), red.getGreen(), red.getBlue(), 26);
    }
}
