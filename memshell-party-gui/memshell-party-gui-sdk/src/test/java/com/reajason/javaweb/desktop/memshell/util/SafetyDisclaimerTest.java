package com.reajason.javaweb.desktop.memshell.util;

import org.junit.jupiter.api.Test;

import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Component;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * 安全使用声明条：单行文案要在、整条不参与焦点遍历（纯组件测试，无需显示环境）。
 */
class SafetyDisclaimerTest {

    @Test
    void bannerShowsTheDisclaimerLineAndNeverTakesFocus() {
        JPanel banner = SafetyDisclaimer.createBanner();

        Component child = banner.getComponent(0);
        assertEquals(SafetyDisclaimer.TEXT, ((JLabel) child).getText());
        assertEquals(SwingUiUtil.errorColor(), ((JLabel) child).getForeground(),
                "声明文案应当用错误语义色（醒目）");
        assertFalse(child.isFocusable(), "声明文案不应进入 Tab 序");
        assertFalse(banner.isFocusable(), "声明条本身不应进入 Tab 序");
    }
}
