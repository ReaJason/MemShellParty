package com.reajason.javaweb.desktop.memshell.ui.panel;

import com.reajason.javaweb.desktop.memshell.extension.ResultAction;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.memshell.MemShellResult;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 结果区扩展动作按钮：不参与焦点遍历（点击后不出现蓝色焦点框），声明了忙碌文案的动作
 * 在完成回调前保持置灰，回调后恢复。
 */
class ResultPanelExtensionActionTest {

    @Test
    void busyActionDisablesButtonUntilDoneCallback() throws Exception {
        final AtomicReference<Runnable> doneHolder = new AtomicReference<Runnable>();
        final ResultPanel[] panelHolder = new ResultPanel[1];
        final JButton[] buttonHolder = new JButton[1];

        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                ResultPanel panel = new ResultPanel();
                ResultAction action = new ResultAction() {
                    @Override
                    public String label() {
                        return "注入内存马";
                    }

                    @Override
                    public String busyLabel() {
                        return "注入中…";
                    }

                    @Override
                    public void perform(DesktopMemShellGenerateResult result) {
                        // 异步动作走带完成回调的重载
                    }

                    @Override
                    public void perform(DesktopMemShellGenerateResult result, Runnable done) {
                        doneHolder.set(done);
                    }
                };
                panel.setResultActions(Collections.singletonList(action));
                panel.showResult(sampleResult());

                JButton button = findButton(panel, "注入内存马");
                assertNotNull(button, "扩展动作按钮应当出现在结果区");
                // 点击后不留下蓝色焦点框，看着像文字被选中
                assertFalse(button.isFocusable());
                assertTrue(button.isEnabled());

                button.doClick(0);
                assertFalse(button.isEnabled(), "动作完成前按钮应保持置灰");
                assertEquals("注入中…", button.getText());

                panelHolder[0] = panel;
                buttonHolder[0] = button;
            }
        });

        assertNotNull(doneHolder.get(), "perform 必须拿到完成回调");
        doneHolder.get().run();
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                // 切回 EDT 后才恢复
            }
        });

        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                JButton button = buttonHolder[0];
                assertTrue(button.isEnabled(), "完成回调后按钮应恢复可点");
                assertEquals("注入内存马", button.getText());
                assertNotNull(panelHolder[0]);
            }
        });
    }

    private static DesktopMemShellGenerateResult sampleResult() {
        MemShellResult result = MemShellResult.builder()
                .shellClassName("com.example.Shell")
                .shellBytesBase64Str("")
                .injectorClassName("com.example.Injector")
                .injectorBytesBase64Str("")
                .build();
        return new DesktopMemShellGenerateResult(result, "Base64", "");
    }

    private static JButton findButton(Container root, String text) {
        for (Component component : root.getComponents()) {
            if (component instanceof JButton && text.equals(((JButton) component).getText())) {
                return (JButton) component;
            }
            if (component instanceof Container) {
                JButton found = findButton((Container) component, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
