package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.GenerationService;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import com.reajason.javaweb.packer.Packers;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JRootPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.GraphicsEnvironment;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * CFR 反编译工具的布局与流程冒烟：内容可内嵌、快捷键可交给宿主窗口、
 * 粘贴 Base64 后自动反编译出源码。需要显示环境（与生成器 frame 同款：headless 跳过，不安装 FlatLaf）。
 */
class DecompileFrameLayoutTest {

    private static byte[] classBytes;
    private static String className;

    @BeforeAll
    static void generateClassBytes() {
        DesktopMemShellGenerateResult result = new GenerationService().generate(baseState());
        className = result.getMemShellResult().getShellClassName();
        classBytes = Base64.getDecoder().decode(result.getMemShellResult().getShellBytesBase64Str());
    }

    @Test
    void frameStructureIsAsExpected() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final DecompileFrame[] frameHolder = new DecompileFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frameHolder[0] = new DecompileFrame();
            }
        });
        final DecompileFrame frame = frameHolder[0];
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    JPanel content = frame.getRootPanel();
                    assertNotNull(content);
                    // 固定上下布局：输入区在 NORTH，源码区占 CENTER
                    assertTrue(content.getLayout() instanceof BorderLayout);

                    JButton decompileButton = frame.getDecompileButton();
                    assertNotNull(decompileButton);
                    assertTrue(decompileButton.isEnabled());
                    assertEquals("反编译", decompileButton.getText());
                    // 还没反编译：源码区停在空态，复制/保存不可点
                    assertFalse(requireButton(frame.getContentPane(), "复制").isEnabled());

                    // 会进忙碌态的动作按钮不参与焦点遍历（禁用时焦点才不会甩给下一个组件、被 FlatLaf 全选）
                    assertFalse(decompileButton.isFocusable(), "反编译按钮不应参与焦点遍历");
                    assertFalse(requireButton(frame.getContentPane(), "选择 .class 文件...").isFocusable(),
                            "选择文件按钮在读取期间会被禁用，不应参与焦点遍历");
                    assertFalse(requireButton(frame.getContentPane(), "复制").isFocusable(),
                            "复制按钮会被 copyWithFeedback 短暂禁用，不应参与焦点遍历");
                }
            });
        } finally {
            dispose(frame);
        }
    }

    @Test
    void embeddedFrameInstallsShortcutOnHostRootPane() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final DecompileFrame[] frameHolder = new DecompileFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frameHolder[0] = new DecompileFrame(false);
            }
        });
        final DecompileFrame frame = frameHolder[0];
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    JRootPane hostRootPane = new JRootPane();
                    frame.installDecompileShortcut(hostRootPane);
                    assertNotNull(hostRootPane.getActionMap().get("decompileClass"),
                            "Ctrl/⌘ + Enter 应当挂到宿主窗口上");
                    assertEquals(frame.getDecompileButton(), hostRootPane.getDefaultButton());

                    frame.uninstallDecompileShortcut(hostRootPane);
                    assertNull(hostRootPane.getActionMap().get("decompileClass"));
                    assertNull(hostRootPane.getDefaultButton());

                    frame.installDecompileShortcut(null);
                    frame.uninstallDecompileShortcut(null);
                }
            });
        } finally {
            dispose(frame);
        }
    }

    /**
     * 粘贴 Base64 后不用点按钮：去抖到期自动反编译，源码出现在结果区，状态出口收到成功消息。
     */
    @Test
    void pastedBase64IsDecompiledAutomatically() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final List<String> reported = new ArrayList<String>();
        final DecompileFrame[] frameHolder = new DecompileFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frameHolder[0] = new DecompileFrame(false);
                frameHolder[0].setStatusReporter(new StatusReporter() {
                    @Override
                    public void report(String message, StatusReporter.Level level) {
                        reported.add(level + ":" + message);
                    }
                });
                frameHolder[0].setBase64Input(Base64.getEncoder().encodeToString(classBytes));
            }
        });
        final DecompileFrame frame = frameHolder[0];
        try {
            // 等真正的源码（"class Xxx"），占位文本 "// 正在使用 CFR 反编译 Xxx ..." 也含类名，不能当完成信号
            final String sourceMarker = "class " + simpleName(className);
            awaitOnEdt(new Callable<Boolean>() {
                @Override
                public Boolean call() {
                    return findTextAreaContaining(frame.getContentPane(), sourceMarker) != null;
                }
            });

            String source = findTextAreaContaining(frame.getContentPane(), sourceMarker).getText();
            assertTrue(source.contains(sourceMarker), source);
            assertFalse(source.startsWith("//"), "展示的应当是反编译源码而不是占位文本");
            assertTrue(reported.toString().contains("SUCCESS:反编译成功"), reported.toString());
        } finally {
            dispose(frame);
        }
    }

    /**
     * 反编译失败（输入不是 class 字节）时给红色提示，源码区不留"正在反编译"的假象。
     */
    @Test
    void invalidInputIsReportedWithoutTouchingResult() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final DecompileFrame[] frameHolder = new DecompileFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frameHolder[0] = new DecompileFrame(false);
            }
        });
        final DecompileFrame frame = frameHolder[0];
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    frame.setBase64Input("这不是 Base64 文本");
                    frame.triggerDecompile();
                }
            });
            // 输入无法识别：不抛异常、不启动反编译，源码区仍在空态
            assertNull(findTextAreaContaining(frame.getContentPane(), className));
            assertFalse(requireButton(frame.getContentPane(), "复制").isEnabled());
        } finally {
            dispose(frame);
        }
    }

    private static void dispose(final DecompileFrame frame) throws Exception {
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frame.dispose();
            }
        });
    }

    /**
     * 在 EDT 上求值条件，轮询等待：反编译在后台线程跑，测试只能等（超时即失败并打印已知状态）。
     */
    private static void awaitOnEdt(final Callable<Boolean> condition) throws Exception {
        long deadline = System.currentTimeMillis() + 60_000;
        while (true) {
            final boolean[] satisfied = new boolean[1];
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    try {
                        satisfied[0] = condition.call();
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                }
            });
            if (satisfied[0]) {
                return;
            }
            if (System.currentTimeMillis() > deadline) {
                fail("等待反编译结果超时");
            }
            Thread.sleep(50);
        }
    }

    private static String simpleName(String className) {
        return className.substring(className.lastIndexOf('.') + 1);
    }

    /**
     * 深度优先找含指定文本的多行输入框（base64 字母表里没有空格，能按类名把源码区与输入区分开）。
     */
    private static JTextArea findTextAreaContaining(Container root, String needle) {
        for (Component child : root.getComponents()) {
            if (child instanceof JTextArea && ((JTextArea) child).getText().contains(needle)) {
                return (JTextArea) child;
            }
            if (child instanceof Container) {
                JTextArea found = findTextAreaContaining((Container) child, needle);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    /**
     * 深度优先找指定文案的按钮；找不到返回 null（不能在这里抛：会中断兄弟子树的遍历）。
     */
    private static JButton findButton(Container root, String text) {
        for (Component child : root.getComponents()) {
            if (child instanceof JButton && text.equals(((JButton) child).getText())) {
                return (JButton) child;
            }
            if (child instanceof Container) {
                JButton found = findButton((Container) child, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static JButton requireButton(Container root, String text) {
        JButton button = findButton(root, text);
        assertNotNull(button, "找不到按钮：" + text);
        return button;
    }

    private static MemShellFormState baseState() {
        MemShellFormState s = new MemShellFormState();
        s.setServer("Tomcat");
        s.setServerVersion("Unknown");
        s.setShellTool("Godzilla");
        s.setShellType("Listener");
        s.setPackingMethod(Packers.DefaultBase64);
        return s;
    }
}
