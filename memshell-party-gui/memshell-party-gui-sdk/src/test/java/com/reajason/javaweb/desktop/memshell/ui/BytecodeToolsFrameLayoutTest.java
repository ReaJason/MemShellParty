package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.service.ClassBytesDecoder;
import com.reajason.javaweb.desktop.memshell.service.fixtures.TriggerTarget;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JRootPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.GraphicsEnvironment;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * 字节码工具界面的布局与流程冒烟：内嵌、快捷键移交、粘贴后自动生成；
 * 切换工具后随机改名生效，输出格式切换到 GzipBase64 后文本确实压缩，源码视图可来回切换。
 */
class BytecodeToolsFrameLayoutTest {

    @Test
    void frameStructureIsAsExpected() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final BytecodeToolsFrame[] holder = new BytecodeToolsFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                holder[0] = new BytecodeToolsFrame(false);
            }
        });
        final BytecodeToolsFrame frame = holder[0];
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    JPanel content = frame.getRootPanel();
                    assertNotNull(content);
                    // 上下布局：输入 / 选项 / 结果三段纵向堆叠
                    assertTrue(content.getLayout() instanceof net.miginfocom.swing.MigLayout);

                    JButton transform = frame.getTransformButton();
                    assertEquals("生成 Base64", transform.getText());
                    assertTrue(transform.isEnabled());
                    assertFalse(transform.isFocusable(), "主操作按钮不应参与焦点遍历");

                    // 空输入：复制 / 下载 / 源码切换均不可用
                    assertFalse(requireButtonByText(content, "复制 Base64").isEnabled());
                    assertFalse(requireButtonByText(content, "下载 .class").isEnabled());
                    assertFalse(requireButtonByTooltip(content, "在 Base64 与 CFR 反编译源码之间切换").isEnabled());
                    assertFalse(requireButtonByTooltip(content, "反编译当前输入类，弹窗查看源码").isEnabled());
                }
            });
        } finally {
            dispose(frame);
        }
    }

    @Test
    void embeddedFrameInstallsShortcutOnHostRootPane() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final BytecodeToolsFrame[] holder = new BytecodeToolsFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                holder[0] = new BytecodeToolsFrame(false);
            }
        });
        final BytecodeToolsFrame frame = holder[0];
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    JRootPane hostRootPane = new JRootPane();
                    frame.installTransformShortcut(hostRootPane);
                    assertNotNull(hostRootPane.getActionMap().get("bytecodeTransform"));
                    assertEquals(frame.getTransformButton(), hostRootPane.getDefaultButton());

                    frame.uninstallTransformShortcut(hostRootPane);
                    assertNull(hostRootPane.getActionMap().get("bytecodeTransform"));
                    assertNull(hostRootPane.getDefaultButton());

                    frame.installTransformShortcut(null);
                    frame.uninstallTransformShortcut(null);
                }
            });
        } finally {
            dispose(frame);
        }
    }

    @Test
    void pastedBase64IsTransformedAutomatically() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final byte[] fixtureBytes = bytesOf(TriggerTarget.class);
        final String inputBase64 = Base64.getEncoder().encodeToString(fixtureBytes);
        final List<String> reported = new ArrayList<String>();
        final BytecodeToolsFrame[] holder = new BytecodeToolsFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                holder[0] = new BytecodeToolsFrame(false);
                holder[0].setStatusReporter(new StatusReporter() {
                    @Override
                    public void report(String message, StatusReporter.Level level) {
                        reported.add(level + ":" + message);
                    }
                });
                holder[0].setBase64Input(inputBase64);
            }
        });
        final BytecodeToolsFrame frame = holder[0];
        try {
            // 去抖到期后自动转换：结果区和输入一样是原 Base64（转换工具不做改写）
            awaitOnEdt(new Callable<Boolean>() {
                @Override
                public Boolean call() {
                    JTextArea output = readOnlyTextArea(frame.getRootPanel());
                    return output != null && inputBase64.equals(output.getText());
                }
            });
            assertTrue(reported.toString().contains("SUCCESS:转换成功"), reported.toString());
            assertTrue(requireButtonByText(frame.getRootPanel(), "复制 Base64").isEnabled());
            assertTrue(requireButtonByText(frame.getRootPanel(), "下载 .class").isEnabled());
            // Base64 不能开换行：字符级断行会触发 macOS 字形缓存污染（整窗拉丁字形随机丢失）
            assertFalse(readOnlyTextArea(frame.getRootPanel()).getLineWrap(),
                    "Base64 输出应横向滚动而不是换行");

            // 切到「随机类名与瘦身」：类名改变，输出不再是原 Base64
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    toolCombo(frame.getRootPanel()).setSelectedIndex(BytecodeToolsFrame.TOOL_RENAME_SHRINK);
                }
            });
            awaitOnEdt(new Callable<Boolean>() {
                @Override
                public Boolean call() {
                    JTextArea output = readOnlyTextArea(frame.getRootPanel());
                    return output != null && !inputBase64.equals(output.getText());
                }
            });
            byte[] renamed = new ClassBytesDecoder().decodeBase64(
                    readOnlyTextArea(frame.getRootPanel()).getText()).getClassBytes();
            String renamedClassName = new ClassReader(renamed).getClassName().replace('/', '.');
            assertNotEquals(TriggerTarget.class.getName(), renamedClassName);
            assertTrue(renamedClassName.startsWith(TriggerTarget.class.getPackage().getName() + "."),
                    "未指定新包名时应保留原包名：" + renamedClassName);
            assertFalse(hasSourceFile(renamed), "默认应清除 SourceFile");

            // 输出格式切到 GzipBase64：只重新编码，不重跑改名
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    formatCombo(frame.getRootPanel()).setSelectedItem("GzipBase64");
                }
            });
            ClassBytesDecoder.DecodedClass gzipped = new ClassBytesDecoder().decodeBase64(
                    readOnlyTextArea(frame.getRootPanel()).getText());
            assertTrue(gzipped.isGzipped());
            assertEquals(renamedClassName, gzipped.getClassName());
            final String gzippedText = readOnlyTextArea(frame.getRootPanel()).getText();

            // 输出区源码视图：CFR 反编译后展示 Java 源码，切回 Base64 恢复原文
            final String sourceMarker = "class " + renamedClassName.substring(renamedClassName.lastIndexOf('.') + 1);
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    requireButtonByTooltip(frame.getRootPanel(), "在 Base64 与 CFR 反编译源码之间切换").doClick();
                }
            });
            awaitOnEdt(new Callable<Boolean>() {
                @Override
                public Boolean call() {
                    return readOnlyTextArea(frame.getRootPanel()).getText().contains(sourceMarker);
                }
            });
            assertFalse(readOnlyTextArea(frame.getRootPanel()).getText().startsWith("//"),
                    "展示的应当是反编译源码而不是占位文本");
            // 源码有空格/换行，可以安全换行；切回 Base64 必须恢复不换行
            assertTrue(readOnlyTextArea(frame.getRootPanel()).getLineWrap(), "源码视图应换行");
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    requireButtonByTooltip(frame.getRootPanel(), "在 Base64 与 CFR 反编译源码之间切换").doClick();
                }
            });
            awaitOnEdt(new Callable<Boolean>() {
                @Override
                public Boolean call() {
                    JTextArea output = readOnlyTextArea(frame.getRootPanel());
                    return output != null && gzippedText.equals(output.getText());
                }
            });
            assertFalse(readOnlyTextArea(frame.getRootPanel()).getLineWrap(), "切回 Base64 后应恢复不换行");
        } finally {
            dispose(frame);
        }
    }

    private static void dispose(final BytecodeToolsFrame frame) throws Exception {
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                frame.dispose();
            }
        });
    }

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
                fail("等待字节码工具结果超时");
            }
            Thread.sleep(50);
        }
    }

    private static byte[] bytesOf(Class<?> type) throws Exception {
        String resource = type.getSimpleName() + ".class";
        InputStream in = type.getResourceAsStream(resource);
        assertNotNull(in);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    private static boolean hasSourceFile(byte[] classBytes) {
        final boolean[] found = {false};
        new ClassReader(classBytes).accept(new org.objectweb.asm.ClassVisitor(org.objectweb.asm.Opcodes.ASM9) {
            @Override
            public void visitSource(String source, String debug) {
                found[0] = true;
            }
        }, 0);
        return found[0];
    }

    private static JComboBox<?> toolCombo(Container root) {
        JComboBox<?> combo = findComboByFirstItem(root, "转换格式");
        assertNotNull(combo, "找不到工具下拉框");
        return combo;
    }

    private static JComboBox<?> formatCombo(Container root) {
        JComboBox<?> combo = findComboByFirstItem(root, "Base64");
        assertNotNull(combo, "找不到输出格式下拉框");
        return combo;
    }

    private static JComboBox<?> findComboByFirstItem(Container root, String item) {
        for (Component child : root.getComponents()) {
            if (child instanceof JComboBox && ((JComboBox<?>) child).getItemCount() > 0
                    && item.equals(String.valueOf(((JComboBox<?>) child).getItemAt(0)))) {
                return (JComboBox<?>) child;
            }
            if (child instanceof Container) {
                JComboBox<?> found = findComboByFirstItem((Container) child, item);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static JTextArea readOnlyTextArea(Container root) {
        for (Component child : root.getComponents()) {
            if (child instanceof JTextArea && !((JTextArea) child).isEditable()) {
                return (JTextArea) child;
            }
            if (child instanceof Container) {
                JTextArea found = readOnlyTextArea((Container) child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static JButton requireButtonByText(Container root, String text) {
        JButton button = findButtonByText(root, text);
        assertNotNull(button, "找不到按钮：" + text);
        return button;
    }

    private static JButton requireButtonByTooltip(Container root, String tooltip) {
        JButton button = findButtonByTooltip(root, tooltip);
        assertNotNull(button, "找不到按钮：" + tooltip);
        return button;
    }

    /**
     * 深度优先找指定文案的按钮；找不到返回 null（不能在这里 fail：会中断兄弟子树的遍历）。
     */
    private static JButton findButtonByText(Container root, String text) {
        for (Component child : root.getComponents()) {
            if (child instanceof JButton && text.equals(((JButton) child).getText())) {
                return (JButton) child;
            }
            if (child instanceof Container) {
                JButton found = findButtonByText((Container) child, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static JButton findButtonByTooltip(Container root, String tooltip) {
        for (Component child : root.getComponents()) {
            if (child instanceof JButton && tooltip.equals(((JButton) child).getToolTipText())) {
                return (JButton) child;
            }
            if (child instanceof Container) {
                JButton found = findButtonByTooltip((Container) child, tooltip);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
