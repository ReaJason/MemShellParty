package com.reajason.javaweb.desktop.memshell.ui.panel;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.packer.Packers;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 窄窗口适配：结果区的最小宽度必须保持很小，否则宿主窗口一窄，整块内容按最小宽度布局，
 * 右侧的注入/复制/保存按钮会被顶出窗口（所见即窗口外的部分被裁掉）。
 *
 * <p>最容易复发的是空态提示：HTML {@code JLabel} 的最小宽度等于首选宽度（约 1000px），
 * 而空态卡片和结果卡片叠在同一个 {@code CardLayout} 里，容器最小宽取所有卡片的较大值——
 * 即使已经生成、显示的是结果卡片，隐藏的空态卡片仍会把结果区撑宽。
 */
class ResultPanelNarrowLayoutTest {

    @Test
    void minimumWidthStaysSmallInEmptyAndGeneratedStates() throws Exception {
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                ResultPanel panel = new ResultPanel();
                assertTrue(panel.getMinimumSize().width < 600,
                        "空态不能把结果区最小宽度撑大：" + panel.getMinimumSize());

                panel.showResult(longNamesResult());
                assertTrue(panel.getMinimumSize().width < 600,
                        "生成后也不能把结果区最小宽度撑大：" + panel.getMinimumSize());
            }
        });
    }

    private static DesktopMemShellGenerateResult longNamesResult() {
        // 长 Base64 内容：展示层按组件宽度插显式换行（文本区不换行防 macOS 字形缓存污染），
        // 最小宽度必须由文本区列数锚定而不是内容宽度
        StringBuilder base64 = new StringBuilder();
        for (int i = 0; i < 8000; i++) {
            base64.append("yv66vgA=");
        }
        MemShellResult result = MemShellResult.builder()
                .shellClassName("org.apache.web.handlers.sessiondecoder.CompositeNodeStickinessListener")
                .helperClassName("org.apache.web.handlers.sessiondecoder.CompositeNodeStickinessListener$RawWsHelper")
                .injectorClassName("com.google.gson.platform.internal.writethrough.ExtensionAwaitingUtils")
                .shellBytesBase64Str(base64.toString())
                .helperBytesBase64Str(base64.toString())
                .injectorBytesBase64Str(base64.toString())
                .build();
        return new DesktopMemShellGenerateResult(result, Packers.DefaultBase64, base64.toString());
    }
}
