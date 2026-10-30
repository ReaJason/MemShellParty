package com.reajason.javaweb.desktop.memshell;

import com.reajason.javaweb.desktop.memshell.app.MemShellDesktopFrame;
import com.reajason.javaweb.memshell.PluginBootstrap;
import com.reajason.javaweb.memshell.PluginLoadResult;

/**
 * MemShellParty Swing 桌面入口（完整发行版）：安装 FlatLaf 并显示「内存马 / 探测马 / 反编译 / 字节码工具」四页窗口。
 *
 * <p>外壳与四个页面的分工见 {@link MemShellDesktopFrame}；宿主程序内嵌时不要调 {@code main}，
 * 用 {@link MemShellGui#createMemShellFrame} / {@link MemShellGui#createProbeFrame} /
 * {@link MemShellGui#createDecompileFrame} / {@link MemShellGui#createBytecodeToolsFrame}
 * 拿界面，自己排外部布局（可参照 {@code MemShellDesktopFrame} 的写法）。
 */
public class MemShellDesktopApplication {

    public static void main(String[] args) {
        PluginLoadResult plugins = PluginBootstrap.load();
        for (String warning : plugins.getWarnings()) {
            System.err.println("插件加载警告: " + warning);
        }
        // 核心 SPI 已完成预热并恢复 TCCL；此处只发现宿主自身的 GuiExtension。
        MemShellDesktopFrame.launch(plugins.getWarnings());
    }
}
