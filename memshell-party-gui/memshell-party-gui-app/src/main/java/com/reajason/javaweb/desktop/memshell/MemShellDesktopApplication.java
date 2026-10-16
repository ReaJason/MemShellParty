package com.reajason.javaweb.desktop.memshell;

import com.reajason.javaweb.desktop.memshell.app.MemShellDesktopFrame;

/**
 * MemShellParty Swing 桌面入口（完整发行版）：安装 FlatLaf 并显示「内存马 / 探测马 / 反编译」三页窗口。
 *
 * <p>外壳与三个页面的分工见 {@link MemShellDesktopFrame}；宿主程序内嵌时不要调 {@code main}，
 * 用 {@link MemShellGui#createMemShellFrame} / {@link MemShellGui#createProbeFrame} /
 * {@link MemShellGui#createDecompileFrame} 拿界面，自己排外部布局（可参照 {@code MemShellDesktopFrame} 的写法）。
 */
public class MemShellDesktopApplication {

    public static void main(String[] args) {
        // 类路径上注册了 GuiExtension（META-INF/services）的扩展会被自动发现
        MemShellDesktopFrame.launch();
    }
}
