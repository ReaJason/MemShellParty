package com.reajason.javaweb.desktop.memshell;

import com.formdev.flatlaf.FlatLightLaf;
import com.reajason.javaweb.desktop.memshell.ui.MemShellGeneratorFrame;

import javax.swing.SwingUtilities;

/**
 * MemShellParty Swing 桌面入口：安装 FlatLaf 并显示生成器窗口。
 */
public class MemShellDesktopApplication {

    public static void main(String[] args) {
        // macOS 下未打包 JVM 参数时，让 Dock/菜单栏显示应用名而非 "java"
        System.setProperty("apple.awt.application.name", "MemShellParty");
        FlatLightLaf.setup();

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // 窗口自带菜单栏（帮助 → 关于），macOS 下 FlatLaf 默认放入屏幕菜单栏
                new MemShellGeneratorFrame().setVisible(true);
            }
        });
    }
}
