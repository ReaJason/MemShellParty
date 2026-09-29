package com.reajason.javaweb.desktop.memshell;

import com.formdev.flatlaf.FlatLightLaf;
import com.reajason.javaweb.desktop.memshell.ui.MemShellGeneratorFrame;

import javax.swing.JFrame;
import javax.swing.JMenuBar;
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
                JFrame frame = new MemShellGeneratorFrame();
                if (System.getProperty("os.name", "").toLowerCase().contains("mac")) {
                    // 挂一个空菜单栏，避免 macOS 上聚焦窗口时丢失系统快捷键（复制/粘贴等）
                    frame.setJMenuBar(new JMenuBar());
                }
                frame.setVisible(true);
            }
        });
    }
}
