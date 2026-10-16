package com.reajason.javaweb.examples.customshellgui;

import com.reajason.javaweb.desktop.memshell.MemShellGui;
import com.reajason.javaweb.desktop.memshell.extension.GuiExtension;
import com.reajason.javaweb.desktop.memshell.ui.MemShellGeneratorFrame;
import com.reajason.javaweb.desktop.memshell.ui.ProbeGeneratorFrame;
import com.reajason.javaweb.desktop.memshell.util.AppVersion;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.util.List;

/**
 * 下游客户端自己的窗口外壳：SDK 只给两个生成器 frame，页签怎么排、状态栏长什么样、品牌叫什么
 * 都是宿主自己的事（官方发行版的外壳见 {@code memshell-party-gui-app} 的 MemShellDesktopFrame）。
 *
 * <p>这里演示的就是「拿 frame 自定义外部布局」的三件套：
 * <ol>
 *   <li>{@code getRootPanel()} 取界面本体，放进自己的页签；</li>
 *   <li>{@code setStatusReporter(...)} 接自己的状态出口（这里是一条极简状态行）；</li>
 *   <li>{@code installGenerateShortcut(getRootPane())} 把 Ctrl/⌘ + Enter 与默认按钮挂到自己的窗口上，
 *       切页时让当前页再调一次即可转移。</li>
 * </ol>
 */
public class CustomShellFrame extends JFrame {

    private final MemShellGeneratorFrame memShellFrame;
    private final ProbeGeneratorFrame probeFrame;
    private final JLabel statusLabel = new JLabel("就绪");

    public CustomShellFrame(List<GuiExtension> extensions) {
        super("自定义工具生成器 - MemShellParty v" + AppVersion.get());
        // standalone = false：窗口属性归本外壳，两个生成器只出界面
        this.memShellFrame = new MemShellGeneratorFrame(extensions, false);
        this.probeFrame = new ProbeGeneratorFrame(false);

        statusLabel.setForeground(SwingUiUtil.mutedColor());
        StatusReporter statusReporter = new StatusReporter() {
            @Override
            public void report(String message, StatusReporter.Level level) {
                statusLabel.setText(message);
            }
        };
        memShellFrame.setStatusReporter(statusReporter);
        probeFrame.setStatusReporter(statusReporter);

        final JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("内存马", memShellFrame.getRootPanel());
        tabs.addTab("探测马", probeFrame.getRootPanel());
        tabs.addChangeListener(e -> installShortcutForActivePage(tabs));

        setLayout(new BorderLayout());
        add(tabs, BorderLayout.CENTER);
        add(statusLabel, BorderLayout.SOUTH);

        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        SwingUiUtil.sizeToScreen(this);
        setLocationRelativeTo(null);
        memShellFrame.installGenerateShortcut(getRootPane());
    }

    /**
     * 切页时把快捷键与默认按钮交给新页（两个 frame 用的是同一个按键，后挂的生效）。
     */
    private void installShortcutForActivePage(JTabbedPane tabs) {
        if (tabs.getSelectedIndex() == 1) {
            probeFrame.installGenerateShortcut(getRootPane());
        } else {
            memShellFrame.installGenerateShortcut(getRootPane());
        }
    }

    /**
     * 宿主程序入口：装自己的观感（这里直接用 MemShellParty 的 FlatLaf 亮色主题）并显示窗口。
     */
    public static void launch() {
        MemShellGui.setupLookAndFeel();
        final List<GuiExtension> extensions = MemShellGui.resolveExtensions();
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new CustomShellFrame(extensions).setVisible(true);
            }
        });
    }

    MemShellGeneratorFrame memShellFrame() {
        return memShellFrame;
    }

    JLabel statusLabel() {
        return statusLabel;
    }
}
