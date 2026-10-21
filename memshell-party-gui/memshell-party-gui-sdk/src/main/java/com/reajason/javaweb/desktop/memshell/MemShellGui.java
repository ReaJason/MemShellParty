package com.reajason.javaweb.desktop.memshell;

import com.formdev.flatlaf.FlatLightLaf;
import com.reajason.javaweb.desktop.memshell.extension.GuiExtension;
import com.reajason.javaweb.desktop.memshell.ui.BytecodeToolsFrame;
import com.reajason.javaweb.desktop.memshell.ui.DecompileFrame;
import com.reajason.javaweb.desktop.memshell.ui.MemShellGeneratorFrame;
import com.reajason.javaweb.desktop.memshell.ui.ProbeGeneratorFrame;
import com.reajason.javaweb.desktop.memshell.ui.panel.MemShellConfigPanel;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.ServiceLoader;
import java.util.Set;

/**
 * 下游复用入口：拿到 MemShellParty 的桌面界面（内存马 / 探测马生成器、CFR 反编译工具、
 * 字节码工具），把它们嵌进自己的布局、挂上自己的扩展（专用面板、结果动作、应用品牌）。
 *
 * <pre>{@code
 * // 独立窗口：只要其中一个窗口
 * MemShellGui.createMemShellFrame(new MyGuiExtension()).setVisible(true);
 * MemShellGui.createDecompileFrame().setVisible(true);
 * MemShellGui.createBytecodeToolsFrame().setVisible(true);
 *
 * // 嵌进自己的页签布局：外壳（页签/状态栏/关于）都是宿主自己的
 * MemShellGui.setupLookAndFeel();
 * MemShellGeneratorFrame memShell = MemShellGui.createMemShellFrame(new MyGuiExtension());
 * ProbeGeneratorFrame probe = MemShellGui.createProbeFrame();
 * DecompileFrame decompile = new DecompileFrame(false);
 * BytecodeToolsFrame bytecode = new BytecodeToolsFrame(false);
 * myTabs.addTab("内存马", memShell.getRootPanel());
 * myTabs.addTab("探测马", probe.getRootPanel());
 * myTabs.addTab("反编译", decompile.getRootPanel());
 * myTabs.addTab("字节码工具", bytecode.getRootPanel());
 * memShell.setStatusReporter(myStatusBar::setStatus);
 * memShell.installGenerateShortcut(getRootPane());
 * }</pre>
 *
 * <p>类路径上的 {@link GuiExtension}（{@code META-INF/services}）会被自动发现，无需显式传入；
 * 同名扩展以显式传入的为准。
 */
public final class MemShellGui {

    private MemShellGui() {
    }

    /**
     * 显式传入的扩展 + 类路径上 ServiceLoader 发现的扩展，按名字去重（显式传入优先）。
     */
    public static List<GuiExtension> resolveExtensions(GuiExtension... extensions) {
        Set<String> names = new LinkedHashSet<String>();
        List<GuiExtension> resolved = new ArrayList<GuiExtension>();
        if (extensions != null) {
            for (GuiExtension extension : extensions) {
                if (extension != null && names.add(extension.name())) {
                    resolved.add(extension);
                }
            }
        }
        for (GuiExtension extension : ServiceLoader.load(GuiExtension.class, discoveryClassLoader())) {
            if (names.add(extension.name())) {
                resolved.add(extension);
            }
        }
        return resolved;
    }

    /**
     * 内存马生成器窗口（不安装 LAF、不显示）：窗口生命周期归宿主时用；
     * 嵌进宿主布局时改用 {@code new MemShellGeneratorFrame(extensions, false)} 取 {@code getRootPanel()}。
     */
    public static MemShellGeneratorFrame createMemShellFrame(GuiExtension... extensions) {
        return new MemShellGeneratorFrame(resolveExtensions(extensions));
    }

    /**
     * 探测马生成器窗口（不安装 LAF、不显示）；内嵌用法同 {@link #createMemShellFrame}。
     * 探测马界面没有扩展点，所以不吃 {@link GuiExtension}。
     */
    public static ProbeGeneratorFrame createProbeFrame() {
        return new ProbeGeneratorFrame();
    }

    /**
     * CFR 反编译工具窗口（不安装 LAF、不显示）：Base64 / GzipBase64 文本或 .class 文件进，Java 源码出。
     * 内嵌用法同 {@link #createMemShellFrame}（{@code standalone = false} 构造后取 {@code getRootPanel()}）。
     * 反编译界面没有扩展点，也不参与生成流程。
     */
    public static DecompileFrame createDecompileFrame() {
        return new DecompileFrame();
    }

    /**
     * 字节码工具窗口（不安装 LAF、不显示）：改父类/包名、添加 main、随机类名与瘦身、
     * 模块绕过、静态初始化触发；输入输出都支持 Base64 / GzipBase64 / .class 互转。
     * 内嵌用法同 {@link #createMemShellFrame}（{@code standalone = false} 构造后取 {@code getRootPanel()}）。
     * 字节码工具没有扩展点，也不参与生成流程。
     */
    public static BytecodeToolsFrame createBytecodeToolsFrame() {
        return new BytecodeToolsFrame();
    }

    /**
     * 可独立内嵌的内存马配置表单（核心配置 + 按工具切换的参数面板，不含打包条与结果区）：
     * 只需要「配置出一个内存马」、生成与结果展示自己来的宿主（如综合利用工具的注入面板）用它；
     * 控制器/校验/工具卡联动都在面板内部，宿主拿 {@code getController()} 读快照、
     * 配 {@code GenerationService#generateShell} 直接出 {@code MemShellResult}。
     */
    public static MemShellConfigPanel createMemShellConfigPanel(GuiExtension... extensions) {
        return new MemShellConfigPanel(resolveExtensions(extensions));
    }

    /**
     * 应用标题：默认 {@code "MemShellParty v1.2.3"}，逐个交给扩展改写；宿主自建外壳时也用它，
     * 保证标题与两个生成器窗口的默认标题同一套规则。
     */
    public static String applicationTitle(List<GuiExtension> extensions, String defaultTitle) {
        String title = defaultTitle;
        if (extensions != null) {
            for (GuiExtension extension : extensions) {
                title = extension.applicationTitle(title);
            }
        }
        return title;
    }

    /**
     * 安装 MemShellParty 的界面观感（FlatLaf 亮色）。宿主有自己的主题时不要调 ——
     * 两个生成器 frame 只声明界面结构，不碰 LAF。
     */
    public static void setupLookAndFeel() {
        FlatLightLaf.setup();
    }

    /**
     * 扩展发现用的类加载器：优先线程上下文（宿主程序常用自己的 UI 类加载器），退回本类的。
     */
    private static ClassLoader discoveryClassLoader() {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        return contextClassLoader != null ? contextClassLoader : MemShellGui.class.getClassLoader();
    }
}
