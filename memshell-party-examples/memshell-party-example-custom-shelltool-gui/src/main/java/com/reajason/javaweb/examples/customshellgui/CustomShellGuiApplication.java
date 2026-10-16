package com.reajason.javaweb.examples.customshellgui;

/**
 * 下游客户端入口：复用 MemShellParty 的两个生成器界面（内存马 / 探测马），
 * 外加自己的 shelltool 面板、结果动作与自己排的窗口外壳 —— 不用再从零写 Swing。
 *
 * <pre>{@code
 * ./gradlew :memshell-party-examples:memshell-party-example-custom-shelltool-gui:run
 * }</pre>
 */
public class CustomShellGuiApplication {

    public static void main(String[] args) {
        // GodzillaSessionGuiExtension 通过 META-INF/services 注册，窗口构造时会被自动发现；
        // 也可以显式传：new CustomShellFrame(MemShellGui.resolveExtensions(new GodzillaSessionGuiExtension()))
        CustomShellFrame.launch();
    }
}
