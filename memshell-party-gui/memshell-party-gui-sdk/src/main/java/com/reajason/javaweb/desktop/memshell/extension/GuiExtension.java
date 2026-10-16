package com.reajason.javaweb.desktop.memshell.extension;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * 桌面端扩展点：自带 shelltool 的下游工具（自建发行版 / 集成进自己的客户端）实现它，
 * 就能复用 MemShellParty 的内存马生成器界面（{@link com.reajason.javaweb.desktop.memshell.ui.MemShellGeneratorFrame}）——
 * 生成器表单、打包、结果区全都现成，只需要补上"自己的工具长什么样"。
 *
 * <p>这里的方法都被内存马生成器界面消费；页面外壳（页签布局、状态栏、关于弹窗、窗口标题之外的品牌）
 * 归宿主自己实现 —— SDK 只提供界面本体，不替宿主决定窗口长什么样。
 *
 * <p>两种接入方式，可同时用：
 * <ul>
 *   <li><b>注册到类路径</b>：实现类用 {@code @MetaInfServices(GuiExtension.class)} 声明，
 *       {@link com.reajason.javaweb.desktop.memshell.MemShellGui#resolveExtensions(GuiExtension...)}
 *       会自动发现；</li>
 *   <li><b>显式传入</b>：{@code MemShellGui.createMemShellFrame(new MyExtension())}，
 *       宿主程序内嵌时用；同名扩展以显式传入的为准。</li>
 * </ul>
 *
 * <p>注意：一个扩展都不给，生成器也照常能用 —— SPI 插件工具会出现在工具下拉框里，参数面板按
 * config 类上的 {@code @ConfigField} 注解生成（见 {@code DynamicToolPanel}），结果区也有反射兜底。
 * 这里的扩展点是"做得更好"（专用面板、品牌、结果动作），不是"跑起来"的前提。
 */
public interface GuiExtension {

    /**
     * 扩展名：用于去重（同名时显式传入的覆盖 ServiceLoader 发现的）。
     */
    String name();

    /**
     * 应用标题，默认 {@code "MemShellParty v1.2.3"}；自建发行版可以换成自己的品牌。
     *
     * <p>内存马生成器窗口标题取它；宿主自建外壳时也可以用
     * {@link com.reajason.javaweb.desktop.memshell.MemShellGui#applicationTitle(List, String)}
     * 拿到同一套规则下的标题。
     */
    default String applicationTitle(String defaultTitle) {
        return defaultTitle;
    }

    /**
     * 工具专用参数面板：key 是 shellTool 名（插件工具就是
     * {@code @ShellToolMeta(name = ...)} 里的名字）。
     *
     * <p>给了面板就顶掉该工具的通用面板（内置工具也能覆盖）；没给的工具不变。
     * 面板里读写参数直接走 {@link ToolPanelContext#getController()}，插件工具的参数写进
     * {@code state.toolParams} 后会和生成参数自动合并（和动态面板同一条链路）。
     */
    default Map<String, ToolPanelFactory> toolPanels() {
        return Collections.emptyMap();
    }

    /**
     * 结果区动作按钮（如"加入我的 Shell 列表"）：未生成结果时按钮自动置灰，
     * 点击时把当前生成结果交给 {@link ResultAction#perform}。
     *
     * <p>按钮默认从左往右排，想要贴右边（收尾动作的常见位置）让
     * {@link ResultAction#alignRight()} 返回 {@code true}。
     */
    default List<ResultAction> resultActions() {
        return Collections.emptyList();
    }

    /**
     * 每次生成成功后的回调：自动同步到宿主程序自己的数据结构（历史记录、台账、上传等）时用。
     * 回调在 EDT 上执行，抛异常不影响生成结果展示，只会打到状态出口。
     */
    default void onResultGenerated(DesktopMemShellGenerateResult result) {
    }
}
