package com.reajason.javaweb.examples.customshelltool;

import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.ToolMapping;
import com.reajason.javaweb.memshell.spi.ShellToolMeta;
import com.reajason.javaweb.memshell.spi.ShellToolProvider;
import org.kohsuke.MetaInfServices;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * 自定义 shelltool 的 SPI 入口，示例的三块拼图之一：
 *
 * <ol>
 *   <li>{@link #getToolMapping()} —— 声明本工具支持哪些 shellType，以及各自的模板类（二进制名）；</li>
 *   <li>{@link #getConfigClass()} —— 工具配置类（承载生成期参数）；</li>
 *   <li>{@link #getGeneratorClass()} —— 生成器（把配置写进模板）。</li>
 * </ol>
 *
 * <p>本示例只适配 servlet-api 相关的 shellType：Filter、Servlet、Listener 及其 Jakarta 变体
 * （Jakarta 变体复用同一份 javax 模板，生成期由 JakartaPostProcessor 改名）。
 * 其余类型（Valve、WebSocket、Agent、Spring、Dubbo、Jetty Handler...）需要各自 server 的
 * 注入器配合，不在本示例范围内 —— 要给某个 server 增加支持时，映射里加上对应 shellType 即可，
 * {@code MemShellRegistry} 会自动按 server 的注入器映射做一次求交集，没有注入器的类型不会对外暴露。
 *
 * <p>{@code @MetaInfServices} 会生成
 * {@code META-INF/services/com.reajason.javaweb.memshell.spi.ShellToolProvider}，
 * {@code MemShellRegistry.getInstance().init()} 通过 ServiceLoader 发现它。打 fat jar 时必须合并
 * META-INF/services（Maven Shade: ServicesResourceTransformer，Shadow: mergeServiceFiles()），
 * 否则这个工具不会被注册。
 *
 * @author ReaJason
 */
@MetaInfServices(ShellToolProvider.class)
// order：内置工具 0-999，社区/自定义插件建议 1000+
@ShellToolMeta(name = GodzillaSessionShellToolProvider.NAME, order = 1000)
public class GodzillaSessionShellToolProvider implements ShellToolProvider {

    /**
     * 工具名：ShellConfig.shellTool 的值，也是 GUI / REST / MCP 里显示的名字。
     * 自定义工具不在 {@code ShellTool} 常量类里，自己维护一个常量即可。
     *
     * <p>注意别和内置工具重名：同名注册会被静默忽略（order 小的先注册生效）。
     * 本示例的会话版哥斯拉已经作为内置工具 GodzillaSession 落地（issue #159，
     * godzilla 模块的 session 包），所以这里改名 GodzillaSessionExample 只作 SPI 教学。
     */
    public static final String NAME = "GodzillaSessionExample";

    private static final String PACKAGE = "com.reajason.javaweb.examples.customshelltool.";

    @Override
    public ToolMapping getToolMapping() {
        return ToolMapping.builder()
                .addShellClass(FILTER, PACKAGE + "GodzillaSessionFilter")
                .addShellClass(JAKARTA_FILTER, PACKAGE + "GodzillaSessionFilter")
                .addShellClass(SERVLET, PACKAGE + "GodzillaSessionServlet")
                .addShellClass(JAKARTA_SERVLET, PACKAGE + "GodzillaSessionServlet")
                .addShellClass(LISTENER, PACKAGE + "GodzillaSessionListener")
                .addShellClass(JAKARTA_LISTENER, PACKAGE + "GodzillaSessionListener")
                .build();
    }

    @Override
    public Class<? extends ShellToolConfig> getConfigClass() {
        return GodzillaSessionConfig.class;
    }

    @Override
    public Class<? extends ShellGenerator> getGeneratorClass() {
        return GodzillaSessionGenerator.class;
    }
}
