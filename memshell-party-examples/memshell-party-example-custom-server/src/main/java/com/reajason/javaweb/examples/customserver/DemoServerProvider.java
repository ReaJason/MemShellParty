package com.reajason.javaweb.examples.customserver;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.spi.ServerMeta;
import com.reajason.javaweb.memshell.spi.ServerProvider;
import org.kohsuke.MetaInfServices;

/**
 * 自定义 server 的 SPI 入口：{@code @MetaInfServices} 生成
 * {@code META-INF/services/com.reajason.javaweb.memshell.spi.ServerProvider}，
 * {@code MemShellRegistry.getInstance().init()} 通过 ServiceLoader 发现它。
 *
 * <p>自定义 server 不在 {@code Server} 常量类里，自己维护一个常量即可；
 * 注册顺序按 {@code @ServerMeta.order} 排（内置 0-999，插件建议 1000+）。
 * 打 fat jar 时必须合并 META-INF/services（Maven Shade: ServicesResourceTransformer，
 * Shadow: mergeServiceFiles()），否则这个 server 不会被注册。
 *
 * @author ReaJason
 */
@MetaInfServices(ServerProvider.class)
@ServerMeta(name = DemoServerProvider.NAME, order = 1000)
public class DemoServerProvider implements ServerProvider {

    /**
     * 目标容器标识：{@code ShellConfig.server} 的值。
     */
    public static final String NAME = "DemoServletApp";

    @Override
    public AbstractServer createServer() {
        return new DemoServer();
    }
}
