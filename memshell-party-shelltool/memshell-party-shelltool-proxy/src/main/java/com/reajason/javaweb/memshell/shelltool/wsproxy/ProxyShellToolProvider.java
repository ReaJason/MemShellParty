package com.reajason.javaweb.memshell.shelltool.wsproxy;

import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.ToolMapping;
import com.reajason.javaweb.memshell.spi.ShellToolMeta;
import com.reajason.javaweb.memshell.spi.ShellToolProvider;

import org.kohsuke.MetaInfServices;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 3.0.0
 */
@MetaInfServices(ShellToolProvider.class)
@ShellToolMeta(name = ShellTool.Proxy, order = 80)
public class ProxyShellToolProvider implements ShellToolProvider {

    @Override
    public ToolMapping getToolMapping() {
        return ToolMapping.builder()
                .addShellClass(WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.wsproxy.ProxyWebSocket")
                .addShellClass(JAKARTA_WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.wsproxy.ProxyWebSocket")
                .addShellClass(BYPASS_NGINX_WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.wsproxy.ProxyWebSocket")
                .addShellClass(JAKARTA_BYPASS_NGINX_WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.wsproxy.ProxyWebSocket")
                .build();
    }

    @Override
    public Class<? extends ShellToolConfig> getConfigClass() {
        return ProxyConfig.class;
    }

    @Override
    public Class<? extends ShellGenerator> getGeneratorClass() {
        return ProxyGenerator.class;
    }
}
