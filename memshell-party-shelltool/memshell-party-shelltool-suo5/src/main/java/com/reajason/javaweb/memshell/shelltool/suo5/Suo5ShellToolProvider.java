package com.reajason.javaweb.memshell.shelltool.suo5;

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
@ShellToolMeta(name = ShellTool.Suo5, order = 40)
public class Suo5ShellToolProvider implements ShellToolProvider {

    @Override
    public ToolMapping getToolMapping() {
        return ToolMapping.builder()
                .addShellClass(SERVLET, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5Servlet")
                .addShellClass(JAKARTA_SERVLET, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5Servlet")
                .addShellClass(FILTER, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter")
                .addShellClass(JAKARTA_FILTER, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter")
                .addShellClass(LISTENER, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5Listener")
                .addShellClass(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5Listener")
                .addShellClass(VALVE, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5Valve")
                .addShellClass(JAKARTA_VALVE, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5Valve")
                .addShellClass(PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5")
                .addShellClass(JAKARTA_PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5")
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5Interceptor")
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5Interceptor")
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5ControllerHandler")
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5ControllerHandler")
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5")
                .addShellClass(SPRING_WEBFLUX_WEB_FILTER, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5WebFilter")
                .addShellClass(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5")
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5")
                .addShellClass(JETTY_AGENT_HANDLER, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5JettyHandler")
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5UndertowServletHandler")
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5")
                .addShellClass(WAS_AGENT_FILTER_MANAGER, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5")
                .addShellClass(ACTION, "com.reajason.javaweb.memshell.shelltool.suo5.Suo5Struts2Action")
                .build();
    }

    @Override
    public Class<? extends ShellToolConfig> getConfigClass() {
        return Suo5Config.class;
    }

    @Override
    public Class<? extends ShellGenerator> getGeneratorClass() {
        return Suo5Generator.class;
    }
}
