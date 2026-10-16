package com.reajason.javaweb.memshell.shelltool.suo5v2;

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
@ShellToolMeta(name = ShellTool.Suo5v2, order = 50)
public class Suo5v2ShellToolProvider implements ShellToolProvider {

    @Override
    public ToolMapping getToolMapping() {
        return ToolMapping.builder()
                .addShellClass(SERVLET, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2Servlet")
                .addShellClass(JAKARTA_SERVLET, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2Servlet")
                .addShellClass(FILTER, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2Filter")
                .addShellClass(JAKARTA_FILTER, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2Filter")
                .addShellClass(LISTENER, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2Listener")
                .addShellClass(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2Listener")
                .addShellClass(VALVE, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2Valve")
                .addShellClass(JAKARTA_VALVE, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2Valve")
                .addShellClass(PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2")
                .addShellClass(JAKARTA_PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2")
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2Interceptor")
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2Interceptor")
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2ControllerHandler")
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2ControllerHandler")
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2")
                .addShellClass(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2")
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2")
                .addShellClass(JETTY_AGENT_HANDLER, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2JettyHandler")
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2UndertowServletHandler")
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2")
                .addShellClass(WAS_AGENT_FILTER_MANAGER, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2")
                .addShellClass(ACTION, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2Struts2Action")
                .addShellClass(CUSTOMIZER, "com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2JettyCustomizer")
                .build();
    }

    @Override
    public Class<? extends ShellToolConfig> getConfigClass() {
        return Suo5v2Config.class;
    }

    @Override
    public Class<? extends ShellGenerator> getGeneratorClass() {
        return Suo5V2Generator.class;
    }
}
