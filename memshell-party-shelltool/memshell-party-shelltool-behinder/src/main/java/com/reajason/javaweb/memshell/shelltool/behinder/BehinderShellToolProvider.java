package com.reajason.javaweb.memshell.shelltool.behinder;

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
@ShellToolMeta(name = ShellTool.Behinder, order = 20)
public class BehinderShellToolProvider implements ShellToolProvider {

    @Override
    public ToolMapping getToolMapping() {
        return ToolMapping.builder()
                .addShellClass(SERVLET, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet")
                .addShellClass(JAKARTA_SERVLET, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet")
                .addShellClass(FILTER, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter")
                .addShellClass(JAKARTA_FILTER, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter")
                .addShellClass(LISTENER, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderListener")
                .addShellClass(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderListener")
                .addShellClass(VALVE, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderValve")
                .addShellClass(JAKARTA_VALVE, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderValve")
                .addShellClass(PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.behinder.Behinder")
                .addShellClass(JAKARTA_PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.behinder.Behinder")
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderInterceptor")
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderInterceptor")
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderControllerHandler")
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderControllerHandler")
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, "com.reajason.javaweb.memshell.shelltool.behinder.Behinder")
                .addShellClass(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.shelltool.behinder.Behinder")
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.shelltool.behinder.Behinder")
                .addShellClass(JETTY_AGENT_HANDLER, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderJettyHandler")
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderUndertowServletHandler")
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, "com.reajason.javaweb.memshell.shelltool.behinder.Behinder")
                .addShellClass(WAS_AGENT_FILTER_MANAGER, "com.reajason.javaweb.memshell.shelltool.behinder.Behinder")
                .addShellClass(ACTION, "com.reajason.javaweb.memshell.shelltool.behinder.BehinderStruts2Action")
                .build();
    }

    @Override
    public Class<? extends ShellToolConfig> getConfigClass() {
        return BehinderConfig.class;
    }

    @Override
    public Class<? extends ShellGenerator> getGeneratorClass() {
        return BehinderGenerator.class;
    }
}
