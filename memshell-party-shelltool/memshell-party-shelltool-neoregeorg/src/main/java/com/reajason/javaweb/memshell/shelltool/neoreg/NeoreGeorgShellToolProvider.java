package com.reajason.javaweb.memshell.shelltool.neoreg;

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
@ShellToolMeta(name = ShellTool.NeoreGeorg, order = 70)
public class NeoreGeorgShellToolProvider implements ShellToolProvider {

    @Override
    public ToolMapping getToolMapping() {
        return ToolMapping.builder()
                .addShellClass(SERVLET, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgServlet")
                .addShellClass(JAKARTA_SERVLET, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgServlet")
                .addShellClass(FILTER, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgFilter")
                .addShellClass(JAKARTA_FILTER, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgFilter")
                .addShellClass(LISTENER, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgListener")
                .addShellClass(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgListener")
                .addShellClass(VALVE, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgValve")
                .addShellClass(JAKARTA_VALVE, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgValve")
                .addShellClass(PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorg")
                .addShellClass(JAKARTA_PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorg")
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgInterceptor")
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgInterceptor")
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgControllerHandler")
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgControllerHandler")
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorg")
                .addShellClass(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorg")
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorg")
                .addShellClass(JETTY_AGENT_HANDLER, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgJettyHandler")
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgUndertowServletHandler")
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorg")
                .addShellClass(WAS_AGENT_FILTER_MANAGER, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorg")
                .addShellClass(ACTION, "com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgStruts2Action")
                .build();
    }

    @Override
    public Class<? extends ShellToolConfig> getConfigClass() {
        return NeoreGeorgConfig.class;
    }

    @Override
    public Class<? extends ShellGenerator> getGeneratorClass() {
        return NeoreGeorgGenerator.class;
    }
}
